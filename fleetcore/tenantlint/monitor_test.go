package tenantlint_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/micromdm/nanomdm/fleetcore/tenantlint"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// The runtime check sees what a source check cannot: it flags a command that would cross tenants and accepts one that cannot.
func TestMonitorFlagsUnscopedCommands(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	mon := tenantlint.NewMonitor("acme", "global_things")
	c, err := mongo.Connect(options.Client().ApplyURI(uri).SetMonitor(mon.CommandMonitor()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(ctx)
	coll := c.Database("fleetcore_monitor_test").Collection("things")
	defer coll.Database().Drop(ctx)

	good := func(name string, f func() error) {
		t.Helper()
		before := len(mon.Violations())
		if err := f(); err != nil && err != mongo.ErrNoDocuments {
			t.Fatalf("%s: %v", name, err)
		}
		if got := mon.Violations()[before:]; len(got) != 0 {
			t.Errorf("%s was flagged: %v", name, got)
		}
	}
	bad := func(name, want string, f func() error) {
		t.Helper()
		before := len(mon.Violations())
		_ = f()
		got := mon.Violations()[before:]
		if len(got) == 0 || !strings.Contains(strings.Join(got, "|"), want) {
			t.Errorf("%s was not flagged as %q: %v", name, want, got)
		}
	}
	// scoped
	good("insert with t", func() error {
		_, err := coll.InsertOne(ctx, bson.D{{Key: "t", Value: "acme"}, {Key: "a", Value: 1}})
		return err
	})
	good("insert with a tenant _id", func() error { _, err := coll.InsertOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fx"}}); return err })
	good("find by t", func() error { return coll.FindOne(ctx, bson.D{{Key: "t", Value: "acme"}, {Key: "a", Value: 1}}).Err() })
	good("find by tenant _id", func() error { return coll.FindOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fx"}}).Err() })
	good("find by tenant _ids", func() error {
		return coll.FindOne(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: bson.A{"acme\x1fx", "acme\x1fy"}}}}}).Err()
	})
	good("find within $and", func() error {
		return coll.FindOne(ctx, bson.D{{Key: "$and", Value: bson.A{bson.D{{Key: "t", Value: "acme"}}, bson.D{{Key: "a", Value: 1}}}}}).Err()
	})
	good("update scoped", func() error {
		_, err := coll.UpdateOne(ctx, bson.D{{Key: "t", Value: "acme"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "a", Value: 2}}}})
		return err
	})
	good("aggregate scoped", func() error {
		cur, err := coll.Aggregate(ctx, mongo.Pipeline{{{Key: "$match", Value: bson.D{{Key: "t", Value: "acme"}}}}, {{Key: "$group", Value: bson.D{{Key: "_id", Value: "$a"}}}}})
		if err == nil {
			cur.Close(ctx)
		}
		return err
	})
	good("a global collection", func() error {
		return c.Database("fleetcore_monitor_test").Collection("global_things").FindOne(ctx, bson.D{}).Err()
	})
	// crossing tenants
	bad("find without the tenant", "not scoped", func() error { return coll.FindOne(ctx, bson.D{{Key: "a", Value: 1}}).Err() })
	bad("find for another tenant", "not scoped", func() error { return coll.FindOne(ctx, bson.D{{Key: "t", Value: "globex"}}).Err() })
	bad("find by an _id of another tenant", "not scoped", func() error { return coll.FindOne(ctx, bson.D{{Key: "_id", Value: "globex\x1fx"}}).Err() })
	bad("find by a bare _id", "not scoped", func() error { return coll.FindOne(ctx, bson.D{{Key: "_id", Value: "x"}}).Err() })
	bad("find where only one _id of the list is ours", "not scoped", func() error {
		return coll.FindOne(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: bson.A{"acme\x1fx", "globex\x1fy"}}}}}).Err()
	})
	bad("a $or that lets another tenant in", "not scoped", func() error {
		return coll.FindOne(ctx, bson.D{{Key: "$or", Value: bson.A{bson.D{{Key: "t", Value: "acme"}}, bson.D{{Key: "a", Value: 1}}}}}).Err()
	})
	bad("an insert without the tenant", "does not carry the tenant", func() error { _, err := coll.InsertOne(ctx, bson.D{{Key: "a", Value: 1}}); return err })
	bad("an insert for another tenant", "another tenant", func() error {
		_, err := coll.InsertOne(ctx, bson.D{{Key: "t", Value: "globex"}})
		return err
	})
	bad("an update without the tenant", "update's filter", func() error {
		_, err := coll.UpdateMany(ctx, bson.D{{Key: "a", Value: 1}}, bson.D{{Key: "$set", Value: bson.D{{Key: "a", Value: 3}}}})
		return err
	})
	bad("a delete without the tenant", "delete's filter", func() error { _, err := coll.DeleteMany(ctx, bson.D{}); return err })
	bad("an aggregate that does not start with the tenant", "begin with a $match", func() error {
		cur, err := coll.Aggregate(ctx, mongo.Pipeline{{{Key: "$group", Value: bson.D{{Key: "_id", Value: "$a"}}}}})
		if err == nil {
			cur.Close(ctx)
		}
		return err
	})
	bad("a count over every tenant", "begin with a $match", func() error { _, err := coll.CountDocuments(ctx, bson.D{}); return err })
	if mon.Checked() < 15 {
		t.Errorf("only %d commands were checked", mon.Checked())
	}
}
