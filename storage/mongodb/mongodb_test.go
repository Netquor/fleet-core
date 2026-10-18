package mongodb

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/micromdm/nanomdm/fleetcore/seal"
	"github.com/micromdm/nanomdm/fleetcore/tenantlint"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/nanomdm/test/e2e"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var _ storage.AllStorage = (*MongoDBStorage)(nil)

// The shared end-to-end suite against a real MongoDB replica set:
//
//	NANOMDM_MONGODB_STORAGE_TEST_URI='mongodb://127.0.0.1:27117/nanomdm_test?replicaSet=rs0' go test ./storage/mongodb
//
// Each run uses a fresh database (the one in the URI, dropped first), so point it at a scratch one.
func TestMongoDB(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()

	fresh := func(opts ...Option) *MongoDBStorage {
		s, err := New(ctx, append([]Option{WithURI(uri), WithoutIndexes()}, opts...)...) // indexes after the drop: the database may hold another test's data
		if err != nil {
			t.Fatal(err)
		}
		if err := s.db.Drop(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.EnsureIndexes(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close(ctx) })
		return s
	}

	t.Run("e2e-WithDeleteCommands()", func(t *testing.T) { e2e.TestE2E(t, ctx, fresh(WithDeleteCommands())) })
	t.Run("e2e", func(t *testing.T) { e2e.TestE2E(t, ctx, fresh()) })
}

// A plist is kept as native BSON beside its raw XML, so the contents can be queried in the database.
func TestMongoDBNativeDocuments(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	s, err := New(ctx, WithURI(uri), WithoutIndexes())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	if err := s.db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	e2e.TestE2E(t, ctx, s)
	for coll, field := range map[string]string{"devices": "authenticate_doc", "commands": "command_doc"} {
		total, _ := s.db.Collection(coll).CountDocuments(ctx, bson.D{})
		with, _ := s.db.Collection(coll).CountDocuments(ctx, bson.D{{Key: field, Value: bson.D{{Key: "$type", Value: "object"}}}})
		if total == 0 || with != total {
			t.Errorf("%s: %d of %d have %s", coll, with, total, field)
		}
	}
	// Query inside a stored result: the status of a command's result, straight from the database.
	n, err := s.db.Collection("enrollment_queue").CountDocuments(ctx, bson.D{{Key: "result_doc.Status", Value: bson.D{{Key: "$exists", Value: true}}}})
	if err != nil || n == 0 {
		t.Errorf("querying result_doc.Status: %d %v", n, err)
	}
}

// Tenants that share collections: the shared end-to-end suite passes for each tenant on its own (with the same device ids in both: nothing may collide or leak),
// and a store bound to one tenant cannot see or change another's data through any method.
func TestMongoDBSharedTenants(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	monitors := map[string]*tenantlint.Monitor{}
	open := func(tenant string) *MongoDBStorage {
		mon := tenantlint.NewMonitor(tenant)
		monitors[tenant] = mon
		client, err := mongo.Connect(options.Client().ApplyURI(uri).SetMonitor(mon.CommandMonitor()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Disconnect(ctx) })
		s, err := New(ctx, WithClient(client), WithTenant(tenant), WithoutIndexes())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close(ctx) })
		return s
	}
	a := open("acme")
	if err := a.db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	b := open("globex")
	t.Run("e2e acme", func(t *testing.T) { e2e.TestE2E(t, ctx, a) })
	t.Run("e2e globex, same device ids", func(t *testing.T) { e2e.TestE2E(t, ctx, b) })
	// While the whole conformance suite ran, no command on a shared collection was without its tenant.
	for tenant, mon := range monitors {
		if v := mon.Violations(); len(v) > 0 {
			t.Errorf("%s: commands that were not scoped to the tenant:\n%s", tenant, strings.Join(v, "\n"))
		}
		if mon.Checked() < 100 {
			t.Errorf("%s: the tenant check saw only %d commands", tenant, mon.Checked())
		}
	}
	for _, mon := range monitors {
		mon.Stop() // the isolation checks below look into the database directly
	}

	// Isolation, method by method.
	if err := a.db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	const dev = "ISOLATION-DEVICE-1"
	rq := func(id string) *mdm.Request {
		r := mdm.NewRequestWithContext(ctx, nil)
		r.EnrollID = &mdm.EnrollID{Type: mdm.Device, ID: id}
		return r
	}
	cmd := func(uuid string) *mdm.Command {
		c := &mdm.Command{CommandUUID: uuid, Raw: []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CommandUUID</key><string>` + uuid + `</string><key>Command</key><dict><key>RequestType</key><string>DeviceInformation</string></dict></dict></plist>`)}
		c.Command.RequestType = "DeviceInformation"
		return c
	}
	au := &mdm.Authenticate{Topic: "com.apple.mgmt.External.x", SerialNumber: "C02ISO", Raw: []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>UDID</key><string>` + dev + `</string></dict></plist>`)}
	au.UDID, au.MessageType.MessageType = dev, "Authenticate"
	tu := &mdm.TokenUpdate{Raw: []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>UDID</key><string>` + dev + `</string></dict></plist>`)}
	tu.UDID, tu.MessageType.MessageType, tu.Topic, tu.PushMagic = dev, "TokenUpdate", "com.apple.mgmt.External.x", "magic"
	if err := tu.SetTokenString("0a0b0c"); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(a.StoreAuthenticate(rq(dev), au))
	must(a.StoreTokenUpdate(rq(dev), tu))
	_, err := a.EnqueueCommand(ctx, []string{dev}, cmd("SAME-UUID"))
	must(err)
	must(a.AssociateCertHash(rq(dev), "ABCDEF"))

	if m, err := b.RetrievePushInfo(ctx, []string{dev}); err != nil || len(m) != 0 {
		t.Errorf("globex sees acme's push info: %v %v", m, err)
	}
	if c, err := b.RetrieveNextCommand(rq(dev), false); err != nil || c != nil {
		t.Errorf("globex sees acme's command: %v %v", c, err)
	}
	if has, _ := b.HasCertHash(rq(dev), "abcdef"); has {
		t.Error("globex sees acme's certificate hash")
	}
	if has, _ := b.EnrollmentHasCertHash(rq(dev), ""); has {
		t.Error("globex sees acme's certificate association")
	}
	if id, _ := b.EnrollmentFromHash(ctx, "abcdef"); id != "" {
		t.Errorf("globex resolves acme's hash to %q", id)
	}
	if n, _ := b.RetrieveTokenUpdateTally(ctx, dev); n != 0 {
		t.Errorf("globex sees acme's tally: %d", n)
	}
	// Changes by globex leave acme alone, even for the same device id and command uuid.
	must(b.ClearQueue(rq(dev)))
	must(b.Disable(rq(dev)))
	if m, _ := a.RetrievePushInfo(ctx, []string{dev}); len(m) != 1 {
		t.Error("globex disabled or removed acme's enrollment")
	}
	if n, _ := a.RetrieveTokenUpdateTally(ctx, dev); n != 1 {
		t.Errorf("globex changed acme's tally: %d", n)
	}
	if c, _ := a.RetrieveNextCommand(rq(dev), false); c == nil || c.CommandUUID != "SAME-UUID" {
		t.Error("globex's ClearQueue cleared acme's queue")
	}
	_, err = b.EnqueueCommand(ctx, []string{dev}, cmd("SAME-UUID")) // the same uuid in another tenant is not a clash
	must(err)
	// A tenant leaving takes only its own data.
	if n, err := b.DeleteTenant(ctx); err != nil || n == 0 {
		t.Fatalf("delete globex: %d %v", n, err)
	}
	if m, _ := a.RetrievePushInfo(ctx, []string{dev}); len(m) != 1 {
		t.Error("deleting globex removed acme's enrollment")
	}
	if c, _ := a.RetrieveNextCommand(rq(dev), false); c == nil {
		t.Error("deleting globex removed acme's command")
	}
	if c, _ := b.RetrieveNextCommand(rq(dev), false); c != nil {
		t.Error("globex's command survived its deletion")
	}
	if _, err := (&MongoDBStorage{}).DeleteTenant(ctx); err == nil {
		t.Error("DeleteTenant without a tenant must refuse")
	}
	// Nothing was written without a tenant.
	for _, coll := range []string{cDevices, cEnrollments, cCommands, cQueue, cCertAuth} {
		n, err := a.db.Collection(coll).CountDocuments(ctx, bson.D{{Key: "t", Value: bson.D{{Key: "$exists", Value: false}}}})
		if err != nil || n != 0 {
			t.Errorf("%s: %d documents without a tenant (%v)", coll, n, err)
		}
	}
}

// Sealed mode: the whole conformance suite passes with the secrets encrypted, and nothing that holds a secret is readable in the database.
func TestMongoDBSealed(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	ring, err := seal.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, WithURI(uri), WithoutIndexes(), WithSealer(ring.For("")))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	if err := s.db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	e2e.TestE2E(t, ctx, s)

	assertSealed(t, ctx, s)
}

// assertSealed fails if a secret-bearing field in the database is readable.
func assertSealed(t *testing.T, ctx context.Context, s *MongoDBStorage) {
	t.Helper()
	check := func(coll, field string) {
		cur, err := s.db.Collection(coll).Find(ctx, bson.D{{Key: field, Value: bson.D{{Key: "$exists", Value: true}, {Key: "$ne", Value: nil}}}})
		if err != nil {
			t.Fatal(err)
		}
		var docs []bson.M
		if err := cur.All(ctx, &docs); err != nil {
			t.Fatal(err)
		}
		if len(docs) == 0 {
			t.Errorf("%s.%s: nothing was stored to check", coll, field)
		}
		for _, d := range docs {
			v, _ := d[field].(string)
			if !strings.HasPrefix(v, "s1.") {
				t.Errorf("%s.%s is not sealed: %.60q", coll, field, v)
			}
			if strings.Contains(v, "plist") || strings.Contains(v, "RequestType") {
				t.Errorf("%s.%s shows plist text", coll, field)
			}
		}
	}
	check("commands", "command")
	check("enrollment_queue", "result")
	check("devices", "token_update")
	if n, _ := s.db.Collection("commands").CountDocuments(ctx, bson.D{{Key: "command_doc", Value: bson.D{{Key: "$type", Value: "object"}}}}); n != 0 {
		t.Errorf("%d commands keep a readable copy", n)
	}
	if n, _ := s.db.Collection("enrollment_queue").CountDocuments(ctx, bson.D{{Key: "result_doc", Value: bson.D{{Key: "$type", Value: "object"}}}}); n != 0 {
		t.Errorf("%d results keep a readable copy", n)
	}
}

// Data written before sealing was on is still read, and the rekey pass seals it (and a rotated key takes over).
func TestMongoDBRewrap(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	plain, err := New(ctx, WithURI(uri), WithoutIndexes())
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close(ctx)
	if err := plain.db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := plain.EnsureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	e2e.TestE2E(t, ctx, plain) // stored in the clear

	k1, _ := seal.NewKeyring(bytes.Repeat([]byte{1}, 32))
	sealed, err := New(ctx, WithURI(uri), WithoutIndexes(), WithSealer(k1.For("")))
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close(ctx)
	if n, err := sealed.Rewrap(ctx); err != nil || n == 0 {
		t.Fatalf("rewrap: %d %v", n, err)
	}
	assertSealed(t, ctx, sealed)
	if n, _ := sealed.Rewrap(ctx); n != 0 {
		t.Errorf("a second pass changed %d documents", n)
	}

	// rotate: the new key first, the old to read
	k2, _ := seal.NewKeyring(bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{1}, 32))
	rotated, err := New(ctx, WithURI(uri), WithoutIndexes(), WithSealer(k2.For("")))
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close(ctx)
	if n, err := rotated.Rewrap(ctx); err != nil || n == 0 {
		t.Fatalf("rotation: %d %v", n, err)
	}
	// now only the new key is needed
	k2only, _ := seal.NewKeyring(bytes.Repeat([]byte{2}, 32))
	final, err := New(ctx, WithURI(uri), WithoutIndexes(), WithSealer(k2only.For("")))
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close(ctx)
	if n, err := final.Rewrap(ctx); err != nil || n != 0 {
		t.Errorf("after rotation the old key should not be needed and nothing left to change: %d %v", n, err)
	}
	assertSealed(t, ctx, final)
}
