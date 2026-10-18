package dep

import (
	"context"
	"os"
	"testing"

	"github.com/micromdm/nanodep/storage/test"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// NANOMDM_MONGODB_STORAGE_TEST_URI='mongodb://127.0.0.1:27117/?replicaSet=rs0' go test ./fleetcore/dep
func TestStore(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	mc, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Disconnect(ctx)
	for name, tenant := range map[string]string{"own database": "", "shared, tenant a": "a"} {
		t.Run(name, func(t *testing.T) {
			db := mc.Database("fleetcore_dep_test")
			db.Drop(ctx)
			for _, pass := range []string{"", "secret"} {
				s, err := New(ctx, db, tenant, pass)
				if err != nil {
					t.Fatal(err)
				}
				test.TestWithStorages(t, ctx, s)
			}
		})
	}
	t.Run("tenants do not see each other", func(t *testing.T) {
		db := mc.Database("fleetcore_dep_test")
		db.Drop(ctx)
		a, _ := New(ctx, db, "a", "p")
		b, _ := New(ctx, db, "b", "p")
		if err := a.StoreCursor(ctx, "same-name", "cursor-a"); err != nil {
			t.Fatal(err)
		}
		if c, _ := b.RetrieveCursor(ctx, "same-name"); c != "" {
			t.Errorf("tenant b read tenant a's cursor: %q", c)
		}
	})
	mc.Database("fleetcore_dep_test").Drop(ctx)
}
