package mongodb

import (
	"context"
	"os"
	"testing"

	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/nanomdm/test/e2e"
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
		s, err := New(ctx, append([]Option{WithURI(uri)}, opts...)...)
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
