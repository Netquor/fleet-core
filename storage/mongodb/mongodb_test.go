package mongodb

import (
	"context"
	"os"
	"testing"

	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/nanomdm/test/e2e"
	"go.mongodb.org/mongo-driver/v2/bson"
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

// A plist is kept as native BSON beside its raw XML, so the contents can be queried in the database.
func TestMongoDBNativeDocuments(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	s, err := New(ctx, WithURI(uri))
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
	for coll, field := range map[string]string{"devices": "authenticate_doc", "command_results": "result_doc", "commands": "command_doc"} {
		total, _ := s.db.Collection(coll).CountDocuments(ctx, bson.D{})
		with, _ := s.db.Collection(coll).CountDocuments(ctx, bson.D{{Key: field, Value: bson.D{{Key: "$type", Value: "object"}}}})
		if total == 0 || with != total {
			t.Errorf("%s: %d of %d have %s", coll, with, total, field)
		}
	}
	// Query inside a stored result: the request type of a command, straight from the database.
	n, err := s.db.Collection("command_results").CountDocuments(ctx, bson.D{{Key: "result_doc.Status", Value: bson.D{{Key: "$exists", Value: true}}}})
	if err != nil || n == 0 {
		t.Errorf("querying result_doc.Status: %d %v", n, err)
	}
}
