package dep

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanodep/client"
	"github.com/micromdm/nanodep/storage/test"
	"github.com/micromdm/nanomdm/fleetcore/seal"
	"go.mongodb.org/mongo-driver/v2/bson"
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

// Secrets written under the old passphrase scheme still open when the tenant key is configured, and the rekey pass moves them to the key.
func TestSealingMigration(t *testing.T) {
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
	db := mc.Database("fleetcore_dep_seal_test")
	db.Drop(ctx)
	defer db.Drop(ctx)

	s, err := New(ctx, db, "acme", "old passphrase")
	if err != nil {
		t.Fatal(err)
	}
	tok := &client.OAuth1Tokens{ConsumerKey: "ck", ConsumerSecret: "cs-secret", AccessToken: "at", AccessSecret: "as-secret", AccessTokenExpiry: time.Now().Add(time.Hour)}
	if err := s.StoreAuthTokens(ctx, "org", tok); err != nil {
		t.Fatal(err)
	}
	if err := s.StoreTokenPKI(ctx, "org", []byte("CERT"), []byte("PRIVATE-KEY")); err != nil {
		t.Fatal(err)
	}
	if err := s.UpstageTokenPKI(ctx, "org"); err != nil {
		t.Fatal(err)
	}
	raw := func() string {
		var d bson.M
		_ = db.Collection(collection).FindOne(ctx, bson.D{}).Decode(&d)
		b, _ := json.Marshal(d)
		return string(b)
	}
	if !strings.Contains(raw(), "aesgcm:") || strings.Contains(raw(), "s1.") {
		t.Fatalf("setup: %s", raw())
	}

	ring, _ := seal.NewKeyring(bytes.Repeat([]byte{4}, 32))
	s.Sealer = ring.For("acme")
	got, err := s.RetrieveAuthTokens(ctx, "org")
	if err != nil || got.ConsumerSecret != "cs-secret" || got.AccessSecret != "as-secret" {
		t.Fatalf("old values after configuring the key: %v %+v", err, got)
	}
	if n, err := s.Rewrap(ctx); err != nil || n != 1 {
		t.Fatalf("rewrap: %d %v", n, err)
	}
	r := raw()
	if strings.Contains(r, "aesgcm:") || !strings.Contains(r, "s1.") || strings.Contains(r, "cs-secret") {
		t.Errorf("after rewrap: %s", r)
	}
	got, err = s.RetrieveAuthTokens(ctx, "org")
	if err != nil || got.ConsumerSecret != "cs-secret" {
		t.Errorf("after rewrap: %v %+v", err, got)
	}
	if _, key, err := s.RetrieveCurrentTokenPKI(ctx, "org"); err != nil || string(key) != "PRIVATE-KEY" {
		t.Errorf("pki key: %q %v", key, err)
	}
	if n, _ := s.Rewrap(ctx); n != 0 {
		t.Errorf("a second pass changed %d", n)
	}
	// another tenant's key does not open it
	s.Sealer = ring.For("other")
	if _, err := s.RetrieveAuthTokens(ctx, "org"); err == nil {
		t.Error("tokens opened under another tenant's key")
	}
}
