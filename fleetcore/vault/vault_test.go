package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/micromdm/nanomdm/fleetcore/seal"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestVault(t *testing.T) {
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
	db := mc.Database("fleetcore_vault_test")
	db.Drop(ctx)
	defer db.Drop(ctx)
	ring, _ := seal.NewKeyring(bytes.Repeat([]byte{3}, 32))
	a, err := NewStore(ctx, db, "acme")
	if err != nil {
		t.Fatal(err)
	}
	a.Sealer = ring.For("acme")
	b, _ := NewStore(ctx, db, "globex")
	b.Sealer = ring.For("globex")

	if v, err := a.Put(ctx, "mac1", FileVaultRecoveryKey, "AAAA-BBBB-CCCC-DDDD", "operator"); err != nil || v != 1 {
		t.Fatalf("%d %v", v, err)
	}
	if v, _ := a.Put(ctx, "mac1", FileVaultRecoveryKey, "EEEE-FFFF-GGGG-HHHH", "rotation"); v != 2 {
		t.Errorf("second version %d", v)
	}
	// the database holds no secret in the clear
	cur, _ := db.Collection("vault_secrets").Find(ctx, bson.D{})
	var docs []bson.M
	cur.All(ctx, &docs)
	raw, _ := json.Marshal(docs)
	if len(docs) != 2 || strings.Contains(string(raw), "AAAA") || strings.Contains(string(raw), "EEEE") {
		t.Errorf("secrets are readable in the database: %s", raw)
	}
	// listing shows no values
	metas, _ := a.List(ctx, "mac1")
	if len(metas) != 2 || metas[0].Version != 2 || !metas[0].Current || metas[1].Current {
		t.Errorf("list: %+v", metas)
	}
	// the server can use the current secret; a person cannot see it without a reason
	if v, ok, _ := a.Peek(ctx, "mac1", FileVaultRecoveryKey); !ok || v != "EEEE-FFFF-GGGG-HHHH" {
		t.Errorf("peek: %q", v)
	}
	if _, _, err := a.Reveal(ctx, "mac1", FileVaultRecoveryKey, 0, "alice", "  "); err != ErrNoReason {
		t.Errorf("reveal without a reason: %v", err)
	}
	if audit, _ := a.Audit(ctx, "mac1", 10); len(audit) != 2 {
		t.Errorf("a refused reveal must not be audited as a reveal: %+v", audit)
	}
	val, meta, err := a.Reveal(ctx, "mac1", FileVaultRecoveryKey, 0, "alice", "locked out, ticket 4711")
	if err != nil || val != "EEEE-FFFF-GGGG-HHHH" || meta.Version != 2 {
		t.Fatalf("reveal: %q %v", val, err)
	}
	// the previous version is the one a Mac that did not take the rotation still needs
	if old, _, _ := a.Reveal(ctx, "mac1", FileVaultRecoveryKey, 1, "alice", "older key"); old != "AAAA-BBBB-CCCC-DDDD" {
		t.Errorf("version 1: %q", old)
	}
	audit, _ := a.Audit(ctx, "mac1", 10)
	if len(audit) != 4 || audit[0].Action != "revealed" || audit[0].Who != "alice" || audit[0].Reason != "older key" {
		t.Errorf("audit: %+v", audit)
	}
	// another tenant sees none of it
	if _, _, err := b.Reveal(ctx, "mac1", FileVaultRecoveryKey, 0, "bob", "curious"); err == nil {
		t.Error("another tenant revealed a secret")
	}
	if m, _ := b.List(ctx, "mac1"); len(m) != 0 {
		t.Errorf("another tenant lists %+v", m)
	}
	// and an altered or moved value does not open
	if _, _, err := (&Store{db: db, tid: "acme", Sealer: ring.For("globex")}).Reveal(ctx, "mac1", FileVaultRecoveryKey, 0, "x", "y"); err == nil {
		t.Error("a secret opened under another tenant's key")
	}
}

func TestPassword(t *testing.T) {
	a, _ := Password(16)
	b, _ := Password(16)
	if len(a) != 16 || a == b || strings.ContainsAny(a, "0O1lI") {
		t.Errorf("%q %q", a, b)
	}
}
