package blueprints

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/seal"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func ringOf(t *testing.T, keys ...byte) *seal.Keyring {
	var ks [][]byte
	for _, k := range keys {
		ks = append(ks, bytes.Repeat([]byte{k}, 32))
	}
	r, err := seal.NewKeyring(ks...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rawJSON2(t *testing.T, ctx context.Context, db *mongo.Database, coll string) string {
	cur, err := db.Collection(coll).Find(ctx, bson.D{})
	if err != nil {
		t.Fatal(err)
	}
	var docs []bson.M
	if err := cur.All(ctx, &docs); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(docs)
	return string(b)
}

func TestSealingAndRekey(t *testing.T) {
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
	db := mc.Database("fleetcore_seal_test")
	db.Drop(ctx)
	defer db.Drop(ctx)

	// 1. Written before a key was configured: readable in the database.
	st, err := NewStore(ctx, db, "acme")
	if err != nil {
		t.Fatal(err)
	}
	dd, err := ddm.NewStore(ctx, db, "acme")
	if err != nil {
		t.Fatal(err)
	}
	b := Blueprint{ID: "wifi", Name: "wifi", Enabled: true, Items: []Item{{ID: "p", Kind: "profile", Payload: wifiProfile("supersecretssid")}, {ID: "c", Kind: "declaration", DeclarationType: "com.apple.configuration.passcode.settings", Declaration: map[string]any{"MinimumLength": 11}}}}
	if err := b.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveBlueprint(ctx, b, "t", Env{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dd.Replace(ctx, "dev", []ddm.Declaration{{Identifier: "x", Kind: ddm.KindConfiguration, Type: "t", Payload: map[string]any{"Password": "hunter2"}}}); err != nil {
		t.Fatal(err)
	}
	if err := dd.PutBlob(ctx, "dev", "k", "text/plain", []byte("blobsecret")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rawJSON2(t, ctx, db, "bp_blueprints"), "items") || !strings.Contains(rawJSON2(t, ctx, db, "ddm_declarations"), "hunter2") {
		t.Fatal("test setup: expected unsealed data")
	}

	// 2. A key is configured: old data still reads, new data is sealed, and rekey seals the old.
	r1 := ringOf(t, 1)
	st.Sealer, dd.Sealer = r1.For("acme"), r1.For("acme")
	if got, err := st.GetBlueprint(ctx, "wifi"); err != nil || len(got.Items) != 2 {
		t.Fatalf("unsealed blueprint after turning sealing on: %v", err)
	}
	if blob, _ := dd.GetBlob(ctx, "dev", "k"); blob == nil || string(blob.Body) != "blobsecret" {
		t.Fatal("unsealed blob unreadable after turning sealing on")
	}
	n, err := st.RewrapBlueprints(ctx)
	if err != nil || n == 0 {
		t.Fatalf("rewrap blueprints: %d %v", n, err)
	}
	n2, err := dd.Rewrap(ctx)
	if err != nil || n2 == 0 {
		t.Fatalf("rewrap declarations: %d %v", n2, err)
	}
	for coll, secret := range map[string]string{"bp_blueprints": "supersecretssid", "bp_revisions": "supersecretssid", "ddm_declarations": "hunter2", "ddm_profiles": "blobsecret"} {
		raw := rawJSON2(t, ctx, db, coll)
		if strings.Contains(raw, secret) || strings.Contains(raw, "c3VwZXJzZWNyZXRzc2lk") {
			t.Errorf("%s still shows its secret", coll)
		}
	}
	if got, _ := st.GetBlueprint(ctx, "wifi"); len(got.Items) != 2 || !bytes.Contains(got.Items[0].Payload, []byte("supersecretssid")) {
		t.Error("the blueprint does not read back after rekey")
	}
	revs, err := st.Revisions(ctx, "wifi", 10)
	if err != nil || len(revs) != 1 || len(revs[0].Items) != 2 {
		t.Errorf("revisions after rekey: %v %d", err, len(revs))
	}
	if again, _ := st.RewrapBlueprints(ctx); again == 0 {
		// Blueprints are re-written each time (their sealed items get a fresh nonce); that is expected, nothing is lost.
		t.Log("second rewrap changed nothing")
	}
	if ds, _ := dd.List(ctx, "dev"); len(ds) != 1 || ds[0].Payload["Password"] != "hunter2" {
		t.Errorf("declarations after rekey: %+v", ds)
	}

	// 3. Rotation: a new key first, the old one kept to read; rekey moves everything; then the old key can go.
	r2 := ringOf(t, 2, 1)
	st.Sealer, dd.Sealer = r2.For("acme"), r2.For("acme")
	if _, err := st.GetBlueprint(ctx, "wifi"); err != nil {
		t.Fatalf("old key no longer reads during rotation: %v", err)
	}
	if n, err := dd.Rewrap(ctx); err != nil || n == 0 {
		t.Fatalf("rotation rewrap: %d %v", n, err)
	}
	if _, err := st.RewrapBlueprints(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := dd.Rewrap(ctx); n != 0 {
		t.Errorf("a second pass changed %d declarations", n)
	}
	only2 := ringOf(t, 2)
	st.Sealer, dd.Sealer = only2.For("acme"), only2.For("acme")
	if got, err := st.GetBlueprint(ctx, "wifi"); err != nil || len(got.Items) != 2 {
		t.Errorf("after rotation the old key is not needed: %v", err)
	}
	if ds, err := dd.List(ctx, "dev"); err != nil || len(ds) != 1 {
		t.Errorf("declarations after rotation: %v", err)
	}
	// Another tenant's key does not open this tenant's data.
	st.Sealer = only2.For("someone-else")
	if _, err := st.GetBlueprint(ctx, "wifi"); err == nil {
		t.Error("a blueprint opened under another tenant's key")
	}
}
