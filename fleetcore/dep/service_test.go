package dep

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanolib/log/stdlogfmt"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// A stand-in for Apple's DEP service: tokens are stored through the API, the syncer fetches the devices, a later sync removes one, and the API lists what is left.
func TestSyncAgainstFakeDEP(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mc, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Disconnect(context.Background())
	db := mc.Database("fleetcore_dep_svc_test")
	db.Drop(ctx)
	defer db.Drop(context.Background())

	synced := make(chan struct{}, 4)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/session":
			io.WriteString(w, `{"auth_session_token":"tok"}`)
		case "/server/devices":
			io.WriteString(w, `{"cursor":"c1","fetched_until":"2026-10-18T00:00:00Z","more_to_follow":false,"devices":[
				{"serial_number":"C02AAA","model":"MacBook Air","os":"OSX","device_family":"Mac","op_type":"added"},
				{"serial_number":"C02BBB","model":"Mac mini","os":"OSX","device_family":"Mac","op_type":"added"}]}`)
		case "/devices/sync":
			io.WriteString(w, `{"cursor":"c2","fetched_until":"2026-10-18T00:01:00Z","more_to_follow":false,"devices":[{"serial_number":"C02BBB","model":"Mac mini","op_type":"deleted"}]}`)
			synced <- struct{}{}
		default:
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()

	store, err := New(ctx, db, "", "pass")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(ctx, db, store, "", stdlogfmt.New(stdlogfmt.WithDebugFlag(true)))
	if err != nil {
		t.Fatal(err)
	}
	svc.Interval = time.Hour
	go svc.Run(ctx)
	time.Sleep(200 * time.Millisecond)
	api := httptest.NewServer(svc.Handler("/v1/dep"))
	defer api.Close()

	put := func(path, body string) int {
		req, _ := http.NewRequest("PUT", api.URL+path, strings.NewReader(body))
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if c := put("/v1/dep/config/acme", `{"base_url":"`+fake.URL+`"}`); c != 200 {
		t.Fatalf("config: %d", c)
	}
	exp := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	if c := put("/v1/dep/tokens/acme", `{"consumer_key":"ck","consumer_secret":"cs","access_token":"at","access_secret":"as","access_token_expiry":"`+exp+`"}`); c != 200 {
		t.Fatalf("tokens: %d", c)
	}

	// Storing the tokens starts the syncer: a fetch (two devices), then a sync (one removed).
	select {
	case <-synced:
	case <-time.After(15 * time.Second):
		t.Fatal("the syncer did not run")
	}
	time.Sleep(300 * time.Millisecond)
	r, err := http.Get(api.URL + "/v1/dep/devices/acme")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Devices []map[string]any `json:"devices"`
	}
	json.NewDecoder(r.Body).Decode(&out)
	r.Body.Close()
	if len(out.Devices) != 1 || out.Devices[0]["serial_number"] != "C02AAA" {
		t.Fatalf("devices: %v", out.Devices)
	}
	if cur, _ := store.RetrieveCursor(ctx, "acme"); cur != "c2" {
		t.Errorf("cursor %q", cur)
	}
	// The secrets are not in the database in the clear.
	raw := db.Collection(collection).FindOne(ctx, map[string]any{"_id": "acme"})
	var d map[string]any
	raw.Decode(&d)
	if strings.Contains(toJSON(d), `"as"`) && !strings.Contains(toJSON(d), "aesgcm:") {
		t.Error("tokens stored in the clear")
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
