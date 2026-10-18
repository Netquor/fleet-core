package dep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/golang-jwt/jwt/v5"
	"github.com/micromdm/nanodep/client"
	nanolog "github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/mdm"
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

// A device signing in with a Managed Apple Account asks the MDM server for a token: a JWT signed with the DEP name's key, naming the server as Apple Business Manager knows it.
func TestManagedAppleAccountToken(t *testing.T) {
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
	db := mc.Database("fleetcore_maid_test")
	db.Drop(ctx)
	defer db.Drop(ctx)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/session":
			io.WriteString(w, `{"auth_session_token":"tok"}`)
		case "/account":
			io.WriteString(w, `{"server_uuid":"11111111-2222-3333-4444-555555555555","server_name":"fleetcore"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()
	store, _ := New(ctx, db, "", "p")
	svc, _ := NewService(ctx, db, store, "", nanolog.NopLogger)
	if err := store.StoreConfig(ctx, "org", &client.Config{BaseURL: fake.URL}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if err := store.StoreAuthTokens(ctx, "org", &client.OAuth1Tokens{ConsumerKey: "a", ConsumerSecret: "b", AccessToken: "c", AccessSecret: "d", AccessTokenExpiry: exp}); err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := store.StoreTokenPKI(ctx, "org", []byte("CERT"), keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := store.UpstageTokenPKI(ctx, "org"); err != nil {
		t.Fatal(err)
	}
	req := mdm.NewRequestWithContext(ctx, nil)
	req.EnrollID = &mdm.EnrollID{ID: "e1"}
	// no name given, one DEP name stored: it signs
	resp, err := svc.GetToken("").GetToken(req, &mdm.GetToken{TokenServiceType: "com.apple.maid"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Parse(string(resp.TokenData), func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !tok.Valid {
		t.Fatalf("the token does not verify with the DEP key: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["iss"] != "11111111-2222-3333-4444-555555555555" || claims["jti"] == "" || claims["service_type"] == nil {
		t.Errorf("claims: %v", claims)
	}
}
