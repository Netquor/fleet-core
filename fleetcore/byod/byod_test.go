package byod

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/micromdm/nanomdm/fleetcore/enroll"
	"github.com/micromdm/plist"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type challenges struct{ n int }

func (c *challenges) SCEPChallenge() (string, error) { c.n++; return "challenge-1", nil }

func idp(t *testing.T) (*rsa.PrivateKey, *httptest.Server) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	return key, srv
}

func token(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	tk := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tk.Header["kid"] = "k1"
	s, err := tk.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAccountDrivenEnrollment(t *testing.T) {
	key, jwks := idp(t)
	auth := &OIDC{Issuer: "https://idp.example.com", JWKSURL: jwks.URL, Audience: "fleetcore"}
	ch := &challenges{}
	h := Handler(Config{Auth: auth, LoginURL: "https://idp.example.com/login", Challenges: ch, Profile: enroll.Options{Organization: "Example", Identifier: "com.example.byod", ServerURL: "https://mdm.example.com/mdm", SCEPURL: "https://mdm.example.com/scep", Topic: "com.apple.mgmt.External.x"}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	now := time.Now()
	good := jwt.MapClaims{"iss": "https://idp.example.com", "aud": "fleetcore", "exp": now.Add(time.Hour).Unix(), "sub": "u1", "email": "alice@example.com"}
	get := func(tok string) *http.Response {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Without a token the device is sent to sign in.
	r := get("")
	if r.StatusCode != 401 || r.Header.Get("WWW-Authenticate") != `Bearer method="apple-as-web" url="https://idp.example.com/login"` {
		t.Errorf("no token: %d %q", r.StatusCode, r.Header.Get("WWW-Authenticate"))
	}
	// Tokens that are not good enough.
	for name, claims := range map[string]jwt.MapClaims{
		"expired":        {"iss": "https://idp.example.com", "aud": "fleetcore", "exp": now.Add(-time.Hour).Unix(), "email": "a@example.com"},
		"wrong audience": {"iss": "https://idp.example.com", "aud": "other", "exp": now.Add(time.Hour).Unix(), "email": "a@example.com"},
		"wrong issuer":   {"iss": "https://evil.example.com", "aud": "fleetcore", "exp": now.Add(time.Hour).Unix(), "email": "a@example.com"},
		"no account":     {"iss": "https://idp.example.com", "aud": "fleetcore", "exp": now.Add(time.Hour).Unix()},
		"no expiry":      {"iss": "https://idp.example.com", "aud": "fleetcore", "email": "a@example.com"},
	} {
		if r := get(token(t, key, claims)); r.StatusCode != 401 {
			t.Errorf("%s token got %d", name, r.StatusCode)
		}
	}
	// A token signed by someone else's key.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if r := get(token(t, other, good)); r.StatusCode != 401 {
		t.Errorf("a token signed with another key got %d", r.StatusCode)
	}
	// A token with the algorithm "none".
	none := jwt.NewWithClaims(jwt.SigningMethodNone, good)
	none.Header["kid"] = "k1"
	ns, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if r := get(ns); r.StatusCode != 401 {
		t.Errorf("an unsigned token got %d", r.StatusCode)
	}
	if ch.n != 0 {
		t.Errorf("%d challenges were made for requests that were refused", ch.n)
	}

	// A good token gets the person's profile.
	r = get(token(t, key, good))
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Fatalf("good token: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	var prof struct {
		PayloadContent []map[string]any
	}
	buf := new(strings.Builder)
	b := make([]byte, 1<<16)
	n, _ := r.Body.Read(b)
	buf.Write(b[:n])
	if err := plist.Unmarshal([]byte(buf.String()), &prof); err != nil {
		t.Fatal(err)
	}
	var mdm, scep map[string]any
	for _, p := range prof.PayloadContent {
		switch p["PayloadType"] {
		case "com.apple.mdm":
			mdm = p
		case "com.apple.security.scep":
			scep = p["PayloadContent"].(map[string]any)
		}
	}
	if mdm == nil || scep == nil || mdm["EnrollmentMode"] != "BYOD" || mdm["AssignedManagedAppleID"] != "alice@example.com" {
		t.Fatalf("profile: %v", prof)
	}
	if _, has := mdm["AccessRights"]; has {
		t.Error("a User Enrollment profile must not ask for access rights")
	}
	subject := scep["Subject"].([]any)
	cn := subject[1].([]any)[0].([]any)[1].(string)
	if !strings.HasPrefix(cn, "ue-") || scep["Challenge"] != "challenge-1" {
		t.Errorf("identity: cn %q challenge %v", cn, scep["Challenge"])
	}
}

func TestWellKnown(t *testing.T) {
	rec := httptest.NewRecorder()
	WellKnown("https://mdm.example.com/enroll/byod").ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/com.apple.remotemanagement", nil))
	var doc struct {
		Servers []struct{ Version, BaseURL string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || len(doc.Servers) != 1 || doc.Servers[0].Version != "mdm-byod" || doc.Servers[0].BaseURL != "https://mdm.example.com/enroll/byod" {
		t.Errorf("%s %v", rec.Body.String(), err)
	}
}

func TestStoreRemembersThePerson(t *testing.T) {
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
	db := mc.Database("fleetcore_byod_test")
	db.Drop(ctx)
	defer db.Drop(ctx)
	a, _ := NewStore(ctx, db, "acme")
	b, _ := NewStore(ctx, db, "globex")
	if err := a.Put(ctx, "ue-1", Identity{ManagedAppleID: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if a.ManagedAppleID(ctx, "ue-1") != "alice@example.com" || b.ManagedAppleID(ctx, "ue-1") != "" || a.ManagedAppleID(ctx, "ue-2") != "" {
		t.Error("the store must keep tenants and names apart")
	}
}
