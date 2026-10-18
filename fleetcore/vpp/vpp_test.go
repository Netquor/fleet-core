package vpp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func sToken(org string, exp time.Time) string {
	b, _ := json.Marshal(map[string]string{"token": "secret-bearer", "expDate": exp.Format(time.RFC3339), "orgName": org})
	return base64.StdEncoding.EncodeToString(b)
}

func TestParseToken(t *testing.T) {
	tok, err := ParseToken(sToken("Example", time.Now().Add(time.Hour)))
	if err != nil || tok.OrgName != "Example" || tok.Expires.IsZero() || tok.Token != "secret-bearer" {
		t.Fatalf("%+v %v", tok, err)
	}
	for _, bad := range []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte("not json")), base64.StdEncoding.EncodeToString([]byte(`{"orgName":"x"}`))} {
		if _, err := ParseToken(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// fakeApple is enough of the service to license an app: assets with counts, assignments, and asynchronous events.
type fakeApple struct {
	assigned    map[string]bool // adam|serial
	events      map[string]string
	associates  atomic.Int32
	available   int
	assignable  bool
	rateLimited bool
}

func (f *fakeApple) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apple wants the token as downloaded (the whole base64 text) as the bearer.
		if tok, err := ParseToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); err != nil || tok.Token != "secret-bearer" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]any{"errorNumber": 9622, "errorMessage": "bad token"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/client/config":
			json.NewEncoder(w).Encode(map[string]any{"locationName": "HQ", "countryISO2ShortCode": "US"})
		case r.URL.Path == "/assets":
			json.NewEncoder(w).Encode(map[string]any{"assets": []any{map[string]any{"adamId": r.URL.Query().Get("adamId"), "pricingParam": "STDQ", "deviceAssignable": f.assignable, "supportedPlatforms": []string{"iOS", "macOS"}, "totalCount": 10, "assignedCount": 10 - f.available, "availableCount": f.available}}})
		case r.URL.Path == "/assignments" && r.Method == "GET":
			var out []any
			for k := range f.assigned {
				p := strings.SplitN(k, "|", 2)
				if (r.URL.Query().Get("adamId") == "" || r.URL.Query().Get("adamId") == p[0]) && (r.URL.Query().Get("serialNumber") == "" || r.URL.Query().Get("serialNumber") == p[1]) {
					out = append(out, map[string]any{"adamId": p[0], "pricingParam": "STDQ", "serialNumber": p[1]})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"assignments": out})
		case r.URL.Path == "/assignments/associate":
			if f.rateLimited {
				w.Header().Set("Retry-After", "5")
				w.WriteHeader(429)
				return
			}
			f.associates.Add(1)
			var b assignBody
			json.NewDecoder(r.Body).Decode(&b)
			id := "EV" + string(rune('0'+f.associates.Load()))
			f.events[id] = "PROCESSING"
			for _, a := range b.Assets {
				for _, s := range b.SerialNumbers {
					f.assigned[a.AdamID+"|"+s] = true
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"eventId": id})
		case r.URL.Path == "/status":
			json.NewEncoder(w).Encode(map[string]any{"eventId": r.URL.Query().Get("eventId"), "eventStatus": f.events[r.URL.Query().Get("eventId")]})
		default:
			http.NotFound(w, r)
		}
	})
}

func TestLicensing(t *testing.T) {
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
	db := mc.Database("fleetcore_vpp_test")
	db.Drop(ctx)
	defer db.Drop(ctx)
	fa := &fakeApple{assigned: map[string]bool{}, events: map[string]string{}, available: 3, assignable: true}
	srv := httptest.NewServer(fa.handler(t))
	defer srv.Close()
	st, err := NewStore(ctx, db, "acme")
	if err != nil {
		t.Fatal(err)
	}
	lic := &Licensing{Store: st, BaseURL: srv.URL}

	// tokens: checked with Apple and kept
	if _, err := st.PutToken(ctx, "hq", sToken("Example", time.Now().Add(-time.Hour)), nil); err == nil {
		t.Error("an expired token was accepted")
	}
	info, err := st.PutToken(ctx, "hq", sToken("Example", time.Now().Add(24*time.Hour)), &Client{BaseURL: srv.URL})
	if err != nil || info.LocationName != "HQ" || info.OrgName != "Example" {
		t.Fatalf("%+v %v", info, err)
	}
	raw := db.Collection("vpp_tokens").FindOne(ctx, map[string]any{})
	var doc map[string]any
	raw.Decode(&doc)
	if b, _ := json.Marshal(doc); strings.Contains(string(b), "secret-bearer") {
		t.Log("token stored without a sealer (as configured)")
	}

	// first ask: Apple is asked to assign; it is pending until the event completes
	ready, pending, err := lic.EnsureLicense(ctx, "hq", "497799835", "C02A", "macOS")
	if err != nil || ready || !pending || fa.associates.Load() != 1 {
		t.Fatalf("first: ready %v pending %v err %v asks %d", ready, pending, err, fa.associates.Load())
	}
	// asking again while it is pending does not ask Apple again
	if _, p, _ := lic.EnsureLicense(ctx, "hq", "497799835", "C02A", "macOS"); !p || fa.associates.Load() != 1 {
		t.Errorf("pending: %v, asks %d", p, fa.associates.Load())
	}
	fa.events["EV1"] = "COMPLETE"
	if ready, _, err := lic.EnsureLicense(ctx, "hq", "497799835", "C02A", "macOS"); err != nil || !ready {
		t.Fatalf("after the event: %v %v", ready, err)
	}
	if ready, _, _ := lic.EnsureLicense(ctx, "hq", "497799835", "C02A", "macOS"); !ready || fa.associates.Load() != 1 {
		t.Error("an assigned license was asked for again")
	}
	// a license Apple already shows as held is not asked for
	fa.assigned["497799835|C02HELD"] = true
	if ready, _, err := lic.EnsureLicense(ctx, "hq", "497799835", "C02HELD", "macOS"); err != nil || !ready || fa.associates.Load() != 1 {
		t.Errorf("held: %v %v asks %d", ready, err, fa.associates.Load())
	}
	// cases that cannot work say why
	fa.available = 0
	if _, _, err := lic.EnsureLicense(ctx, "hq", "111", "C02B", "macOS"); err == nil || !strings.Contains(err.Error(), "no licenses") {
		t.Errorf("none left: %v", err)
	}
	fa.available = 3
	if _, _, err := lic.EnsureLicense(ctx, "hq", "222", "C02B", "tvOS"); err == nil || !strings.Contains(err.Error(), "not available for tvOS") {
		t.Errorf("platform: %v", err)
	}
	fa.assignable = false
	if _, _, err := lic.EnsureLicense(ctx, "hq", "333", "C02B", "macOS"); err == nil || !strings.Contains(err.Error(), "user licensing") {
		t.Errorf("not device assignable: %v", err)
	}
	fa.assignable = true
	if _, _, err := lic.EnsureLicense(ctx, "hq", "444", "", "macOS"); err == nil {
		t.Error("a license without a serial number")
	}
	// Apple asks to wait: pending, not an error
	fa.rateLimited = true
	if ready, pending, err := lic.EnsureLicense(ctx, "hq", "555", "C02C", "macOS"); err != nil || ready || !pending {
		t.Errorf("rate limited: %v %v %v", ready, pending, err)
	}
	// the API
	api := httptest.NewServer(http.StripPrefix("/v1", lic.Handler()))
	defer api.Close()
	res, _ := http.Get(api.URL + "/v1/vpp/tokens")
	var tl struct{ Tokens []TokenInfo }
	json.NewDecoder(res.Body).Decode(&tl)
	if len(tl.Tokens) != 1 || tl.Tokens[0].Name != "hq" {
		t.Errorf("tokens: %+v", tl)
	}
	res, _ = http.Get(api.URL + "/v1/vpp/hq/assets?adam_id=497799835")
	b := new(strings.Builder)
	buf := make([]byte, 4096)
	n, _ := res.Body.Read(buf)
	b.Write(buf[:n])
	if res.StatusCode != 200 || !strings.Contains(b.String(), "availableCount") {
		t.Errorf("assets: %d %s", res.StatusCode, b.String())
	}
	if res, _ := http.Get(api.URL + "/v1/vpp/nope/assets"); res.StatusCode != 404 {
		t.Errorf("an unknown token: %d", res.StatusCode)
	}
}
