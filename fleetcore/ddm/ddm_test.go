package ddm

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func req(ctx context.Context, id string) *mdm.Request {
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{ID: id}
	return r
}

func TestProtocol(t *testing.T) {
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
	db := mc.Database("fleetcore_ddm_test")
	db.Drop(ctx)
	defer db.Drop(ctx)
	st, err := NewStore(ctx, db, "")
	if err != nil {
		t.Fatal(err)
	}
	var got Report
	svc := &Service{Store: st, OnStatus: func(_ context.Context, _ string, r Report) { got = r }}
	call := func(endpoint string, data []byte) ([]byte, error) {
		return svc.DeclarativeManagement(req(ctx, "dev1"), &mdm.DeclarativeManagement{Endpoint: endpoint, Data: data})
	}

	cfg := Declaration{Identifier: "cfg1", Kind: KindConfiguration, Type: "com.apple.configuration.passcode.settings", Payload: map[string]any{"MinimumLength": 8}, Source: "bp/item"}
	act := Declaration{Identifier: "cfg1.act", Kind: KindActivation, Type: "com.apple.activation.simple", Payload: map[string]any{"StandardConfigurations": []any{"cfg1"}}, Source: "bp/item"}

	// A device with nothing still gets valid answers.
	b, err := call("tokens", nil)
	if err != nil || !json.Valid(b) {
		t.Fatalf("tokens for a new device: %s %v", b, err)
	}
	changed, state, err := st.Replace(ctx, "dev1", []Declaration{cfg, act})
	if err != nil || !changed || state.Token == "" {
		t.Fatalf("%v %v %+v", changed, err, state)
	}
	// The same set again changes nothing (so the device is not told to sync again).
	if changed, _, _ := st.Replace(ctx, "dev1", []Declaration{act, cfg}); changed {
		t.Error("an identical set counted as a change")
	}

	b, _ = call("tokens", nil)
	var tok struct {
		SyncTokens struct{ DeclarationsToken, Timestamp string }
	}
	json.Unmarshal(b, &tok)
	if tok.SyncTokens.DeclarationsToken != state.Token || tok.SyncTokens.Timestamp == "" {
		t.Errorf("tokens: %s", b)
	}
	b, _ = call("declaration-items", nil)
	var items struct {
		Declarations struct {
			Configurations, Activations []struct{ Identifier, ServerToken string }
		}
		DeclarationsToken string
	}
	json.Unmarshal(b, &items)
	if len(items.Declarations.Configurations) != 1 || items.Declarations.Configurations[0].ServerToken != cfg.Token() || len(items.Declarations.Activations) != 1 || items.DeclarationsToken != state.Token {
		t.Fatalf("items: %s", b)
	}
	b, err = call("declaration/configuration/cfg1", nil)
	var wire struct {
		Type, Identifier, ServerToken string
		Payload                       map[string]any
	}
	json.Unmarshal(b, &wire)
	if err != nil || wire.Identifier != "cfg1" || wire.ServerToken != cfg.Token() || wire.Payload["MinimumLength"] != float64(8) {
		t.Fatalf("declaration: %s %v", b, err)
	}
	if s, _ := st.State(ctx, "dev1"); s.SyncedToken != state.Token {
		t.Error("fetching the items was not recorded")
	}
	// A wrong kind or a missing identifier is a 404, not an empty answer.
	for _, ep := range []string{"declaration/activation/cfg1", "declaration/configuration/nope"} {
		_, err := call(ep, nil)
		var he *service.HTTPStatusError
		if err == nil || !asStatus(err, &he) || he.Status != http.StatusNotFound {
			t.Errorf("%s: %v", ep, err)
		}
	}

	// A changed payload changes its token and the set's.
	cfg2 := cfg
	cfg2.Payload = map[string]any{"MinimumLength": 12}
	changed, state2, _ := st.Replace(ctx, "dev1", []Declaration{cfg2, act})
	if !changed || state2.Token == state.Token || cfg2.Token() == cfg.Token() {
		t.Error("a changed payload kept its token")
	}
	// Dropping one removes it.
	st.Replace(ctx, "dev1", []Declaration{act})
	if d, _ := st.Get(ctx, "dev1", KindConfiguration, "cfg1"); d != nil {
		t.Error("a removed declaration is still served")
	}

	// A status report is stored and passed on.
	report := `{"StatusItems":{"device.operating-system.version":"15.1","management.declarations":{"configurations":[{"identifier":"cfg1","server-token":"` + cfg.Token() + `","active":true,"valid":"valid"}],"activations":[],"assets":[],"management":[]}},"Errors":[]}`
	if _, err := call("status", []byte(report)); err != nil {
		t.Fatal(err)
	}
	if got.String("device.operating-system.version") != "15.1" || len(got.Declarations()) != 1 || !got.Declarations()[0].Active {
		t.Errorf("report: %+v", got)
	}
	decls, items2, _, err := st.Status(ctx, "dev1")
	if err != nil || !decls["cfg1"].Active || items2["device·operating-system·version"] != "15.1" {
		t.Errorf("stored status: %+v %v %v", decls, items2, err)
	}
	if _, err := call("status", []byte("not json")); err == nil {
		t.Error("a malformed report was accepted")
	}
}

func asStatus(err error, target **service.HTTPStatusError) bool {
	for err != nil {
		if e, ok := err.(*service.HTTPStatusError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestTranslatePasscode(t *testing.T) {
	tr, ok := Translate("com.apple.mobiledevice.passwordpolicy", map[string]any{
		"PayloadType": "com.apple.mobiledevice.passwordpolicy", "forcePIN": true, "minLength": 8, "allowSimple": false, "maxInactivity": 5, "somethingNew": "x",
	}, "", schemas.Embedded())
	if !ok || tr.Declaration != "com.apple.configuration.passcode.settings" {
		t.Fatalf("%+v", tr)
	}
	want := map[string]any{"RequirePasscode": true, "MinimumLength": 8, "RequireComplexPasscode": true, "MaximumInactivityInMinutes": 5}
	for k, v := range want {
		if tr.Payload[k] != v {
			t.Errorf("%s: got %v want %v", k, tr.Payload[k], v)
		}
	}
	if len(tr.Untranslated) != 1 || tr.Untranslated[0] != "somethingNew" || tr.Approximate["allowSimple"] == "" {
		t.Errorf("untranslated %v approximate %v", tr.Untranslated, tr.Approximate)
	}
	// every key the translation produced is a key of the declaration
	def, _ := schemas.Embedded().Declaration(tr.Declaration)
	known := map[string]bool{}
	for _, k := range def.Keys {
		known[k.Key] = true
	}
	for k := range tr.Payload {
		if !known[k] {
			t.Errorf("%s is not a key of %s", k, tr.Declaration)
		}
	}
	if _, ok := Translate("com.example.unknown", nil, "", schemas.Embedded()); ok {
		t.Error("an unknown payload type was translated")
	}
}
