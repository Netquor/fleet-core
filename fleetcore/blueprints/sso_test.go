package blueprints

import (
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/commands"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

func TestSSOPayloadLayers(t *testing.T) {
	p, err := SSOPayload(Item{Kind: "platform_sso", Preset: "entra", SSO: map[string]any{"PlatformSSO": map[string]any{"AuthenticationMethod": "UserSecureEnclaveKey", "AccountDisplayName": "Example"}, "Type": "Redirect"}})
	if err != nil {
		t.Fatal(err)
	}
	if p["ExtensionIdentifier"] != "com.microsoft.CompanyPortalMac.ssoextension" || p["TeamIdentifier"] != "UBF8T346G9" || p["PlatformSSO"].(map[string]any)["AccountDisplayName"] != "Example" {
		t.Errorf("%v", p)
	}
	if urls, _ := p["URLs"].([]any); len(urls) < 3 {
		t.Errorf("the preset's URLs are missing: %v", p["URLs"])
	}
	// the item's settings win over the preset's
	p, _ = SSOPayload(Item{Kind: "platform_sso", Preset: "entra", SSO: map[string]any{"Type": "Credential"}})
	if p["Type"] != "Credential" {
		t.Errorf("override: %v", p["Type"])
	}
	// placeholders are filled from parameters, and a missing one is an error naming it
	missing := map[string]bool{}
	got := substitute(map[string]any{"u": []any{"https://{{ domain }}/x", "{{other}}"}}, map[string]string{"domain": "example.okta.com"}, missing)
	if s := got.(map[string]any)["u"].([]any)[0]; s != "https://example.okta.com/x" || !missing["other"] {
		t.Errorf("%v %v", got, missing)
	}
	if _, err := SSOPayload(Item{Preset: "nope"}); err == nil {
		t.Error("an unknown preset")
	}
}

func TestSSOItemValidation(t *testing.T) {
	ok := Item{ID: "sso", Kind: "platform_sso", Preset: "entra", SSO: map[string]any{"PlatformSSO": map[string]any{"AuthenticationMethod": "UserSecureEnclaveKey"}}}
	if err := (&Blueprint{ID: "b", Items: []Item{ok}}).Prepare(); err != nil {
		t.Fatal(err)
	}
	for name, it := range map[string]Item{
		"no extension":   {ID: "sso", Kind: "platform_sso"},
		"unknown preset": {ID: "sso", Kind: "platform_sso", Preset: "ghost"},
		"bad method":     {ID: "sso", Kind: "platform_sso", Preset: "entra", SSO: map[string]any{"PlatformSSO": map[string]any{"AuthenticationMethod": "Telepathy"}}},
		"bad delivery":   {ID: "sso", Kind: "platform_sso", Preset: "entra", Delivery: "command"},
	} {
		if err := (&Blueprint{ID: "b", Items: []Item{it}}).Prepare(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestPlatformSSODelivery(t *testing.T) {
	f := newFixture(t)
	f.device("sup", "macOS", "15.0")
	f.supervised("sup", true)
	f.device("loose", "macOS", "15.0") // not supervised: no declarations for this Mac, so a profile
	f.device("phone", "iOS", "18.2")
	f.supervised("phone", true)
	f.save(Blueprint{ID: "sso", Enabled: true, Items: []Item{{ID: "login", Kind: "platform_sso", Preset: "entra", SSO: map[string]any{"PlatformSSO": map[string]any{"AuthenticationMethod": "UserSecureEnclaveKey", "EnableAuthorization": true}}}}})
	f.reconcile()

	// macOS 27 takes the declaration; before that, the profile
	f.device("new", "macOS", "27.0")
	f.supervised("new", true)
	f.reconcile()
	d := f.declsOf("new")["fc.sso.login"]
	if d.Type != typeExtensibleSSO || d.Payload["ExtensionComposedIdentifier"] != "com.microsoft.CompanyPortalMac.ssoextension (UBF8T346G9)" {
		t.Fatalf("declaration: %+v", d)
	}
	if pso := d.Payload["PlatformSSO"].(map[string]any); pso["AuthenticationMethod"] != "UserSecureEnclaveKey" || pso["Authorization"].(map[string]any)["EnableIdentityProviderAccounts"] != true {
		t.Errorf("the settings are not in the declaration's groups: %v", d.Payload["PlatformSSO"])
	}
	if _, ok := f.declsOf("sup")["fc.sso.login"]; ok {
		t.Error("a Mac before macOS 27 was given the declaration form")
	}
	var profile *sent
	for _, s := range f.enq.take() {
		s := s
		if s.requestType() == "InstallProfile" && s.ids[0] == "loose" {
			profile = &s
		}
	}
	if profile == nil {
		t.Fatal("the unsupervised Mac got no profile")
	}
	raw, _ := profile.param("Payload").([]byte)
	if !strings.Contains(string(raw), "com.apple.extensiblesso") || !strings.Contains(string(raw), "UserSecureEnclaveKey") {
		t.Errorf("the profile: %s", raw)
	}
	if a := appFor(f, "phone", "login"); a.State != StateNA || !strings.Contains(a.Note, "Macs") {
		t.Errorf("an iPhone with a Mac-only setting: %+v", a)
	}
	// a profile identifier that stays the same keeps the profile from being reinstalled
	f.eng.Store.Touch(f.ctx, Rule{})
	f.now = f.now.Add(time.Minute)
	f.reconcile()
}

// Every flat setting of the profile has a place in the declaration, or is reported; and what is produced is valid by Apple's schema for the declaration.
func TestSSODeclarationFollowsTheSchema(t *testing.T) {
	prof, _ := schemas.Current().Profile("com.apple.extensiblesso")
	var pso *schemas.Key
	for i := range prof.Keys {
		if prof.Keys[i].Key == "PlatformSSO" {
			pso = &prof.Keys[i]
		}
	}
	flat := map[string]any{}
	for _, k := range pso.Keys {
		switch k.Type {
		case "boolean":
			flat[k.Key] = true
		case "integer":
			flat[k.Key] = int64(3600)
			if k.Min != nil {
				flat[k.Key] = int64(*k.Min)
			}
		case "string":
			if len(k.Allowed) > 0 {
				flat[k.Key] = k.Allowed[0]
			} else {
				flat[k.Key] = "x"
			}
		}
	}
	decl, dropped := SSODeclaration(map[string]any{"ExtensionIdentifier": "com.example.sso", "TeamIdentifier": "ABCD1234", "Type": "Redirect", "PlatformSSO": flat}, "macOS")
	for _, d := range dropped {
		t.Logf("not expressible in the declaration: %s", d)
	}
	def, _ := schemas.Current().Declaration(typeExtensibleSSO)
	if ps := commands.Check(def.Keys, decl, ""); len(ps) > 0 {
		t.Errorf("the declaration is not valid by the schema: %v", ps)
	}
	// only the two UUID-based access key settings have no counterpart (the declaration refers to assets instead)
	for _, d := range dropped {
		if d != "PlatformSSO.AccessKeyTerminalIdentityUUID" && d != "PlatformSSO.AccessKeyReaderIssuerCertificateUUID" {
			t.Errorf("%s has no place in the declaration", d)
		}
	}
}
