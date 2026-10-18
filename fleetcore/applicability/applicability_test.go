package applicability

import (
	"context"
	"strings"
	"testing"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

func profile(payloads string) []byte {
	return []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>PayloadType</key><string>Configuration</string><key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>t</string><key>PayloadUUID</key><string>U</string><key>PayloadContent</key><array>` + payloads + `</array></dict></plist>`)
}

func payload(typ, extra string) string {
	return `<dict><key>PayloadType</key><string>` + typ + `</string><key>PayloadVersion</key><integer>1</integer><key>PayloadIdentifier</key><string>x.` + typ + `</string><key>PayloadUUID</key><string>V</string>` + extra + `</dict>`
}

// findPayloadOnlyOn returns a payload type the schema supports on `yes` and not on `no`.
func findPayloadOnlyOn(t *testing.T, yes, no string) string {
	for _, p := range schemas.Current().Profiles {
		a, ok1 := p.OS[yes]
		b, ok2 := p.OS[no]
		if ok1 && !a.Unsupported() && ok2 && b.Unsupported() {
			return p.PayloadType
		}
	}
	t.Skipf("no payload type found that is %s-only in this schema set", yes)
	return ""
}

func TestPayloadTypeNotOnPlatformIsLeftOut(t *testing.T) {
	r, _ := NewRegistry(context.Background(), nil, "")
	macOnly := findPayloadOnlyOn(t, "macOS", "iOS")
	res, err := r.Apply(profile(payload(macOnly, "")+payload("com.apple.applicationaccess", `<key>allowCamera</key><true/>`)), "iOS", "18.2")
	if err != nil {
		t.Fatal(err)
	}
	if res.NotApplicable || strings.Contains(string(res.Profile), macOnly) || !strings.Contains(string(res.Profile), "com.apple.applicationaccess") || len(res.LeftOut) == 0 {
		t.Errorf("%s kept on iOS: %+v\n%s", macOnly, res.LeftOut, res.Profile)
	}
	res, _ = r.Apply(profile(payload(macOnly, "")), "iPadOS", "18.2")
	if !res.NotApplicable {
		t.Errorf("a profile with nothing for iPadOS should be not applicable: %+v", res)
	}
	res, _ = r.Apply(profile(payload(macOnly, "")), "macOS", "15.0")
	if res.NotApplicable || len(res.LeftOut) != 0 {
		t.Errorf("macOS keeps its own payloads: %+v", res)
	}
}

func TestKeyNotOnPlatformIsLeftOut(t *testing.T) {
	r, _ := NewRegistry(context.Background(), nil, "")
	var typ, key string
	for _, p := range schemas.Current().Profiles {
		if a, ok := p.OS["iOS"]; !ok || a.Unsupported() {
			continue
		}
		for _, k := range p.Keys {
			if i, ok := k.OS["iOS"]; ok && i.Unsupported() && k.Type == "boolean" {
				if m, ok := k.OS["macOS"]; ok && !m.Unsupported() {
					typ, key = p.PayloadType, k.Key
				}
			}
		}
		if typ != "" {
			break
		}
	}
	if typ == "" {
		t.Skip("no suitable key in this schema set")
	}
	in := profile(payload(typ, `<key>`+key+`</key><true/>`))
	res, _ := r.Apply(in, "iOS", "18.2")
	if strings.Contains(string(res.Profile), "<key>"+key+"</key>") || len(res.LeftOut) != 1 || res.LeftOut[0].Key != key {
		t.Errorf("%s.%s kept on iOS: %+v", typ, key, res)
	}
	res, _ = r.Apply(in, "macOS", "15.0")
	if !strings.Contains(string(res.Profile), "<key>"+key+"</key>") {
		t.Errorf("%s.%s dropped on macOS", typ, key)
	}
}

func TestOverridesForThirdPartyDomains(t *testing.T) {
	ctx := context.Background()
	r, _ := NewRegistry(ctx, nil, "")
	chrome := profile(payload("com.google.Chrome", `<key>HomepageLocation</key><string>x</string>`))
	if res, _ := r.Apply(chrome, "iOS", "18"); !res.NotApplicable {
		t.Errorf("Chrome payload kept on iOS (the shipped default says macOS only): %+v", res)
	}
	if res, _ := r.Apply(chrome, "macOS", "15"); res.NotApplicable {
		t.Error("Chrome payload dropped on macOS")
	}
	// An unknown payload type nobody described is kept.
	if res, _ := r.Apply(profile(payload("com.acme.custom", "")), "iOS", "18"); res.NotApplicable {
		t.Error("an unknown payload type must be kept")
	}
	// The administrator adds a rule; it takes effect and can be removed.
	if err := r.Put(ctx, Override{ID: "acme", Match: "com.acme.*", Platforms: []string{"macOS"}}); err != nil {
		t.Fatal(err)
	}
	if res, _ := r.Apply(profile(payload("com.acme.custom", "")), "iOS", "18"); !res.NotApplicable {
		t.Error("the new override did not apply")
	}
	_ = r.Delete(ctx, "acme")
	if res, _ := r.Apply(profile(payload("com.acme.custom", "")), "iOS", "18"); res.NotApplicable {
		t.Error("the removed override still applies")
	}
	if err := r.Put(ctx, Override{ID: "bad", Match: "x", Platforms: []string{"Windows"}}); err == nil {
		t.Error("an unknown platform was accepted")
	}
	// Preference domains inside managed preferences.
	prefs := profile(payload("com.apple.ManagedClient.preferences", `<key>PayloadContent</key><dict><key>com.google.Chrome</key><dict><key>Forced</key><array/></dict><key>com.apple.dock</key><dict><key>Forced</key><array/></dict></dict>`))
	res, _ := r.Apply(prefs, "macOS", "15")
	if len(res.LeftOut) != 0 {
		t.Errorf("macOS keeps both domains: %+v", res.LeftOut)
	}
}

func TestInvalidProfile(t *testing.T) {
	r, _ := NewRegistry(context.Background(), nil, "")
	if _, err := r.Apply([]byte("not a plist"), "macOS", "15"); err == nil {
		t.Error("garbage accepted")
	}
	if res, err := r.Apply([]byte("anything"), "", ""); err != nil || string(res.Profile) != "anything" {
		t.Errorf("no platform must pass the profile through: %v", err)
	}
}
