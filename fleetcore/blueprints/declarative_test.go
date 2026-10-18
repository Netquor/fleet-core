package blueprints

import (
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (f *fixture) supervised(id string, yes bool) {
	if err := f.store.SetDeviceFields(f.ctx, id, bson.D{{Key: "supervised", Value: yes}}, true); err != nil {
		panic(err)
	}
}

func (f *fixture) declsOf(id string) map[string]ddm.Declaration {
	ds, err := f.ddm.List(f.ctx, id)
	if err != nil {
		panic(err)
	}
	m := map[string]ddm.Declaration{}
	for _, d := range ds {
		m[d.Identifier] = d
	}
	return m
}

func (f *fixture) releases() {
	pub := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	rs := []osreleases.Release{
		{Platform: "macOS", Version: "27.0.1", Major: 27, Num: 27000001, PublishedAt: pub, Source: "gdmf"},
		{Platform: "macOS", Version: "26.6.2", Major: 26, Num: 26006002, PublishedAt: pub.AddDate(0, 0, -20), Source: "gdmf"},
		{Platform: "iOS", Version: "27.0.1", Major: 27, Num: 27000001, PublishedAt: pub, Devices: []string{"iPhone16,1"}, Source: "gdmf"},
		{Platform: "iOS", Version: "26.7.1", Major: 26, Num: 26007001, PublishedAt: pub.AddDate(0, 0, -4), Devices: []string{"iPhone12,1", "iPhone16,1"}, Source: "gdmf"},
	}
	f.rel.Replace(rs)
	f.rel.SetAvailable(rs)
}

func TestSoftwareUpdateEnforcement(t *testing.T) {
	f := newFixture(t)
	f.releases()
	f.device("mac", "macOS", "26.5")
	f.supervised("mac", true)
	f.device("byod", "macOS", "26.5") // not supervised: Apple allows enforcement only on supervised Macs
	f.device("current", "macOS", "27.0.1")
	f.supervised("current", true)
	f.device("old-iphone", "iOS", "26.4")
	f.supervised("old-iphone", true)
	f.store.SetDeviceFields(f.ctx, "old-iphone", bson.D{{Key: "model", Value: "iPhone12,1"}}, true)

	days := 5
	hour := 9
	_ = days
	f.save(Blueprint{ID: "updates", Enabled: true, Items: []Item{{ID: "os", Kind: "os_update", Target: "latest", DeadlineDays: days, DeadlineHour: &hour, DetailsURL: "https://example.com/os"}}})
	f.reconcile()

	// The supervised Mac gets the newest release, with a deadline counted from the release date.
	d := f.declsOf("mac")
	cfg, ok := d["fc.updates.os"]
	if !ok {
		t.Fatalf("no enforcement declaration for the Mac: %v", keys(d))
	}
	if cfg.Type != typeEnforceSpecific || cfg.Payload["TargetOSVersion"] != "27.0.1" || cfg.Payload["TargetLocalDateTime"] != "2026-10-23T09:00:00" || cfg.Payload["DetailsURL"] != "https://example.com/os" {
		t.Errorf("payload: %v", cfg.Payload)
	}
	act, ok := d["fc.updates.os.act"]
	if !ok || act.Kind != ddm.KindActivation || act.Payload["StandardConfigurations"].([]any)[0] != "fc.updates.os" {
		t.Errorf("activation: %+v", act)
	}
	if _, ok := d["fc.status"]; !ok {
		t.Error("the status subscription is missing")
	}
	// The iPhone that cannot run 27 is moved to the newest it can.
	if c := f.declsOf("old-iphone")["fc.updates.os"]; c.Payload["TargetOSVersion"] != "26.7.1" {
		t.Errorf("old iPhone: %v", c.Payload)
	}
	// An unsupervised Mac is told why not, not failed.
	apps, _ := f.store.Applications(f.ctx, "byod")
	var found bool
	for _, a := range apps {
		if a.Item == "os" {
			found = true
			if a.State != StateNA || !strings.Contains(a.Note, "not available") {
				t.Errorf("byod: %+v", a)
			}
		}
	}
	if !found {
		t.Error("no record for the unsupervised Mac")
	}
	// A Mac already on the release has nothing to enforce.
	if _, ok := f.declsOf("current")["fc.updates.os"]; ok {
		t.Error("a current device was given an enforcement")
	}
	if apps, _ := f.store.Applications(f.ctx, "current"); len(apps) != 1 || apps[0].State != StateApplied {
		t.Errorf("current: %+v", apps)
	}

	// The device was told to sync (once), by the DeclarativeManagement command.
	var nudges int
	for _, s := range f.enq.take() {
		if s.requestType() == "DeclarativeManagement" && s.ids[0] == "mac" {
			nudges++
		}
	}
	if nudges != 1 {
		t.Errorf("the Mac was told to sync %d times", nudges)
	}
	f.eng.Store.Touch(f.ctx, Rule{})
	f.reconcile()
	for _, s := range f.enq.take() {
		if s.requestType() == "DeclarativeManagement" && s.ids[0] == "mac" {
			t.Error("told to sync again with nothing new")
		}
	}

	// The device reports: the declaration is active and valid -> applied; invalid -> failed with the reason.
	token := cfg.Token()
	rep := func(valid string, active bool, reasons ...ddm.Reason) ddm.Report {
		return ddm.Report{StatusItems: map[string]rawJSON{"device.operating-system.version": rawJSON(`"26.5"`), "management.declarations": rawJSON(declStatus("fc.updates.os", token, valid, active, reasons))}}
	}
	f.eng.OnStatus(f.ctx, "mac", rep("valid", false))
	if a := appFor(f, "mac", "os"); a.State != StatePending {
		t.Errorf("valid but not yet active: %+v", a)
	}
	f.eng.OnStatus(f.ctx, "mac", rep("valid", true))
	if a := appFor(f, "mac", "os"); a.State != StateApplied {
		t.Errorf("active: %+v", a)
	}
	f.eng.OnStatus(f.ctx, "mac", rep("invalid", false, ddm.Reason{Code: "Error.ConfigurationCannotBeApplied", Description: "target not available"}))
	if a := appFor(f, "mac", "os"); a.State != StateFailed || !strings.Contains(a.Error, "target not available") {
		t.Errorf("invalid: %+v", a)
	}
	// A report for a token we no longer serve is ignored.
	stale := ddm.Report{StatusItems: map[string]rawJSON{"management.declarations": rawJSON(declStatus("fc.updates.os", "old-token", "valid", true, nil))}}
	f.eng.OnStatus(f.ctx, "mac", stale)
	if a := appFor(f, "mac", "os"); a.State != StateFailed {
		t.Errorf("a stale report changed the state: %+v", a)
	}

	// When the Mac updates (its status says so), the enforcement is lifted.
	f.eng.OnStatus(f.ctx, "mac", ddm.Report{StatusItems: map[string]rawJSON{"device.operating-system.version": rawJSON(`"27.0.1"`)}})
	f.reconcile()
	if _, ok := f.declsOf("mac")["fc.updates.os"]; ok {
		t.Error("the enforcement stayed after the Mac updated")
	}
	if dv, _ := f.store.GetDevice(f.ctx, "mac"); dv.OSVersion != "27.0.1" {
		t.Errorf("inventory did not follow the status report: %s", dv.OSVersion)
	}
}

func TestDeclarationItemAndLeavingScope(t *testing.T) {
	f := newFixture(t)
	f.device("mac", "macOS", "15.0", "eng")
	f.supervised("mac", true)
	f.save(Blueprint{ID: "pw", Enabled: true, Scope: Rule{Field: "tag", Op: "eq", Value: "eng"}, Items: []Item{
		{ID: "passcode", Kind: "declaration", DeclarationType: "com.apple.configuration.passcode.settings", Declaration: map[string]any{"RequirePasscode": true, "MinimumLength": 10}},
	}})
	f.reconcile()
	if _, ok := f.declsOf("mac")["fc.pw.passcode"]; !ok {
		t.Fatalf("declaration missing: %v", keys(f.declsOf("mac")))
	}
	// leaving the scope takes the declaration (and its activation) away
	f.store.SetDeviceFields(f.ctx, "mac", bsonDTags(nil), true)
	f.reconcile()
	d := f.declsOf("mac")
	if _, ok := d["fc.pw.passcode"]; ok {
		t.Error("declaration stayed after leaving the scope")
	}
	if _, ok := d["fc.pw.passcode.act"]; ok {
		t.Error("activation stayed after leaving the scope")
	}
	if apps, _ := f.store.Applications(f.ctx, "mac"); len(apps) != 0 {
		t.Errorf("records left: %+v", apps)
	}
	// An invalid payload is refused when the blueprint is saved.
	bad := Blueprint{ID: "bad", Items: []Item{{ID: "x", Kind: "declaration", DeclarationType: "com.apple.configuration.passcode.settings", Declaration: map[string]any{"MinimumLength": "ten"}}}}
	if err := bad.Prepare(); err == nil {
		t.Error("a payload of the wrong type was accepted")
	}
	unknown := Blueprint{ID: "bad2", Items: []Item{{ID: "x", Kind: "declaration", DeclarationType: "com.example.nope"}}}
	if err := unknown.Prepare(); err == nil {
		t.Error("an unknown declaration type was accepted")
	}
}

func TestOldOSCannotTakeDeclarations(t *testing.T) {
	f := newFixture(t)
	f.device("ancient", "macOS", "12.6")
	f.supervised("ancient", true)
	f.save(Blueprint{ID: "pw", Enabled: true, Items: []Item{{ID: "p", Kind: "declaration", DeclarationType: "com.apple.configuration.passcode.settings", Declaration: map[string]any{"RequirePasscode": true}}}})
	f.reconcile()
	apps, _ := f.store.Applications(f.ctx, "ancient")
	if len(apps) != 1 || apps[0].State != StateNA || !strings.Contains(apps[0].Note, "cannot take declarative management") {
		t.Errorf("%+v", apps)
	}
	if len(f.declsOf("ancient")) != 0 {
		t.Error("declarations stored for a device that cannot use them")
	}
}

func appFor(f *fixture, device, item string) Application {
	apps, _ := f.store.Applications(f.ctx, device)
	for _, a := range apps {
		if a.Item == item {
			return a
		}
	}
	return Application{}
}

func keys(m map[string]ddm.Declaration) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func wifiProfile(ssid string) []byte {
	return profile("com.example.wifi", payload("com.apple.wifi.managed", `<key>SSID_STR</key><string>`+ssid+`</string>`))
}

func (f *fixture) installs() []sent {
	var out []sent
	for _, s := range f.enq.take() {
		if s.requestType() == "InstallProfile" {
			out = append(out, s)
		}
	}
	return out
}

func TestProfilesRideDeclarativeManagementWhenTheDeviceCan(t *testing.T) {
	f := newFixture(t)
	f.eng.BaseURL = "https://mdm.example.com"
	f.device("sup", "macOS", "15.0")
	f.supervised("sup", true)
	f.device("byod", "macOS", "15.0") // an unsupervised Mac cannot take declarations: it keeps getting the profile by command
	f.device("phone", "iOS", "18.2")  // a device enrollment iPhone can
	f.save(Blueprint{ID: "wifi", Enabled: true, Items: []Item{{ID: "wifi", Kind: "profile", Payload: wifiProfile("corp")}}})
	f.reconcile()

	// Supervised Mac and iPhone: a legacy-profile declaration, no InstallProfile.
	for _, id := range []string{"sup", "phone"} {
		d := f.declsOf(id)["fc.wifi.wifi"]
		if d.Type != typeLegacy || !strings.HasPrefix(d.Payload["ProfileURL"].(string), "https://mdm.example.com/ddm/profile/") {
			t.Errorf("%s: legacy declaration missing: %+v", id, d)
		}
		key := d.Payload["ProfileURL"].(string)[len("https://mdm.example.com/ddm/profile/"):]
		body, _ := f.ddm.Profile(f.ctx, id, key)
		if !strings.Contains(string(body), "com.example.wifi") {
			t.Errorf("%s: the profile body is not downloadable (%d bytes)", id, len(body))
		}
		if a := appFor(f, id, "wifi"); a.Delivery != "declarative" || a.State != StatePending {
			t.Errorf("%s: %+v", id, a)
		}
	}
	// the unsupervised Mac gets the command
	ins := f.installs()
	if len(ins) != 1 || ins[0].ids[0] != "byod" {
		t.Fatalf("expected one InstallProfile, for byod: %d", len(ins))
	}
	if a := appFor(f, "byod", "wifi"); a.Delivery != "profile" {
		t.Errorf("byod: %+v", a)
	}

	// the status channel confirms it
	d := f.declsOf("sup")["fc.wifi.wifi"]
	f.eng.OnStatus(f.ctx, "sup", ddm.Report{StatusItems: map[string]rawJSON{"management.declarations": rawJSON(declStatus("fc.wifi.wifi", d.Token(), "valid", true, nil))}})
	if a := appFor(f, "sup", "wifi"); a.State != StateApplied {
		t.Errorf("%+v", a)
	}

	// byod is supervised later (say it went through Apple Business Manager): the profile moves to declarative delivery, removed first.
	f.answer("byod", ins[0].uuid(), "Acknowledged")
	f.supervised("byod", true)
	f.reconcile()
	var rm *sent
	for _, s := range f.enq.take() {
		if s.requestType() == "RemoveProfile" && s.ids[0] == "byod" {
			s := s
			rm = &s
		}
	}
	if rm == nil || rm.param("Identifier") != "com.example.wifi" {
		t.Fatal("the installed profile was not removed before the declaration took over")
	}
	if _, ok := f.declsOf("byod")["fc.wifi.wifi"]; ok {
		t.Error("the declaration was delivered while the profile was still installed")
	}
	f.answer("byod", rm.uuid(), "Acknowledged")
	f.reconcile()
	if d := f.declsOf("byod")["fc.wifi.wifi"]; d.Type != typeLegacy {
		t.Errorf("the declaration did not follow the removal: %+v", d)
	}
	if got := f.installs(); len(got) != 0 {
		t.Errorf("an InstallProfile was sent as well: %d", len(got))
	}
}

func TestDeliveryChoices(t *testing.T) {
	f := newFixture(t)
	f.eng.BaseURL = "https://mdm.example.com"
	f.device("sup", "macOS", "15.0")
	f.supervised("sup", true)
	f.device("byod", "macOS", "15.0")
	f.save(Blueprint{ID: "forced", Enabled: true, Items: []Item{
		{ID: "cmd", Kind: "profile", Delivery: "profile", Payload: wifiProfile("a")},
		{ID: "decl", Kind: "profile", Delivery: "declarative", Payload: profile("com.example.vpn", payload("com.apple.wifi.managed", `<key>SSID_STR</key><string>b</string>`))},
	}})
	f.reconcile()
	// "profile" is always a command, even where declarations would work
	got := f.installs()
	ids := map[string]int{}
	for _, s := range got {
		ids[s.ids[0]]++
	}
	if ids["sup"] != 1 || ids["byod"] != 1 {
		t.Errorf("delivery profile: %v", ids)
	}
	// "declarative" on a device that cannot is not silently downgraded
	if a := appFor(f, "byod", "decl"); a.State != StateNA || !strings.Contains(a.Note, "declarative delivery is not possible") {
		t.Errorf("byod: %+v", a)
	}
	if a := appFor(f, "sup", "decl"); a.Delivery != "declarative" {
		t.Errorf("sup: %+v", a)
	}
}

func TestEquivalentsExistInTheSchema(t *testing.T) {
	set := schemas.Current()
	for payload, decls := range ddm.Equivalents() {
		if _, ok := set.Profile(payload); !ok {
			t.Errorf("profile payload %s is not in the schema", payload)
		}
		for _, d := range decls {
			if _, ok := set.Declaration(d); !ok {
				t.Errorf("%s: declaration %s is not in the schema", payload, d)
			}
		}
	}
}
