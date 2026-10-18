package blueprints

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"github.com/micromdm/nanomdm/mdm"
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
	// An unsupervised Mac can take neither: Apple allows both only on supervised devices. It is told why.
	if a := appFor(f, "byod", "os"); a.State != StateNA || !strings.Contains(a.Note, "supervised") {
		t.Errorf("byod: %+v", a)
	}
	if _, ok := f.declsOf("byod")["fc.updates.os"]; ok {
		t.Error("an unsupervised Mac was given the enforcement declaration")
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

func TestSoftwareUpdateFallsBackToTheMDMCommand(t *testing.T) {
	f := newFixture(t)
	f.releases()
	// An iPhone below iOS 17 cannot take declarative enforcement; ScheduleOSUpdate still exists there.
	f.device("old-phone", "iOS", "16.4")
	f.supervised("old-phone", true)
	f.store.SetDeviceFields(f.ctx, "old-phone", bson.D{{Key: "model", Value: "iPhone16,1"}}, true)
	// A Mac past the removal of the commands and without supervision has no way: told so, not failed.
	f.device("new-mac", "macOS", "27.0")
	// A supervised Mac on 14 takes the declaration, not the command.
	f.device("sonoma", "macOS", "14.2")
	f.supervised("sonoma", true)
	f.save(Blueprint{ID: "updates", Enabled: true, Items: []Item{{ID: "os", Kind: "os_update", Target: "latest", InstallAction: "DownloadOnly"}}})
	f.reconcile()

	var cmd *sent
	for _, s := range f.enq.take() {
		s := s
		if s.requestType() == "ScheduleOSUpdate" {
			cmd = &s
		}
	}
	if cmd == nil || cmd.ids[0] != "old-phone" {
		t.Fatalf("no ScheduleOSUpdate for the old iPhone: %v", cmd)
	}
	updates, _ := cmd.param("Updates").([]any)
	if len(updates) != 1 || updates[0].(map[string]any)["InstallAction"] != "DownloadOnly" {
		t.Errorf("updates: %v", cmd.param("Updates"))
	}
	if a := appFor(f, "old-phone", "os"); a.Kind != "os_update" || a.State != StatePending || a.Delivery == "declarative" {
		t.Errorf("old phone: %+v", a)
	}
	if a := appFor(f, "new-mac", "os"); a.State != StateNA {
		t.Errorf("new mac: %+v", a)
	}
	if _, ok := f.declsOf("sonoma")["fc.updates.os"]; !ok {
		t.Error("the supervised Mac on 14 should have the declaration")
	}
}

func TestSingleInstanceDeclarationsDoNotCollide(t *testing.T) {
	f := newFixture(t)
	f.device("mac", "macOS", "27.0.1")
	f.supervised("mac", true)
	item := func(limit int) Item {
		return Item{ID: "cache", Kind: "declaration", DeclarationType: "com.apple.configuration.content-cache.settings", Declaration: map[string]any{"CacheLimit": limit}}
	}
	f.save(Blueprint{ID: "high", Enabled: true, Priority: 10, Items: []Item{item(100)}})
	f.save(Blueprint{ID: "low", Enabled: true, Priority: 1, Items: []Item{item(200)}})
	f.reconcile()
	d := f.declsOf("mac")
	if d["fc.high.cache"].Type == "" || d["fc.low.cache"].Type != "" {
		t.Errorf("only the higher priority may be sent: %v", keys(d))
	}
	if a := appFor(f, "mac", "cache"); a.Blueprint == "low" && a.State != StateNA {
		t.Errorf("low: %+v", a)
	}
	apps, _ := f.store.Applications(f.ctx, "mac")
	var lowNote string
	for _, a := range apps {
		if a.Blueprint == "low" {
			lowNote = a.Note
		}
	}
	if !strings.Contains(lowNote, "conflicts with high/cache") {
		t.Errorf("low's note: %q", lowNote)
	}
}

func TestOrganizationInfoIsSent(t *testing.T) {
	f := newFixture(t)
	f.eng.Organization = "Acme Co"
	f.device("mac", "macOS", "15.0")
	f.supervised("mac", true)
	f.save(Blueprint{ID: "x", Enabled: true})
	f.reconcile()
	if d := f.declsOf("mac")["fc.org"]; d.Kind != ddm.KindManagement || d.Payload["Name"] != "Acme Co" {
		t.Errorf("%+v", d)
	}
}

func TestAssetsAreHostedAndReferenced(t *testing.T) {
	f := newFixture(t)
	f.eng.BaseURL = "https://mdm.example.com"
	f.device("phone", "iOS", "18.2")
	f.supervised("phone", true)
	creds := []byte(`{"Username":"u","Password":"p"}`)
	bp := Blueprint{ID: "cal", Enabled: true, Items: []Item{
		{ID: "pw", Kind: "asset", DeclarationType: "com.apple.asset.credential.userpassword", AssetData: creds, ContentType: "application/json"},
		{ID: "acct", Kind: "declaration", DeclarationType: "com.apple.configuration.account.caldav", Declaration: map[string]any{"HostName": "cal.example.com", "AuthenticationCredentialsAssetReference": "$asset:pw"}, Predicate: "@status(device.model.family) == 'iPhone'"},
	}}
	f.save(bp)
	f.reconcile()
	d := f.declsOf("phone")
	asset, cfg := d["fc.cal.pw"], d["fc.cal.acct"]
	ref, _ := asset.Payload["Reference"].(map[string]any)
	if asset.Kind != ddm.KindAsset || ref == nil || ref["Size"] != float64(len(creds)) || ref["ContentType"] != "application/json" || len(ref["Hash-SHA-256"].(string)) != 64 {
		t.Fatalf("asset: %+v", asset)
	}
	if cfg.Payload["AuthenticationCredentialsAssetReference"] != "fc.cal.pw" {
		t.Errorf("the reference was not resolved: %v", cfg.Payload)
	}
	if act := d["fc.cal.acct.act"]; act.Payload["Predicate"] != "@status(device.model.family) == 'iPhone'" {
		t.Errorf("the predicate did not reach the activation: %v", act.Payload)
	}
	if _, ok := d["fc.cal.pw.act"]; ok {
		t.Error("an asset needs no activation")
	}
	url := ref["DataURL"].(string)
	blob, _ := f.ddm.GetBlob(f.ctx, "phone", url[strings.LastIndex(url, "/")+1:])
	if blob == nil || string(blob.Body) != string(creds) || blob.ContentType != "application/json" {
		t.Errorf("the asset data is not served: %+v", blob)
	}
	// An item that refers to an asset the blueprint does not have is refused when saved.
	bad := Blueprint{ID: "bad", Items: []Item{{ID: "acct", Kind: "declaration", DeclarationType: "com.apple.configuration.account.caldav", Declaration: map[string]any{"HostName": "x", "AuthenticationCredentialsAssetReference": "$asset:missing"}}}}
	if err := bad.Prepare(); err == nil {
		t.Error("a reference to a missing asset was accepted")
	}
}

func TestUserScopedDeclarations(t *testing.T) {
	f := newFixture(t)
	f.device("mac", "macOS", "15.0")
	f.supervised("mac", true)
	f.store.AddUser(f.ctx, "mac", "mac:alice")
	f.store.AddUser(f.ctx, "mac", "mac:bob")
	item := Item{ID: "cal", Kind: "declaration", DeclarationType: "com.apple.configuration.account.caldav", Declaration: map[string]any{"HostName": "cal.example.com"}}
	// On macOS this account type is delivered to the user channel only.
	f.save(Blueprint{ID: "sys", Enabled: true, Items: []Item{item}})
	f.reconcile()
	if a := appFor(f, "mac", "cal"); a.State != StateNA || !strings.Contains(a.Note, "user-scoped") {
		t.Errorf("system scope on macOS: %+v", a)
	}
	user := item
	user.Scope = "user"
	f.save(Blueprint{ID: "usr", Enabled: true, Items: []Item{user}})
	f.reconcile()
	for _, u := range []string{"mac:alice", "mac:bob"} {
		d := f.declsOf(u)["fc.usr.cal"]
		if d.Type != "com.apple.configuration.account.caldav" || d.Source != "usr/cal@"+u {
			t.Errorf("%s: %+v", u, d)
		}
		if a := appFor(f, "mac", "cal@"+u); a.State != StatePending {
			t.Errorf("%s record: %+v", u, a)
		}
	}
	if _, ok := f.declsOf("mac")["fc.usr.cal"]; ok {
		t.Error("a user-scoped declaration went to the device channel")
	}
	// each user channel is told to sync, not the device for it
	told := map[string]bool{}
	for _, s := range f.enq.take() {
		if s.requestType() == "DeclarativeManagement" {
			told[s.ids[0]] = true
		}
	}
	if !told["mac:alice"] || !told["mac:bob"] {
		t.Errorf("user channels not told to sync: %v", told)
	}
	// A report from a user channel updates that user's record.
	tok := f.declsOf("mac:alice")["fc.usr.cal"].Token()
	f.eng.OnStatus(f.ctx, "mac:alice", ddm.Report{StatusItems: map[string]rawJSON{"management.declarations": rawJSON(declStatus("fc.usr.cal", tok, "valid", true, nil))}})
	if a := appFor(f, "mac", "cal@mac:alice"); a.State != StateApplied {
		t.Errorf("alice: %+v", a)
	}
	if a := appFor(f, "mac", "cal@mac:bob"); a.State != StatePending {
		t.Errorf("bob must stay pending: %+v", a)
	}
	// A user who leaves loses the declaration.
	leave := mdm.NewRequestWithContext(f.ctx, nil)
	leave.EnrollID = &mdm.EnrollID{ID: "mac:bob", ParentID: "mac", Type: mdm.User}
	f.obs.DDM = f.ddm
	if err := f.obs.CheckOut(leave, &mdm.CheckOut{}); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	if len(f.declsOf("mac:bob")) != 0 {
		t.Error("a user who left still has declarations")
	}
}

func TestLegacyProfileAsAssetOn27AndStatusExtras(t *testing.T) {
	f := newFixture(t)
	f.eng.BaseURL = "https://mdm.example.com"
	f.device("new", "macOS", "27.0.1")
	f.supervised("new", true)
	f.device("old", "macOS", "15.0")
	f.supervised("old", true)
	f.store.SetDeviceFields(f.ctx, "old", bson.D{{Key: "tags", Value: []string{"eng"}}, {Key: "groups", Value: []string{"Engineering"}}}, true)
	f.save(Blueprint{ID: "wifi", Enabled: true, StatusItems: []string{"diskmanagement.filevault.enabled", "passcode.is-compliant"}, Items: []Item{{ID: "wifi", Kind: "profile", Payload: wifiProfile("corp")}}})
	f.reconcile()

	d := f.declsOf("new")
	cfg, asset := d["fc.wifi.wifi"], d["fc.wifi.wifi.asset"]
	if cfg.Payload["ProfileAssetReference"] != "fc.wifi.wifi.asset" || cfg.Payload["ProfileURL"] != nil {
		t.Errorf("on 27 the profile is an asset reference: %v", cfg.Payload)
	}
	ref, _ := asset.Payload["Reference"].(map[string]any)
	if asset.Type != "com.apple.asset.data" || ref["ContentType"] != "application/x-plist" || ref["Hash-SHA-256"] == nil {
		t.Errorf("asset: %+v", asset)
	}
	if old := f.declsOf("old")["fc.wifi.wifi"]; old.Payload["ProfileURL"] == nil || old.Payload["ProfileAssetReference"] != nil {
		t.Errorf("before 27 it is a URL: %v", old.Payload)
	}
	// the blueprint's extra status item is subscribed, and the server's properties and capabilities are sent
	var names []string
	for _, it := range f.declsOf("old")["fc.status"].Payload["StatusItems"].([]any) {
		names = append(names, it.(map[string]any)["Name"].(string))
	}
	joined := strings.Join(names, " ")
	if !strings.Contains(joined, "diskmanagement.filevault.enabled") {
		t.Errorf("the blueprint's status item is not subscribed: %v", names)
	}
	if strings.Contains(joined, "passcode.is-compliant") {
		t.Errorf("a status item that does not exist on macOS was subscribed: %v", names)
	}
	props := f.declsOf("old")["fc.properties"]
	if props.Kind != ddm.KindManagement || props.Payload["tags"].([]any)[0] != "eng" || props.Payload["groups"].([]any)[0] != "Engineering" {
		t.Errorf("properties: %+v", props)
	}
	if c := f.declsOf("old")["fc.capabilities"]; c.Payload["Version"] != "1.0" {
		t.Errorf("capabilities: %+v", c)
	}
	// an unknown status item is refused when saving
	if err := (&Blueprint{ID: "x", StatusItems: []string{"no.such.item"}}).Prepare(); err == nil {
		t.Error("an unknown status item was accepted")
	}
}

type fakePeople map[string]string

func (f fakePeople) ManagedAppleID(_ context.Context, cn string) string { return f[cn] }

func TestUserEnrollmentRules(t *testing.T) {
	f := newFixture(t)
	f.obs.BYOD = fakePeople{"ue-abc": "alice@example.com"}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "ue-abc"}}
	au := func(id string, typ mdm.EnrollType, c *x509.Certificate) {
		r := mdm.NewRequestWithContext(f.ctx, c)
		r.EnrollID = &mdm.EnrollID{ID: id, Type: typ}
		raw := []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>OSVersion</key><string>18.2</string><key>ProductName</key><string>iPhone16,1</string></dict></plist>`)
		if err := f.obs.Authenticate(r, &mdm.Authenticate{Raw: raw}); err != nil {
			t.Fatal(err)
		}
	}
	au("ue1", mdm.UserEnrollment, cert)
	au("dev1", mdm.Device, nil)
	d, _ := f.store.GetDevice(f.ctx, "ue1")
	if d.ManagedAppleID != "alice@example.com" || !d.UserEnrollment() || d.EnrollKind() != "user" {
		t.Fatalf("the BYOD device is not tied to its person: %+v", d)
	}
	if other, _ := f.store.GetDevice(f.ctx, "dev1"); other.ManagedAppleID != "" || other.UserEnrollment() {
		t.Errorf("a normal enrollment picked up a person: %+v", other)
	}
	// the person is a field smart groups can use
	env, _ := f.eng.Env(f.ctx)
	x, _ := Rule{Field: "user", Op: "eq", Value: "alice@example.com"}.Expand(env)
	ds, _ := f.store.QueryDevices(f.ctx, x, "", 10)
	if len(ds) != 1 || ds[0].ID != "ue1" || !x.Match(&ds[0]) {
		t.Errorf("rule on the person: %v", ds)
	}

	// What Apple forbids on User Enrollment is not sent: a command, and the part of a profile that is forbidden.
	var forbiddenPayload string
	for _, p := range schemas.Current().Profiles {
		if i, ok := p.OS["iOS"]; ok && !i.Unsupported() && i.UserEnrollment == "forbidden" {
			forbiddenPayload = p.PayloadType
			break
		}
	}
	items := []Item{{ID: "where", Kind: "command", RequestType: "DeviceLocation"}}
	if forbiddenPayload != "" {
		items = append(items, Item{ID: "mixed", Kind: "profile", Payload: profile("com.example.mixed", payload(forbiddenPayload, "")+payload("com.apple.wifi.managed", `<key>SSID_STR</key><string>x</string>`))})
	}
	f.save(Blueprint{ID: "ue", Enabled: true, Items: items})
	f.reconcile()
	if a := appFor(f, "ue1", "where"); a.State != StateNA || !strings.Contains(a.Note, "User Enrollment") {
		t.Errorf("DeviceLocation on a BYOD device: %+v", a)
	}
	if a := appFor(f, "dev1", "where"); a.State == StateNA {
		t.Errorf("DeviceLocation on a normal enrollment must be sent: %+v", a)
	}
	if forbiddenPayload != "" {
		if a := appFor(f, "ue1", "mixed"); !strings.Contains(a.Note, "left out") {
			t.Errorf("the forbidden payload was not left out: %+v", a)
		}
		if a := appFor(f, "dev1", "mixed"); strings.Contains(a.Note, forbiddenPayload) {
			t.Errorf("a normal enrollment lost %s: %+v", forbiddenPayload, a)
		}
	}
}

func (f *fixture) awaitingMac(id, serial string) {
	r := mdm.NewRequestWithContext(f.ctx, nil)
	r.EnrollID = &mdm.EnrollID{ID: id, Type: mdm.Device}
	au := &mdm.Authenticate{SerialNumber: serial, Raw: []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>OSVersion</key><string>15.0</string><key>ProductName</key><string>Mac15,6</string></dict></plist>`)}
	au.UDID = id
	if err := f.obs.Authenticate(r, au); err != nil {
		panic(err)
	}
	tu := &mdm.TokenUpdate{Raw: []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>AwaitingConfiguration</key><true/></dict></plist>`)}
	tu.UDID = id
	if err := f.obs.TokenUpdate(r, tu); err != nil {
		panic(err)
	}
}

func (f *fixture) deviceConfigured() []sent {
	var out []sent
	for _, s := range f.enq.take() {
		if s.requestType() == "DeviceConfigured" {
			out = append(out, s)
		}
	}
	return out
}

// A device Apple assigned to this server is known before it enrolls, is supervised and carries its DEP name when it does, and is held in Setup Assistant until what it must have is done.
func TestAutomatedDeviceEnrollment(t *testing.T) {
	f := newFixture(t)
	f.eng.OnDEPDevice = nil
	heard := 0
	f.eng.OnDEPDevice = func(_ context.Context, d DEPDevice, removed bool) { heard++ }
	f.eng.DEPDeviceEvent(f.ctx, DEPDevice{Serial: "C02ADE", Model: "MacBook Air", DEPName: "acme-abm", Supervised: true}, false)
	if heard != 1 {
		t.Errorf("the assignment was heard %d times", heard)
	}
	if rec, _ := f.store.DEPRecord(f.ctx, "C02ADE"); rec == nil || rec.DEPName != "acme-abm" {
		t.Fatalf("the assigned device is not remembered: %+v", rec)
	}

	// Enrolling: the device learns its DEP name and that it is supervised, from its serial number alone.
	f.awaitingMac("ade-mac", "C02ADE")
	d, _ := f.store.GetDevice(f.ctx, "ade-mac")
	if d.DEPName != "acme-abm" || d.Supervised == nil || !*d.Supervised || !d.Awaiting {
		t.Fatalf("the enrolled device: %+v", d)
	}
	// A Mac that is not assigned is neither.
	f.awaitingMac("byo-mac", "C02OTHER")
	if o, _ := f.store.GetDevice(f.ctx, "byo-mac"); o.DEPName != "" || (o.Supervised != nil && *o.Supervised) {
		t.Errorf("an unassigned Mac: %+v", o)
	}
	// the DEP name is a field smart groups can use
	env, _ := f.eng.Env(f.ctx)
	x, _ := Rule{Field: "dep_name", Op: "eq", Value: "acme-abm"}.Expand(env)
	if ds, _ := f.store.QueryDevices(f.ctx, x, "", 10); len(ds) != 1 || ds[0].ID != "ade-mac" {
		t.Errorf("rule on the DEP name: %v", ds)
	}

	// A Setup item holds the device in Setup Assistant until it is applied.
	f.save(Blueprint{ID: "setup", Enabled: true, Scope: Rule{Field: "dep_name", Op: "eq", Value: "acme-abm"}, Items: []Item{
		{ID: "wifi", Kind: "profile", Setup: true, Delivery: "profile", Payload: wifiProfile("setup-net")},
	}})
	f.reconcile()
	var install *sent
	for _, s := range f.enq.take() {
		s := s
		if s.requestType() == "InstallProfile" {
			install = &s
		}
	}
	if install == nil {
		t.Fatal("the Setup profile was not sent")
	}
	f.now = f.now.Add(time.Minute)
	f.eng.Store.Touch(f.ctx, Rule{})
	f.reconcile()
	if got := f.deviceConfigured(); len(got) != 0 {
		t.Fatal("the device was released before its Setup profile was installed")
	}
	f.answer("ade-mac", install.uuid(), "Acknowledged") // applied; the device is looked at at once
	f.reconcile()
	got := f.deviceConfigured()
	if len(got) != 1 || got[0].ids[0] != "ade-mac" {
		t.Fatalf("the device was not released once its Setup profile was applied: %v", got)
	}
	if d, _ := f.store.GetDevice(f.ctx, "ade-mac"); d.Awaiting {
		t.Error("a released device is still awaiting")
	}
	f.eng.Store.Touch(f.ctx, Rule{})
	f.reconcile()
	if len(f.deviceConfigured()) != 0 {
		t.Error("DeviceConfigured was sent twice")
	}
	// A device with nothing to wait for is released at once.
	if got := f.deviceConfigured(); len(got) != 0 {
		t.Fatal(got)
	}
	f.reconcile()
	if len(f.deviceConfigured()) == 0 {
		// byo-mac is not in the Setup blueprint's scope
		t.Log("byo-mac released (no Setup items)")
	}

	// A device whose Setup item never completes is released when the wait runs out.
	f.awaitingMac("stuck-mac", "C02ADE")
	f.store.SetDeviceFields(f.ctx, "stuck-mac", bson.D{{Key: "awaiting", Value: true}, {Key: "awaiting_since", Value: f.now}}, true)
	f.reconcile()
	f.enq.take()
	f.now = f.now.Add(31 * time.Minute)
	f.eng.Store.Touch(f.ctx, Rule{})
	f.reconcile()
	released := false
	for _, s := range f.deviceConfigured() {
		released = released || s.ids[0] == "stuck-mac"
	}
	if !released {
		t.Error("a device stuck in Setup Assistant was never released")
	}

	// Apple takes a device back.
	f.eng.DEPDeviceEvent(f.ctx, DEPDevice{Serial: "C02ADE"}, true)
	if rec, _ := f.store.DEPRecord(f.ctx, "C02ADE"); rec != nil {
		t.Error("a device Apple took back is still recorded")
	}
}
