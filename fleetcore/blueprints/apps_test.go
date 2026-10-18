package blueprints

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type fakeLicenser struct {
	calls   []string
	pending int
	err     error
}

func (f *fakeLicenser) EnsureLicense(_ context.Context, token, adam, serial, platform string) (bool, bool, error) {
	f.calls = append(f.calls, token+"/"+adam+"/"+serial+"/"+platform)
	if f.err != nil {
		return false, false, f.err
	}
	if f.pending > 0 {
		f.pending--
		return false, true, nil
	}
	return true, false, nil
}

func (f *fixture) serial(id, serial string) {
	if err := f.store.SetDeviceFields(f.ctx, id, bson.D{{Key: "serial", Value: serial}}, true); err != nil {
		panic(err)
	}
}

func (f *fixture) sentOf(rt string) []sent {
	var out []sent
	for _, s := range f.enq.take() {
		if s.requestType() == rt {
			out = append(out, s)
		}
	}
	return out
}

func appBlueprint(extra ...func(*Item)) Blueprint {
	it := Item{ID: "slack", Kind: "app", AdamID: "803453959", BundleID: "com.tinyspeck.chatlyio", VPPToken: "hq"}
	for _, f := range extra {
		f(&it)
	}
	return Blueprint{ID: "apps", Enabled: true, Items: []Item{it}}
}

func TestAppsByCommandAndByDeclaration(t *testing.T) {
	f := newFixture(t)
	lic := &fakeLicenser{pending: 1}
	f.eng.Apps = lic
	f.eng.BaseURL = "https://mdm.example.com"
	f.device("old", "macOS", "15.0") // no managed app declaration before macOS 26
	f.supervised("old", true)
	f.serial("old", "C02OLD")
	f.device("new", "macOS", "26.1")
	f.supervised("new", true)
	f.serial("new", "C02NEW")
	f.save(appBlueprint(func(it *Item) { it.AppConfig = map[string]any{"Server": "https://chat.example.com", "Retries": 3} }))
	f.reconcile()

	// Apple is still assigning the first license: nothing is sent for it yet, and the state says why.
	if a := appFor(f, "old", "slack"); a.State != StateLicensing && a.State != StatePending {
		t.Errorf("old: %+v", a)
	}
	f.now = f.now.Add(time.Minute)
	f.eng.Store.Touch(f.ctx, Rule{})
	f.reconcile()

	// The Mac that cannot take declarations gets the command, with the app configuration inline.
	ins := f.sentOf("InstallApplication")
	var oldCmd *sent
	for i := range ins {
		if ins[i].ids[0] == "old" {
			oldCmd = &ins[i]
		}
	}
	if oldCmd == nil {
		t.Fatalf("no InstallApplication for the old Mac (calls %v)", lic.calls)
	}
	if oldCmd.param("iTunesStoreID") == nil || oldCmd.param("ChangeManagementState") != "Managed" || oldCmd.param("InstallAsManaged") != true {
		t.Errorf("command: %v", oldCmd)
	}
	if cfg, _ := oldCmd.param("Configuration").(map[string]any); cfg["Server"] != "https://chat.example.com" {
		t.Errorf("configuration: %v", oldCmd.param("Configuration"))
	}
	// licensed against the serial number, per device
	joined := strings.Join(lic.calls, " ")
	if !strings.Contains(joined, "hq/803453959/C02OLD/macOS") || !strings.Contains(joined, "hq/803453959/C02NEW/macOS") {
		t.Errorf("licensing calls: %v", lic.calls)
	}

	// The new Mac gets a managed app declaration, with the configuration as an asset.
	d := f.declsOf("new")
	cfg, asset := d["fc.apps.slack"], d["fc.apps.slack.config"]
	if cfg.Type != typeAppManaged || cfg.Payload["AppStoreID"] != "803453959" || cfg.Payload["BundleID"] != "com.tinyspeck.chatlyio" {
		t.Fatalf("declaration: %+v", cfg)
	}
	if ib := cfg.Payload["InstallBehavior"].(map[string]any); ib["Install"] != "Required" || ib["License"].(map[string]any)["Assignment"] != "Device" {
		t.Errorf("install behavior: %v", cfg.Payload["InstallBehavior"])
	}
	if cfg.Payload["AppConfig"].(map[string]any)["LegacyAppConfigAssetReference"] != "fc.apps.slack.config" || asset.Kind != ddm.KindAsset {
		t.Errorf("app configuration: %v / %+v", cfg.Payload["AppConfig"], asset)
	}
	if len(f.sentOf("InstallApplication")) != 0 {
		// (the take above already drained the queue; anything new would be for "new")
		t.Error("a Mac with declarative management was sent the command as well")
	}
	if a := appFor(f, "new", "slack"); a.Delivery != "declarative" || a.State != StatePending {
		t.Errorf("new: %+v", a)
	}

	// Leaving the scope: the command-delivered app is removed by its bundle identifier; the declarative one goes with its declaration.
	f.save(Blueprint{ID: "apps", Enabled: true, Scope: Rule{Field: "serial", Op: "eq", Value: "nobody"}, Items: appBlueprint().Items})
	f.reconcile()
	rm := f.sentOf("RemoveApplication")
	if len(rm) != 1 || rm[0].ids[0] != "old" || rm[0].param("Identifier") != "com.tinyspeck.chatlyio" {
		t.Errorf("removal: %v", rm)
	}
	if _, ok := f.declsOf("new")["fc.apps.slack"]; ok {
		t.Error("the declaration stayed after the device left the scope")
	}
}

func TestAppLicenseProblems(t *testing.T) {
	f := newFixture(t)
	lic := &fakeLicenser{err: errors.New("no licenses of app 803453959 are left (10 owned, 10 assigned)")}
	f.eng.Apps = lic
	f.device("mac", "macOS", "15.0")
	f.supervised("mac", true)
	f.serial("mac", "C02X")
	f.save(appBlueprint())
	f.reconcile()
	a := appFor(f, "mac", "slack")
	if a.State != StateNA || !strings.Contains(a.Note, "no licenses") {
		t.Fatalf("%+v", a)
	}
	if len(f.sentOf("InstallApplication")) != 0 {
		t.Error("an app without a license was sent")
	}
	// licenses are bought: the next look (within ten minutes) installs it
	lic.err = nil
	f.now = f.now.Add(11 * time.Minute)
	f.eng.Store.Touch(f.ctx, Rule{})
	f.reconcile()
	if len(f.sentOf("InstallApplication")) != 1 {
		t.Error("the app was not installed once a license was available")
	}
	// no licensing configured at all
	f2 := newFixture(t)
	f2.device("mac", "macOS", "15.0")
	f2.save(appBlueprint())
	f2.reconcile()
	if a := appFor(f2, "mac", "slack"); a.State != StateNA || !strings.Contains(a.Note, "not configured") {
		t.Errorf("%+v", a)
	}
}

func TestUserEnrollmentAppIsLicensedToThePerson(t *testing.T) {
	f := newFixture(t)
	lic := &fakeLicenser{}
	f.eng.Apps = lic
	f.device("byod", "iOS", "18.2")
	f.store.SetDeviceFields(f.ctx, "byod", bson.D{{Key: "enroll_type", Value: "User Enrollment"}}, true)
	f.save(appBlueprint())
	f.reconcile()
	if len(lic.calls) != 0 {
		t.Errorf("a User Enrollment device has no serial number to license: %v", lic.calls)
	}
	cfg := f.declsOf("byod")["fc.apps.slack"]
	if cfg.Type != typeAppManaged || cfg.Payload["InstallBehavior"].(map[string]any)["License"].(map[string]any)["Assignment"] != "User" {
		t.Errorf("the license should be the person's: %+v", cfg)
	}
}

func TestPreLicenseOnDEPAssignment(t *testing.T) {
	f := newFixture(t)
	lic := &fakeLicenser{}
	f.eng.Apps = lic
	f.save(Blueprint{ID: "apps", Enabled: true, Scope: Rule{Field: "dep_name", Op: "eq", Value: "acme-abm"}, Items: appBlueprint().Items})
	f.save(Blueprint{ID: "other", Enabled: true, Scope: Rule{Field: "dep_name", Op: "eq", Value: "somebody-else"}, Items: []Item{{ID: "x", Kind: "app", AdamID: "999", VPPToken: "hq", BundleID: "com.x"}}})
	f.eng.PreLicense(f.ctx, DEPDevice{Serial: "C02NEW", Model: "MacBook Air", OS: "OSX", DEPName: "acme-abm"})
	if len(lic.calls) != 1 || lic.calls[0] != "hq/803453959/C02NEW/macOS" {
		t.Errorf("pre-licensing: %v", lic.calls)
	}
}

func TestAppItemValidation(t *testing.T) {
	bad := map[string]Item{
		"neither":      {ID: "a", Kind: "app"},
		"both":         {ID: "a", Kind: "app", AdamID: "1", ManifestURL: "https://x/m.plist", VPPToken: "t"},
		"letters":      {ID: "a", Kind: "app", AdamID: "12ab", VPPToken: "t"},
		"no token":     {ID: "a", Kind: "app", AdamID: "123"},
		"http":         {ID: "a", Kind: "app", ManifestURL: "http://x/m.plist", BundleID: "com.x"},
		"no bundle":    {ID: "a", Kind: "app", ManifestURL: "https://x/m.plist"},
		"auto update":  {ID: "a", Kind: "app", AdamID: "123", VPPToken: "t", AutoUpdate: "Sometimes"},
		"bad delivery": {ID: "a", Kind: "app", AdamID: "123", VPPToken: "t", Delivery: "profile"},
	}
	for name, it := range bad {
		if err := (&Blueprint{ID: "b", Items: []Item{it}}).Prepare(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	good := []Item{{ID: "a", Kind: "app", AdamID: "123", VPPToken: "t"}, {ID: "b", Kind: "app", ManifestURL: "https://x/m.plist", BundleID: "com.x"}}
	if err := (&Blueprint{ID: "b", Items: good}).Prepare(); err != nil {
		t.Error(err)
	}
	// the bundle identifier can be left out when the app is kept on leaving
	if err := (&Blueprint{ID: "b", KeepOnLeave: true, Items: []Item{{ID: "m", Kind: "app", ManifestURL: "https://x/m.plist"}}}).Prepare(); err != nil {
		t.Error(err)
	}
}
