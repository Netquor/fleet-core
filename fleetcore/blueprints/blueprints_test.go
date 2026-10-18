package blueprints

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanolib/log/stdlogfmt"
	"github.com/micromdm/nanomdm/fleetcore/applicability"
	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/plist"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func testLogger() log.Logger {
	if os.Getenv("BP_DEBUG") != "" {
		return stdlogfmt.New(stdlogfmt.WithDebugFlag(true))
	}
	return log.NopLogger
}

type sent struct {
	ids  []string
	body []byte
}

type recorder struct {
	mu   sync.Mutex
	sent []sent
}

func (r *recorder) Enqueue(_ context.Context, ids []string, body []byte) error {
	r.mu.Lock()
	r.sent = append(r.sent, sent{ids, body})
	r.mu.Unlock()
	return nil
}

func (r *recorder) installs() int {
	n := 0
	for _, s := range r.take() {
		if s.requestType() == "InstallProfile" {
			n++
		}
	}
	return n
}

func (r *recorder) take() []sent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sent
	r.sent = nil
	return out
}

func (s sent) requestType() string {
	var c struct{ Command struct{ RequestType string } }
	_ = plist.Unmarshal(s.body, &c)
	return c.Command.RequestType
}

func (s sent) uuid() string {
	var c struct{ CommandUUID string }
	_ = plist.Unmarshal(s.body, &c)
	return c.CommandUUID
}

func (s sent) param(key string) any {
	var c struct{ Command map[string]any }
	_ = plist.Unmarshal(s.body, &c)
	return c.Command[key]
}

func profile(id, extraPayloads string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>PayloadType</key><string>Configuration</string><key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>` + id + `</string><key>PayloadUUID</key><string>11111111-1111-1111-1111-111111111111</string>
<key>PayloadContent</key><array>` + extraPayloads + `</array></dict></plist>`)
}

func payload(typ, extra string) string {
	return `<dict><key>PayloadType</key><string>` + typ + `</string><key>PayloadVersion</key><integer>1</integer><key>PayloadIdentifier</key><string>` + typ + `.x</string><key>PayloadUUID</key><string>22222222-2222-2222-2222-222222222222</string>` + extra + `</dict>`
}

type fixture struct {
	ctx   context.Context
	store *Store
	eng   *Engine
	enq   *recorder
	obs   *Observer
	rel   *osreleases.Catalog
	ddm   *ddm.Store
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	mc, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mc.Disconnect(context.Background()) })
	db := mc.Database("fleetcore_bp_test")
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Drop(context.Background()) })
	st, err := NewStore(ctx, db, "")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := applicability.NewRegistry(ctx, db, "")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{ctx: ctx, store: st, enq: &recorder{}, rel: &osreleases.Catalog{}, now: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	f.eng = New(st, f.enq, reg, f.rel, testLogger(), Config{})
	f.eng.Now = func() time.Time { return f.now }
	st.Now = func() time.Time { return f.now }
	f.obs = &Observer{Store: st, Now: func() time.Time { return f.now }}
	f.ddm, err = ddm.NewStore(ctx, db, "")
	if err != nil {
		t.Fatal(err)
	}
	f.ddm.Now = func() time.Time { return f.now }
	f.eng.DDM = f.ddm
	return f
}

func (f *fixture) device(id, platform, version string, tags ...string) {
	if err := f.store.UpsertDevice(f.ctx, DeviceUpdate{ID: id, UDID: id, Serial: "S" + id, Platform: platform, Model: platform + "1,1", OSVersion: version}, f.now); err != nil {
		panic(err)
	}
	if len(tags) > 0 {
		if err := f.store.SetDeviceFields(f.ctx, id, bsonDTags(tags), false); err != nil {
			panic(err)
		}
	}
}

// reconcile runs the engine over every due device until none is left.
func (f *fixture) reconcile() int {
	n := 0
	for f.eng.Once(f.ctx) {
		n++
		if n > 1000 {
			panic("runaway")
		}
	}
	return n
}

func (f *fixture) answer(device, uuid, status string) {
	r := mdm.NewRequestWithContext(f.ctx, nil)
	r.EnrollID = &mdm.EnrollID{ID: device}
	if _, err := f.obs.CommandAndReportResults(r, &mdm.CommandResults{CommandUUID: uuid, Status: status}); err != nil {
		panic(err)
	}
}

func (f *fixture) save(b Blueprint) {
	if err := b.Prepare(); err != nil {
		panic(err)
	}
	if _, err := f.store.SaveBlueprint(f.ctx, b, "test", Env{Releases: f.rel}); err != nil {
		panic(err)
	}
	f.eng.Invalidate()
}

func TestRuleMatchAgreesWithMongoFilter(t *testing.T) {
	f := newFixture(t)
	f.device("m1", "macOS", "15.0", "eng")
	f.device("m2", "macOS", "14.6.1", "sales")
	f.device("i1", "iOS", "18.2")
	f.device("i2", "iPadOS", "17.7", "eng", "kiosk")
	if err := f.store.PutGroup(f.ctx, Group{ID: "eng", Name: "Engineering", Rule: &Rule{Field: "tag", Op: "eq", Value: "eng"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.PutGroup(f.ctx, Group{ID: "kiosks", Name: "Kiosks"}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetDeviceFields(f.ctx, "i1", bsonDGroups([]string{"Kiosks"}), false); err != nil {
		t.Fatal(err)
	}
	env, _ := f.eng.Env(f.ctx)
	rules := map[string]Rule{
		"platform":      {Field: "platform", Op: "eq", Value: "macOS"},
		"not mac":       {Not: &Rule{Field: "platform", Op: "eq", Value: "macOS"}},
		"os gte":        {All: []Rule{{Field: "platform", Op: "eq", Value: "macOS"}, {Field: "os_version", Op: "gte", Value: "15.0"}}},
		"os lt 3 part":  {Field: "os_version", Op: "lt", Value: "14.6.2"},
		"tag in":        {Field: "tag", Op: "in", Value: []any{"eng", "kiosk"}},
		"tag nin":       {Field: "tag", Op: "nin", Value: []any{"eng"}},
		"dynamic group": {Field: "group", Op: "eq", Value: "Engineering"},
		"not dyn group": {Field: "group", Op: "ne", Value: "Engineering"},
		"static group":  {Field: "group", Op: "eq", Value: "Kiosks"},
		"any":           {Any: []Rule{{Field: "serial", Op: "eq", Value: "Sm1"}, {Field: "model", Op: "prefix", Value: "iOS"}}},
		"empty":         {},
	}
	for name, r := range rules {
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		x, err := r.Expand(env)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fromMongo, err := f.store.QueryDevices(f.ctx, x, "", 100)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := map[string]bool{}
		for _, d := range fromMongo {
			got[d.ID] = true
		}
		for _, id := range []string{"m1", "m2", "i1", "i2"} {
			d, _ := f.store.GetDevice(f.ctx, id)
			if x.Match(d) != got[id] {
				t.Errorf("%s: device %s: Match says %v, MongoDB says %v", name, id, x.Match(d), got[id])
			}
		}
	}
}

func TestProfileLifecycle(t *testing.T) {
	f := newFixture(t)
	f.device("mac1", "macOS", "15.0", "eng")
	f.device("mac2", "macOS", "15.0")
	wifi := func(note string) []byte {
		return profile("com.example.wifi", payload("com.apple.wifi.managed", `<key>SSID_STR</key><string>`+note+`</string>`))
	}
	f.save(Blueprint{ID: "eng", Enabled: true, Scope: Rule{Field: "tag", Op: "eq", Value: "eng"}, Items: []Item{{Kind: "profile", Payload: wifi("corp")}}})
	f.reconcile()
	got := f.enq.take()
	var installs []sent
	for _, s := range got {
		if s.requestType() == "InstallProfile" {
			installs = append(installs, s)
		}
	}
	if len(installs) != 1 || installs[0].ids[0] != "mac1" {
		t.Fatalf("expected one install for mac1, got %d (%v)", len(installs), got)
	}
	// the device acknowledges: applied; another pass sends nothing
	f.answer("mac1", installs[0].uuid(), "Acknowledged")
	f.eng.Store.Touch(f.ctx, Rule{})
	f.reconcile()
	for _, s := range f.enq.take() {
		if s.requestType() == "InstallProfile" {
			t.Fatal("sent again after it was applied")
		}
	}
	apps, _ := f.store.Applications(f.ctx, "mac1")
	if len(apps) != 1 || apps[0].State != StateApplied {
		t.Fatalf("%+v", apps)
	}

	// a new revision reinstalls
	f.save(Blueprint{ID: "eng", Enabled: true, Scope: Rule{Field: "tag", Op: "eq", Value: "eng"}, Items: []Item{{Kind: "profile", Payload: wifi("corp2")}}})
	f.reconcile()
	again := f.enq.take()
	if len(again) == 0 || again[0].requestType() != "InstallProfile" {
		t.Fatalf("a changed profile was not sent: %v", again)
	}
	f.answer("mac1", again[0].uuid(), "Acknowledged")

	// leaving the scope removes the profile
	if err := f.store.SetDeviceFields(f.ctx, "mac1", bsonDTags(nil), true); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	rm := f.enq.take()
	var removal *sent
	for i := range rm {
		if rm[i].requestType() == "RemoveProfile" {
			removal = &rm[i]
		}
	}
	if removal == nil || removal.param("Identifier") != "com.example.wifi" {
		t.Fatalf("no removal on leaving scope: %v", rm)
	}
	f.answer("mac1", removal.uuid(), "Acknowledged")
	if apps, _ := f.store.Applications(f.ctx, "mac1"); len(apps) != 0 {
		t.Errorf("records left after removal: %+v", apps)
	}

	// a failure is recorded and retried with a backoff
	if err := f.store.SetDeviceFields(f.ctx, "mac1", bsonDTags([]string{"eng"}), true); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	s := f.enq.take()
	if len(s) == 0 {
		t.Fatal("not reinstalled on re-entering")
	}
	f.answer("mac1", s[0].uuid(), "Error")
	apps, _ = f.store.Applications(f.ctx, "mac1")
	if len(apps) != 1 || apps[0].State != StateFailed {
		t.Fatalf("%+v", apps)
	}
	f.reconcile()
	if len(f.enq.take()) != 0 {
		t.Error("retried at once instead of after a backoff")
	}
	f.now = f.now.Add(11 * time.Minute)
	f.eng.Store.Touch(f.ctx, Rule{})
	f.reconcile()
	if len(f.enq.take()) == 0 {
		t.Error("not retried after the backoff")
	}
}

func TestPlatformApplicability(t *testing.T) {
	f := newFixture(t)
	f.device("mac", "macOS", "15.0")
	f.device("phone", "iOS", "18.2")
	chrome := profile("com.example.chrome", payload("com.google.Chrome", `<key>HomepageLocation</key><string>https://example.com</string>`))
	mixed := profile("com.example.mixed",
		payload("com.apple.ManagedClient.preferences", `<key>PayloadContent</key><dict><key>com.apple.dock</key><dict><key>Forced</key><array/></dict></dict>`)+
			payload("com.apple.applicationaccess", `<key>allowCamera</key><true/>`))
	f.save(Blueprint{ID: "all", Enabled: true, Items: []Item{{ID: "chrome", Kind: "profile", Payload: chrome}, {ID: "mixed", Kind: "profile", Payload: mixed}}})
	f.reconcile()
	byDevice := map[string][]string{}
	for _, s := range f.enq.take() {
		if s.requestType() == "InstallProfile" {
			byDevice[s.ids[0]] = append(byDevice[s.ids[0]], s.requestType())
		}
	}
	if len(byDevice["mac"]) != 2 {
		t.Errorf("mac should get both profiles, got %v", byDevice["mac"])
	}
	if len(byDevice["phone"]) != 1 {
		t.Errorf("phone should get only the part that applies (the Chrome profile and the macOS-only managed preferences payload are not for it), got %v", byDevice["phone"])
	}
	apps, _ := f.store.Applications(f.ctx, "phone")
	na := 0
	for _, a := range apps {
		if a.State == StateNA {
			na++
			if !strings.Contains(a.Note, "") {
				t.Errorf("no note: %+v", a)
			}
		}
	}
	if na != 1 {
		t.Errorf("the Chrome profile should be not_applicable on the phone: %+v", apps)
	}
}

func TestStagedRollout(t *testing.T) {
	f := newFixture(t)
	const n = 60
	for i := 0; i < n; i++ {
		f.device(fmt.Sprintf("d%02d", i), "macOS", "15.0")
	}
	f.save(Blueprint{ID: "staged", Enabled: true, Items: []Item{{Kind: "profile", Payload: profile("com.example.p", payload("com.apple.wifi.managed", `<key>SSID_STR</key><string>x</string>`))}},
		Rings: []Ring{{Name: "canary", Percent: 10, AfterSeconds: 0}, {Name: "rest", Percent: 100, AfterSeconds: 3600}}})
	f.reconcile()
	canary := f.enq.take()
	first := 0
	for _, s := range canary {
		if s.requestType() == "InstallProfile" {
			first++
			f.answer(s.ids[0], s.uuid(), "Acknowledged")
		}
	}
	if first == 0 || first > n/2 {
		t.Fatalf("the canary ring should be a small part of %d devices, got %d", n, first)
	}
	f.now = f.now.Add(61 * time.Minute)
	f.eng.Store.Touch(f.ctx, Rule{})
	f.reconcile()
	rest := f.enq.installs()
	if first+rest != n {
		t.Errorf("canary %d + rest %d != %d", first, rest, n)
	}
}

func TestOutOfDateRule(t *testing.T) {
	f := newFixture(t)
	f.rel.Replace([]osreleases.Release{
		{Platform: "macOS", Version: "27.0.1", Major: 27, Num: 27000001},
		{Platform: "macOS", Version: "26.6.2", Major: 26, Num: 26006002},
	})
	f.device("old", "macOS", "26.5")
	f.device("newest-of-26", "macOS", "26.6.2")
	f.device("current", "macOS", "27.0.1")
	f.device("ancient", "macOS", "14.1")
	env, _ := f.eng.Env(f.ctx)
	ids := func(r Rule) string {
		x, err := r.Expand(env)
		if err != nil {
			t.Fatal(err)
		}
		ds, _ := f.store.QueryDevices(f.ctx, x, "", 100)
		var out []string
		for _, d := range ds {
			out = append(out, d.ID)
			if !x.Match(&d) {
				t.Errorf("Match disagrees for %s", d.ID)
			}
		}
		return strings.Join(out, ",")
	}
	if got := ids(Rule{Field: "os_version", Op: "lt", Value: "latest"}); got != "ancient,newest-of-26,old" {
		t.Errorf("behind the newest release: %s", got)
	}
	if got := ids(Rule{Field: "os_version", Op: "lt", Value: "latest-in-major"}); got != "old" {
		t.Errorf("behind in own major (a Mac that stays on 26 is current at 26.6.2): %s", got)
	}
}

func TestClaimIsExclusive(t *testing.T) {
	f := newFixture(t)
	f.device("a", "macOS", "15.0")
	d1, _ := f.store.Claim(f.ctx, f.now, time.Minute)
	d2, _ := f.store.Claim(f.ctx, f.now, time.Minute)
	if d1 == nil || d2 != nil {
		t.Fatalf("a leased device was claimed twice: %v %v", d1, d2)
	}
	if d3, _ := f.store.Claim(f.ctx, f.now.Add(2*time.Minute), time.Minute); d3 == nil {
		t.Error("an expired lease was not reclaimed")
	}
}
