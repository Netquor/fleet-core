package relay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/seal"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestMatchAndValidate(t *testing.T) {
	if !Match(nil, "command.result") || !Match([]string{"*"}, "x") || !Match([]string{"command.*"}, "command.result") || Match([]string{"command.*"}, "device.renamed") || !Match([]string{"device.renamed", "command.queued"}, "command.queued") {
		t.Error("pattern matching")
	}
	if ValidPatterns([]string{"device.*", "command.result"}) != "" || ValidPatterns([]string{"nonsense.*"}) != "nonsense.*" {
		t.Error("validation")
	}
	for _, c := range Catalog {
		if c.Description == "" || c.Key == "" {
			t.Errorf("catalog entry %s is incomplete", c.Type)
		}
	}
}

func TestMoreEventsFromTheDatabase(t *testing.T) {
	db := testDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := NewStore(ctx, db, "acme", seal.Plain().For("acme"))
	if err != nil {
		t.Fatal(err)
	}
	out := &collector{}
	r := &Relay{DB: db, Tenant: "acme", Store: st, Sinks: []Sink{{Name: "all", Out: out}}, Holder: "a"}
	go r.Run(ctx)
	time.Sleep(2 * time.Second)
	dev := db.Collection("bp_devices")
	_, _ = dev.InsertOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fD1"}, {Key: "t", Value: "acme"}, {Key: "id", Value: "D1"}, {Key: "serial", Value: "C02X"}, {Key: "platform", Value: "macOS"}, {Key: "model", Value: "Mac1,1"}, {Key: "active", Value: true}})
	_, _ = dev.UpdateOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fD1"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "os_version", Value: "15.1"}, {Key: "name", Value: "kim-mbp"}}}})
	_, _ = dev.UpdateOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fD1"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "groups", Value: bson.A{"eng"}}, {Key: "supervised", Value: true}}}})
	_, _ = dev.UpdateOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fD1"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "active", Value: false}}}})
	_, _ = db.Collection("bp_groups").InsertOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fg1"}, {Key: "t", Value: "acme"}, {Key: "id", Value: "g1"}, {Key: "name", Value: "G"}})
	_, _ = db.Collection("vault_audit").InsertOne(ctx, bson.D{{Key: "t", Value: "acme"}, {Key: "device", Value: "D1"}, {Key: "kind", Value: "filevault"}, {Key: "action", Value: "reveal"}, {Key: "who", Value: "alice"}, {Key: "reason", Value: "locked out"}, {Key: "value", Value: "SECRETVALUE"}})
	_, _ = db.Collection("dep_devices").InsertOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fC02X"}, {Key: "t", Value: "acme"}, {Key: "serial_number", Value: "C02X"}})
	_, _ = db.Collection("dep_devices").DeleteOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fC02X"}})
	_, _ = db.Collection("os_releases").InsertOne(ctx, bson.D{{Key: "_id", Value: "macOS|15.2"}, {Key: "platform", Value: "macOS"}, {Key: "version", Value: "15.2"}})

	got := out.wait(t, 11)
	var types []string
	for _, e := range got {
		types = append(types, e.Type)
	}
	want := []string{"device.enrolled", "device.os_changed", "device.renamed", "device.supervision_changed", "device.membership_changed", "device.deactivated", "group.saved", "vault.access", "dep.device.assigned", "dep.device.removed", "os.release.published"}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Errorf("types\n got %v\nwant %v", types, want)
	}
	if b, _ := json.Marshal(got); strings.Contains(string(b), "SECRETVALUE") {
		t.Error("a stored secret left in an event")
	}
	// they are in the log, in order, with sequence numbers, and each has a distinct id
	logged, err := st.Events(ctx, 0, nil, "", 100)
	if err != nil || len(logged) != 11 {
		t.Fatalf("log: %d %v", len(logged), err)
	}
	ids := map[string]bool{}
	for i, e := range logged {
		if e.Seq != int64(i+1) || ids[e.ID] {
			t.Errorf("event %d: seq %d id %s", i, e.Seq, e.ID)
		}
		ids[e.ID] = true
	}
	dev2, _ := st.Events(ctx, 0, []string{"device.*"}, "", 100)
	if len(dev2) != 6 {
		t.Errorf("device.* selected %d", len(dev2))
	}
	byKey, _ := st.Events(ctx, 0, nil, "D1", 100)
	if len(byKey) != 7 {
		t.Errorf("key filter selected %d", len(byKey))
	}
}

type receiver struct {
	mu     sync.Mutex
	got    []Event
	fail   bool
	secret string
	badSig int
	status int
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	m := hmac.New(sha256.New, []byte(rc.secret))
	m.Write([]byte(r.Header.Get("X-Fleetcore-Timestamp") + "." + string(b)))
	if r.Header.Get("X-Fleetcore-Signature") != "sha256="+hex.EncodeToString(m.Sum(nil)) {
		rc.badSig++
	}
	if rc.fail {
		w.WriteHeader(503)
		return
	}
	var e Event
	_ = json.Unmarshal(b, &e)
	rc.got = append(rc.got, e)
}

func (rc *receiver) count() int { rc.mu.Lock(); defer rc.mu.Unlock(); return len(rc.got) }

func TestSubscriptionsDeliverInOrderRetryPauseAndReplay(t *testing.T) {
	db := testDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := NewStore(ctx, db, "", seal.Plain().For("x"))
	if err != nil {
		t.Fatal(err)
	}
	rc := &receiver{}
	ts := httptest.NewServer(rc)
	defer ts.Close()
	rel := &Relay{DB: db, Store: st, Holder: "d"}
	disp := &Dispatcher{Relay: rel, Store: st, Interval: 100 * time.Millisecond, Client: SafeClient(true)}
	api := &API{Store: st, Dispatcher: disp, AllowPrivate: true}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	call := func(method, path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		b, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(b, &m)
		return resp.StatusCode, m
	}
	// some history first, which a new subscription does not get unless it asks
	for i := 1; i <= 3; i++ {
		_, _, _ = st.Append(ctx, Event{ID: fmt.Sprintf("old%d", i), Type: "device.renamed", Key: "D", At: time.Now(), Origin: "t"})
	}
	code, sub := call("POST", "/event-subscriptions", fmt.Sprintf(`{"name":"hook","url":%q,"types":["command.*"]}`, ts.URL))
	if code != 201 || sub["secret"] == nil || !strings.HasPrefix(sub["secret"].(string), "whsec_") {
		t.Fatalf("create: %d %v", code, sub)
	}
	id := sub["id"].(string)
	rc.secret = sub["secret"].(string)
	if _, again := call("GET", "/event-subscriptions/"+id, ""); again["secret"] != nil {
		t.Error("the secret can be read again")
	}
	if code, _ := call("POST", "/event-subscriptions", `{"url":"http://example.com/x"}`); code != 201 {
		// AllowPrivate is on in this test, which also allows http
		t.Errorf("http with AllowPrivate: %d", code)
	}
	if code, _ := call("POST", "/event-subscriptions", `{"url":"https://x","types":["bogus.*"]}`); code != 422 {
		t.Errorf("a pattern that matches nothing: %d", code)
	}
	go disp.Run(ctx)

	for i := 1; i <= 3; i++ {
		_, _, _ = st.Append(ctx, Event{ID: fmt.Sprintf("q%d", i), Type: "command.queued", Key: "E", At: time.Now(), Origin: "t"})
		_, _, _ = st.Append(ctx, Event{ID: fmt.Sprintf("r%d", i), Type: "device.renamed", Key: "E", At: time.Now(), Origin: "t"})
	}
	eventually(t, "three command events", func() bool { return rc.count() == 3 })
	rc.mu.Lock()
	for i := 1; i < 3; i++ {
		if rc.got[i].Seq <= rc.got[i-1].Seq || rc.got[i].Type != "command.queued" {
			t.Errorf("order or filter: %+v", rc.got)
		}
	}
	if rc.badSig != 0 {
		t.Error("a delivery was signed wrongly")
	}
	rc.mu.Unlock()

	// the endpoint fails: the subscription backs off, then pauses itself after enough failures; nothing is lost
	rc.mu.Lock()
	rc.fail = true
	rc.mu.Unlock()
	_, _, _ = st.Append(ctx, Event{ID: "q4", Type: "command.queued", Key: "E", At: time.Now(), Origin: "t"})
	eventually(t, "a failure to be recorded", func() bool {
		_, s := call("GET", "/event-subscriptions/"+id, "")
		if s["state"] != "failing" {
			t.Logf("subscription now: %v", s)
		}
		return s["state"] == "failing"
	})
	if _, d := call("GET", "/event-subscriptions/"+id+"/deliveries", ""); len(d["deliveries"].([]any)) < 4 {
		t.Errorf("deliveries %v", d)
	}
	// pause it by hand the way the dispatcher would, then resume
	_ = st.UpdateSubscription(ctx, id, bson.D{{Key: "paused_reason", Value: "test"}})
	if _, s := call("GET", "/event-subscriptions/"+id, ""); s["state"] != "paused" {
		t.Errorf("state %v", s["state"])
	}
	rc.mu.Lock()
	rc.fail = false
	rc.mu.Unlock()
	if code, _ := call("POST", "/event-subscriptions/"+id+"/resume", ""); code != 204 {
		t.Errorf("resume: %d", code)
	}
	eventually(t, "the held event after resume", func() bool { return rc.count() == 4 })

	// replay from the start delivers the command events again
	if code, _ := call("POST", "/event-subscriptions/"+id+"/replay", `{"from_seq":0}`); code != 202 {
		t.Errorf("replay: %d", code)
	}
	eventually(t, "the replay", func() bool { return rc.count() == 8 })

	// test event
	if code, r := call("POST", "/event-subscriptions/"+id+"/test", ""); code != 200 || r["ok"] != true {
		t.Errorf("test: %d %v", code, r)
	}
	// delete
	if code, _ := call("DELETE", "/event-subscriptions/"+id, ""); code != 204 {
		t.Errorf("delete: %d", code)
	}
	if code, _ := call("GET", "/event-subscriptions/"+id, ""); code != 404 {
		t.Errorf("deleted subscription: %d", code)
	}
	// the log API
	code, evs := call("GET", "/events?types=command.*&limit=2", "")
	if code != 200 || len(evs["events"].([]any)) != 2 || evs["next"].(float64) == 0 {
		t.Errorf("events: %d %v", code, evs)
	}
	if code, _ := call("GET", "/events?types=nope", ""); code != 422 {
		t.Errorf("bad types: %d", code)
	}
}

func TestStreamAndURLSafety(t *testing.T) {
	db := testDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, _ := NewStore(ctx, db, "", seal.Plain().For("x"))
	api := &API{Store: st}
	for _, bad := range []string{"http://example.com/x", "https://user:pw@example.com/", "https://127.0.0.1/hook", "https://localhost/hook", "ftp://x/y", "not a url"} {
		if err := api.checkURL(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// the client itself refuses a private address even if the check was dodged
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer loop.Close()
	if _, err := SafeClient(false).Get(loop.URL); err == nil {
		t.Error("the safe client reached a loopback address")
	}
	if resp, err := SafeClient(true).Get(loop.URL); err != nil {
		t.Errorf("the permissive client: %v", err)
	} else {
		resp.Body.Close()
	}

	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	_, _, _ = st.Append(ctx, Event{ID: "s0", Type: "device.renamed", Key: "D", At: time.Now(), Origin: "t"})
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/events/stream?after=0&types=device.*", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "event: device.renamed") || !strings.Contains(string(buf[:n]), "id: 1") {
		t.Errorf("stream: %q", buf[:n])
	}
}
