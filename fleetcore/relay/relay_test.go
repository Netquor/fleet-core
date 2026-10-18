package relay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func natsServer(t *testing.T) string {
	bin, err := exec.LookPath("nats-server")
	if err != nil {
		t.Skip("nats-server is not installed")
	}
	port := freePort(t)
	cmd := exec.Command(bin, "-a", "127.0.0.1", "-p", strconv.Itoa(port))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	url := "nats://127.0.0.1:" + strconv.Itoa(port)
	for i := 0; i < 50; i++ {
		if c, err := nats.Connect(url); err == nil {
			c.Close()
			return url
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("nats-server did not start")
	return ""
}

func testDB(t *testing.T) *mongo.Database {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	mc, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	db := mc.Database("fleetcore_relay_test")
	_ = db.Drop(context.Background())
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = mc.Disconnect(context.Background()) })
	return db
}

type collector struct {
	mu     sync.Mutex
	events []Event
}

func (c *collector) Publish(_ context.Context, e Event) error {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
	return nil
}

func (c *collector) wait(t *testing.T, n int) []Event {
	for i := 0; i < 100; i++ {
		c.mu.Lock()
		if len(c.events) >= n {
			out := append([]Event(nil), c.events...)
			c.mu.Unlock()
			return out
		}
		c.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("wanted %d events, got %d: %+v", n, len(c.events), c.events)
	return nil
}

func TestRelayPublishesWhatMatters(t *testing.T) {
	db := testDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &collector{}
	r := &Relay{DB: db, Tenant: "acme", Sinks: []Sink{{Name: "test", Out: out}}, Holder: "a"}
	go r.Run(ctx)
	time.Sleep(2 * time.Second)

	enr, queue, applied := db.Collection("enrollments"), db.Collection("enrollment_queue"), db.Collection("bp_applied")
	_, _ = enr.InsertOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fE1"}, {Key: "t", Value: "acme"}, {Key: "id", Value: "E1"}, {Key: "type", Value: "Device"}, {Key: "token", Value: "SECRET"}})
	_, _ = enr.InsertOne(ctx, bson.D{{Key: "_id", Value: "other\x1fE9"}, {Key: "t", Value: "other"}, {Key: "id", Value: "E9"}, {Key: "type", Value: "Device"}}) // another tenant: not relayed
	_, _ = queue.InsertOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fq1"}, {Key: "t", Value: "acme"}, {Key: "id", Value: "E1"}, {Key: "command_uuid", Value: "C1"}, {Key: "command", Value: "SECRET PROFILE"}})
	_, _ = queue.UpdateOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fq1"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "status", Value: "Acknowledged"}, {Key: "result", Value: "SECRET RESULT"}}}})
	_, _ = applied.InsertOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fa1"}, {Key: "t", Value: "acme"}, {Key: "device", Value: "E1"}, {Key: "blueprint", Value: "wifi"}, {Key: "item", Value: "i1"}, {Key: "state", Value: "pending"}})
	_, _ = applied.UpdateOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fa1"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "state", Value: "applied"}}}})
	_, _ = enr.UpdateOne(ctx, bson.D{{Key: "_id", Value: "acme\x1fE1"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "enabled", Value: false}}}})

	got := out.wait(t, 6)
	types := []string{}
	for _, e := range got {
		types = append(types, e.Type)
		if e.ID == "" || e.Origin != "fleetcore:acme" || e.Key == "" {
			t.Errorf("event %+v", e)
		}
		b, _ := json.Marshal(e)
		if string(b) != "" && (strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "E9")) {
			t.Errorf("a secret or another tenant's data left in %s", b)
		}
	}
	want := []string{"enrollment.created", "command.queued", "command.result", "application.state", "application.state", "enrollment.checkout"}
	if len(types) != len(want) {
		t.Fatalf("types %v", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Errorf("event %d: %s, want %s (all: %v)", i, types[i], want[i], types)
		}
	}
	if got[2].Data["status"] != "Acknowledged" || got[4].Data["state"] != "applied" {
		t.Errorf("data %+v %+v", got[2].Data, got[4].Data)
	}
}

func TestRelayResumesAndOnlyOneHoldsTheLease(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	enr := db.Collection("enrollments")
	first := &collector{}
	c1, cancel1 := context.WithCancel(ctx)
	r1 := &Relay{DB: db, Sinks: []Sink{{Name: "test", Out: first}}, Holder: "one", LeaseFor: 3 * time.Second}
	done := make(chan struct{})
	go func() { r1.Run(c1); close(done) }()
	time.Sleep(2 * time.Second)

	// a second process does not relay while the first holds the lease
	second := &collector{}
	c2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	go (&Relay{DB: db, Sinks: []Sink{{Name: "test", Out: second}}, Holder: "two", LeaseFor: 3 * time.Second}).Run(c2)

	_, _ = enr.InsertOne(ctx, bson.D{{Key: "_id", Value: "E1"}, {Key: "id", Value: "E1"}, {Key: "type", Value: "Device"}})
	first.wait(t, 1)
	time.Sleep(time.Second)
	if n := len(second.events); n != 0 {
		t.Errorf("the second process relayed %d events while the first held the lease", n)
	}

	// the first stops; events that happen meanwhile are published by whoever takes over, from where the first left off
	cancel1()
	<-done
	_, _ = enr.InsertOne(ctx, bson.D{{Key: "_id", Value: "E2"}, {Key: "id", Value: "E2"}, {Key: "type", Value: "Device"}})
	got := second.wait(t, 1)
	if got[0].Key != "E2" {
		t.Errorf("the takeover repeated or skipped: %+v", got)
	}
}

func TestNATSAndWebhookSinks(t *testing.T) {
	url := natsServer(t)
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	msgs := make(chan *nats.Msg, 4)
	if _, err := nc.ChanSubscribe("nq.events.>", msgs); err != nil {
		t.Fatal(err)
	}
	e := Event{ID: "x1", Type: "command.result", Key: "UDID.1:user", Data: map[string]any{"status": "Acknowledged"}, At: time.Now(), Origin: "fleetcore"}
	if err := (&NATS{Conn: nc, Prefix: "nq.events"}).Publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-msgs:
		var back Event
		_ = json.Unmarshal(m.Data, &back)
		if m.Subject != "nq.events.command.result.UDID_1:user" || back.ID != "x1" {
			t.Errorf("%s %+v", m.Subject, back)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing arrived on NATS")
	}

	var gotSig, gotBody, gotTS string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSig, gotBody, gotTS = r.Header.Get("X-Fleetcore-Signature"), string(b), r.Header.Get("X-Fleetcore-Timestamp")
	}))
	defer ts.Close()
	if err := (&Webhook{URL: ts.URL, Secret: []byte("k")}).Publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, []byte("k"))
	m.Write([]byte(gotTS + "." + gotBody))
	if gotSig != "sha256="+hex.EncodeToString(m.Sum(nil)) {
		t.Error("the signature does not match the timestamp and body")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	if err := (&Webhook{URL: bad.URL}).Publish(context.Background(), e); err == nil {
		t.Error("a failed delivery was reported as sent")
	}
}
