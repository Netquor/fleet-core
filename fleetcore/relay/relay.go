// Package relay turns changes in the database into events on a message bus. It reads one MongoDB change stream for the tenant, maps the changes that matter
// (an enrollment appears or checks out, a command is queued or answered, a blueprint item changes state, a blueprint is saved, Apple assigns a device) to small events,
// and publishes them to NATS and/or a signed webhook.
//
// Events carry identifiers and states, never profile bodies, results, tokens or any value that is sealed at rest: a consumer that needs more asks the management API,
// which is authenticated. Delivery is at least once: the stream's resume token is saved after each batch, so a restart repeats at most the last batch, and every event has
// a stable id (the change's own) for consumers to ignore repeats. Only one process of a tenant relays at a time (a lease in the database), and another takes over when it stops.
package relay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/micromdm/nanolib/log"
	"github.com/nats-io/nats.go"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Event is what is published. Its JSON is the envelope the rest of the platform uses: {type, key, data, at, origin} plus the id.
type Event struct {
	ID     string         `json:"id"`
	Type   string         `json:"type"`
	Key    string         `json:"key"`
	Data   map[string]any `json:"data,omitempty"`
	At     time.Time      `json:"at"`
	Origin string         `json:"origin"`
}

// Publisher sends events somewhere. Publish returning an error makes the relay retry the batch.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}

// NATS publishes to subjects "<prefix>.<type>.<key>" (key has dots and spaces replaced), through JetStream when a stream is named, otherwise core pub/sub.
type NATS struct {
	Conn   *nats.Conn
	Prefix string // default "fleetcore.events"
	Stream bool   // use JetStream publish with an ack (the stream must exist and cover the subjects)
}

func subjectToken(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', ' ', '*', '>', '\x1f':
			return '_'
		}
		return r
	}, s)
}

// Publish implements Publisher.
func (n *NATS) Publish(ctx context.Context, e Event) error {
	prefix := n.Prefix
	if prefix == "" {
		prefix = "fleetcore.events"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, _ := json.Marshal(e)
	subj := prefix + "." + e.Type + "." + subjectToken(e.Key)
	if n.Stream {
		js, err := n.Conn.JetStream()
		if err != nil {
			return err
		}
		_, err = js.Publish(subj, b, nats.MsgId(e.ID), nats.Context(ctx))
		return err
	}
	if err := n.Conn.Publish(subj, b); err != nil {
		return err
	}
	return n.Conn.FlushWithContext(ctx)
}

// Webhook posts each event as JSON with an HMAC-SHA256 signature of the body in X-Fleetcore-Signature (hex), the event id in X-Fleetcore-Event, and retries a failed delivery.
type Webhook struct {
	URL    string
	Secret []byte
	Client *http.Client
}

// Publish implements Publisher.
func (w *Webhook) Publish(ctx context.Context, e Event) error {
	body, _ := json.Marshal(e)
	c := w.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fleetcore-Event", e.ID)
	if len(w.Secret) > 0 {
		m := hmac.New(sha256.New, w.Secret)
		m.Write(body)
		req.Header.Set("X-Fleetcore-Signature", hex.EncodeToString(m.Sum(nil)))
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the webhook answered %d", resp.StatusCode)
	}
	return nil
}

// Multi publishes to every sink; it fails if any does (the batch is then repeated, which at-least-once delivery allows).
type Multi []Publisher

// Publish implements Publisher.
func (m Multi) Publish(ctx context.Context, e Event) error {
	var errs []error
	for _, p := range m {
		if err := p.Publish(ctx, e); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Relay watches the database and publishes.
type Relay struct {
	DB     *mongo.Database
	Tenant string
	Out    Publisher
	Logger log.Logger
	// Origin is put on every event (default "fleetcore" or "fleetcore:<tenant>").
	Origin string
	// LeaseFor is how long a holder owns the relay without renewing (default 30 seconds).
	LeaseFor time.Duration
	// Holder names this process in the lease.
	Holder string
	Now    func() time.Time

	mu sync.Mutex
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func (r *Relay) key(parts ...string) string {
	k := strings.Join(parts, "\x1f")
	if r.Tenant == "" {
		return k
	}
	return r.Tenant + "\x1f" + k
}

func (r *Relay) origin() string {
	if r.Origin != "" {
		return r.Origin
	}
	if r.Tenant != "" {
		return "fleetcore:" + r.Tenant
	}
	return "fleetcore"
}

// changed is one change stream event, as much of it as the mapping needs.
type changed struct {
	ID        bson.Raw `bson:"_id"`
	Operation string   `bson:"operationType"`
	NS        struct {
		Coll string `bson:"coll"`
	} `bson:"ns"`
	DocumentKey struct {
		ID any `bson:"_id"`
	} `bson:"documentKey"`
	Full        bson.M `bson:"fullDocument"`
	Description struct {
		Updated bson.M   `bson:"updatedFields"`
		Removed []string `bson:"removedFields"`
	} `bson:"updateDescription"`
	At bson.Timestamp `bson:"clusterTime"`
}

func str(m bson.M, k string) string {
	s, _ := m[k].(string)
	return s
}

// mine reports whether a change belongs to this relay's tenant.
func (r *Relay) mine(c *changed) bool {
	if r.Tenant == "" {
		return true
	}
	if t, ok := c.Full["t"].(string); ok {
		return t == r.Tenant
	}
	if id, ok := c.DocumentKey.ID.(string); ok {
		return strings.HasPrefix(id, r.Tenant+"\x1f")
	}
	return false
}

// mapChange turns a change into an event, or nil when it is not one worth publishing. Only identifiers and states leave the database here.
func (r *Relay) mapChange(c *changed) *Event {
	ev := func(typ, key string, data map[string]any) *Event {
		return &Event{Type: typ, Key: key, Data: data, At: time.Unix(int64(c.At.T), 0).UTC(), Origin: r.origin()}
	}
	insert := c.Operation == "insert"
	update := c.Operation == "update" || c.Operation == "replace"
	switch c.NS.Coll {
	case "enrollments":
		id := str(c.Full, "id")
		if id == "" {
			return nil
		}
		if insert {
			return ev("enrollment.created", id, map[string]any{"enrollment": id, "type": str(c.Full, "type")})
		}
		if update {
			if en, ok := c.Description.Updated["enabled"].(bool); ok && !en {
				return ev("enrollment.checkout", id, map[string]any{"enrollment": id})
			}
		}
	case "enrollment_queue":
		id, uuid := str(c.Full, "id"), str(c.Full, "command_uuid")
		if id == "" {
			return nil
		}
		if insert {
			return ev("command.queued", id, map[string]any{"enrollment": id, "command_uuid": uuid})
		}
		if st, ok := c.Description.Updated["status"].(string); ok && update && st != "" {
			return ev("command.result", id, map[string]any{"enrollment": id, "command_uuid": uuid, "status": st})
		}
	case "bp_applied":
		if insert || update {
			dev := str(c.Full, "device")
			if _, changedState := c.Description.Updated["state"]; dev == "" || (update && !changedState) {
				return nil
			}
			return ev("application.state", dev, map[string]any{"device": dev, "blueprint": str(c.Full, "blueprint"), "item": str(c.Full, "item"), "state": str(c.Full, "state")})
		}
	case "bp_blueprints":
		if insert || update || c.Operation == "delete" {
			id := str(c.Full, "id")
			if id == "" {
				if k, ok := c.DocumentKey.ID.(string); ok {
					id = k[strings.LastIndex(k, "\x1f")+1:]
				}
			}
			typ := "blueprint.saved"
			if c.Operation == "delete" {
				typ = "blueprint.deleted"
			}
			return ev(typ, id, map[string]any{"blueprint": id})
		}
	case "dep_devices":
		if insert {
			serial := str(c.Full, "serial_number")
			if serial == "" {
				serial = str(c.Full, "serial")
			}
			return ev("dep.device.assigned", serial, map[string]any{"serial": serial})
		}
	}
	return nil
}

// eventID is the same for the same change however many times it is read.
func eventID(c *changed) string {
	h := sha256.Sum256(c.ID)
	return hex.EncodeToString(h[:12])
}

// lease takes or renews the relay lease; false when another process holds it.
func (r *Relay) lease(ctx context.Context) (bool, error) {
	d := r.LeaseFor
	if d == 0 {
		d = 30 * time.Second
	}
	now := r.now()
	id := r.key("lease")
	_, err := r.DB.Collection("relay_state").UpdateOne(ctx, // tenant-ok: the _id is tenant-prefixed by r.key
		bson.D{{Key: "_id", Value: id}, {Key: "$or", Value: bson.A{bson.D{{Key: "holder", Value: r.Holder}}, bson.D{{Key: "expires_at", Value: bson.D{{Key: "$lt", Value: now}}}}}}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "holder", Value: r.Holder}, {Key: "expires_at", Value: now.Add(d)}}}}, options.UpdateOne().SetUpsert(true))
	if mongo.IsDuplicateKeyError(err) {
		return false, nil
	}
	return err == nil, err
}

func (r *Relay) saveToken(ctx context.Context, tok bson.Raw) error {
	_, err := r.DB.Collection("relay_state").UpdateOne(ctx, bson.D{{Key: "_id", Value: r.key("resume")}}, // tenant-ok: the _id is tenant-prefixed by r.key
		bson.D{{Key: "$set", Value: bson.D{{Key: "token", Value: tok}, {Key: "at", Value: r.now()}}}}, options.UpdateOne().SetUpsert(true))
	return err
}

func (r *Relay) loadToken(ctx context.Context) bson.Raw {
	var doc struct {
		Token bson.Raw `bson:"token"`
	}
	if err := r.DB.Collection("relay_state").FindOne(ctx, bson.D{{Key: "_id", Value: r.key("resume")}}).Decode(&doc); err != nil {
		return nil
	}
	return doc.Token
}

// Run relays until the context ends. It waits while another process holds the lease, and starts from where the last holder stopped (or from now, the first time).
func (r *Relay) Run(ctx context.Context) error {
	if r.Holder == "" {
		r.Holder = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	for ctx.Err() == nil {
		held, err := r.lease(ctx)
		if err != nil {
			r.logf("lease: %v", err)
		}
		if held {
			if err := r.watch(ctx); err != nil && ctx.Err() == nil {
				r.logf("change stream: %v", err)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	return ctx.Err()
}

func (r *Relay) logf(format string, a ...any) {
	if r.Logger != nil {
		r.Logger.Info("msg", fmt.Sprintf(format, a...))
	}
}

func (r *Relay) watch(ctx context.Context) error {
	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
	if tok := r.loadToken(ctx); tok != nil {
		opts.SetResumeAfter(tok)
	}
	pipeline := mongo.Pipeline{{{Key: "$match", Value: bson.D{
		{Key: "ns.coll", Value: bson.D{{Key: "$in", Value: bson.A{"enrollments", "enrollment_queue", "bp_applied", "bp_blueprints", "dep_devices"}}}},
		{Key: "operationType", Value: bson.D{{Key: "$in", Value: bson.A{"insert", "update", "replace", "delete"}}}},
	}}}}
	cs, err := r.DB.Watch(ctx, pipeline, opts)
	if err != nil {
		return err
	}
	defer cs.Close(context.Background())
	renew := time.NewTicker(10 * time.Second)
	defer renew.Stop()
	go func() { // renew the lease while the stream blocks waiting for changes
		for {
			select {
			case <-ctx.Done():
				return
			case <-renew.C:
				if held, _ := r.lease(ctx); !held {
					cs.Close(context.Background()) // another process took over
					return
				}
			}
		}
	}()
	for cs.Next(ctx) {
		var c changed
		if err := cs.Decode(&c); err != nil {
			r.logf("decode: %v", err)
			continue
		}
		c.ID = cs.ResumeToken()
		if r.mine(&c) {
			if e := r.mapChange(&c); e != nil {
				e.ID = eventID(&c)
				if err := r.publish(ctx, *e); err != nil {
					return err
				}
			}
		}
		if err := r.saveToken(ctx, cs.ResumeToken()); err != nil {
			return err
		}
	}
	return cs.Err()
}

// publish retries a failed delivery with a growing pause, so a bus that is briefly away delays events and does not lose them.
func (r *Relay) publish(ctx context.Context, e Event) error {
	pause := 500 * time.Millisecond
	for {
		err := r.Out.Publish(ctx, e)
		if err == nil {
			return nil
		}
		r.logf("publish %s: %v", e.Type, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pause):
		}
		if pause < 30*time.Second {
			pause *= 2
		}
	}
}
