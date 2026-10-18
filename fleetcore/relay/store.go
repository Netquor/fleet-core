package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/seal"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Retention is how long events stay in the log for replay and for subscriptions that are behind.
const Retention = 7 * 24 * time.Hour

// Store keeps the event log, the subscriptions and their recent deliveries. With a tenant, tenants share the collections.
type Store struct {
	db  *mongo.Database
	tid string
	// Sealer seals subscription secrets at rest.
	Sealer seal.Interface
	Now    func() time.Time
}

// NewStore returns the store and makes its indexes (events and delivery records expire on their own).
func NewStore(ctx context.Context, db *mongo.Database, tenant string, sealer seal.Interface) (*Store, error) {
	s := &Store{db: db, tid: tenant, Sealer: sealer}
	lead := func(k bson.D) bson.D {
		if tenant == "" {
			return k
		}
		return append(bson.D{{Key: "t", Value: 1}}, k...)
	}
	idx := func(coll string, m mongo.IndexModel) error {
		_, err := db.Collection(coll).Indexes().CreateOne(ctx, m)
		return err
	}
	for _, err := range []error{
		idx("relay_events", mongo.IndexModel{Keys: lead(bson.D{{Key: "seq", Value: 1}})}),
		idx("relay_events", mongo.IndexModel{Keys: bson.D{{Key: "at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(int32(Retention.Seconds()))}),
		idx("relay_deliveries", mongo.IndexModel{Keys: lead(bson.D{{Key: "subscription", Value: 1}, {Key: "at", Value: -1}})}),
		idx("relay_deliveries", mongo.IndexModel{Keys: bson.D{{Key: "at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(3 * 24 * 3600)}),
	} {
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Store) key(parts ...string) string {
	k := strings.Join(parts, "\x1f")
	if s.tid == "" {
		return k
	}
	return s.tid + "\x1f" + k
}

func (s *Store) stamp(d bson.D) bson.D {
	if s.tid == "" {
		return d
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, d...)
}

func (s *Store) scope(f bson.D) bson.D {
	if s.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, f...)
}

// Append writes an event to the log and gives it the next sequence number. An event with the same id is written once: stored is false when it was already there.
func (s *Store) Append(ctx context.Context, e Event) (Event, bool, error) {
	var ctr struct {
		N int64 `bson:"n"`
	}
	err := s.db.Collection("relay_state").FindOneAndUpdate(ctx, bson.D{{Key: "_id", Value: s.key("seq")}}, // tenant-ok: the _id is tenant-prefixed by s.key
		bson.D{{Key: "$inc", Value: bson.D{{Key: "n", Value: 1}}}}, options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)).Decode(&ctr)
	if err != nil {
		return e, false, err
	}
	e.Seq = ctr.N
	doc := s.stamp(bson.D{{Key: "_id", Value: s.key("e", e.ID)}, {Key: "seq", Value: e.Seq}, {Key: "id", Value: e.ID}, {Key: "type", Value: e.Type}, {Key: "key", Value: e.Key}, {Key: "data", Value: e.Data}, {Key: "at", Value: e.At}, {Key: "origin", Value: e.Origin}})
	if _, err := s.db.Collection("relay_events").InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			var have struct {
				Seq int64 `bson:"seq"`
			}
			if s.db.Collection("relay_events").FindOne(ctx, bson.D{{Key: "_id", Value: s.key("e", e.ID)}}).Decode(&have) == nil {
				e.Seq = have.Seq
			}
			return e, false, nil
		}
		return e, false, err
	}
	return e, true, nil
}

// Events returns events with a sequence number above after, oldest first, optionally limited to types (patterns) and a key.
func (s *Store) Events(ctx context.Context, after int64, types []string, key string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	f := bson.D{{Key: "seq", Value: bson.D{{Key: "$gt", Value: after}}}}
	if key != "" {
		f = append(f, bson.E{Key: "key", Value: key})
	}
	if len(types) > 0 {
		var ors bson.A
		for _, p := range types {
			switch {
			case p == "*":
				ors = nil
				goto done
			case strings.HasSuffix(p, ".*"):
				ors = append(ors, bson.D{{Key: "type", Value: bson.D{{Key: "$regex", Value: "^" + regexQuote(strings.TrimSuffix(p, "*"))}}}})
			default:
				ors = append(ors, bson.D{{Key: "type", Value: p}})
			}
		}
	done:
		if len(ors) > 0 {
			f = append(f, bson.E{Key: "$or", Value: ors})
		}
	}
	cur, err := s.db.Collection("relay_events").Find(ctx, s.scope(f), options.Find().SetSort(bson.D{{Key: "seq", Value: 1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	var docs []struct {
		Seq    int64          `bson:"seq"`
		ID     string         `bson:"id"`
		Type   string         `bson:"type"`
		Key    string         `bson:"key"`
		Data   map[string]any `bson:"data"`
		At     time.Time      `bson:"at"`
		Origin string         `bson:"origin"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	out := make([]Event, len(docs))
	for i, d := range docs {
		out[i] = Event{Seq: d.Seq, ID: d.ID, Type: d.Type, Key: d.Key, Data: d.Data, At: d.At, Origin: d.Origin}
	}
	return out, nil
}

// LastSeq is the newest sequence number that is in the log (0 when there are none). It is the largest stored number, not the counter: the counter runs ahead of an event for a moment
// while it is being written, and a consumer that moved its cursor to the counter could skip that event.
func (s *Store) LastSeq(ctx context.Context) (int64, error) {
	var d struct {
		Seq int64 `bson:"seq"`
	}
	err := s.db.Collection("relay_events").FindOne(ctx, s.scope(bson.D{}), options.FindOne().SetSort(bson.D{{Key: "seq", Value: -1}}).SetProjection(bson.D{{Key: "seq", Value: 1}})).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return 0, nil
	}
	return d.Seq, err
}

func regexQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---- subscriptions ----

// Subscription is a webhook the server keeps delivering to, in order, from where it left off.
type Subscription struct {
	ID      string   `bson:"id" json:"id"`
	Name    string   `bson:"name" json:"name"`
	URL     string   `bson:"url" json:"url"`
	Types   []string `bson:"types,omitempty" json:"types,omitempty"` // patterns; empty means every type
	Enabled bool     `bson:"enabled" json:"enabled"`
	// Secret signs each delivery (X-Fleetcore-Signature). It is shown once, when the subscription is created, and kept sealed.
	Secret string `bson:"secret" json:"-"`
	// Cursor is the sequence number delivered up to.
	Cursor        int64     `bson:"cursor" json:"cursor"`
	CreatedAt     time.Time `bson:"created_at" json:"created_at"`
	LastSuccessAt time.Time `bson:"last_success_at,omitempty" json:"last_success_at,omitempty"`
	LastError     string    `bson:"last_error,omitempty" json:"last_error,omitempty"`
	LastErrorAt   time.Time `bson:"last_error_at,omitempty" json:"last_error_at,omitempty"`
	Failures      int       `bson:"failures" json:"failures"` // consecutive
	// PausedReason is set when the subscription stopped itself after too many failures in a row; resume it to continue from the cursor.
	PausedReason  string    `bson:"paused_reason,omitempty" json:"paused_reason,omitempty"`
	NextAttemptAt time.Time `bson:"next_attempt_at,omitempty" json:"next_attempt_at,omitempty"`
	Delivered     int64     `bson:"delivered" json:"delivered"`
}

// Delivery is one attempt, kept for a few days.
type Delivery struct {
	Subscription string    `bson:"subscription" json:"subscription"`
	Seq          int64     `bson:"seq" json:"seq"`
	Event        string    `bson:"event" json:"event"` // the event type
	At           time.Time `bson:"at" json:"at"`
	Status       int       `bson:"status" json:"status"` // HTTP status, 0 if the request failed
	OK           bool      `bson:"ok" json:"ok"`
	Error        string    `bson:"error,omitempty" json:"error,omitempty"`
	Millis       int64     `bson:"millis" json:"millis"`
}

func newSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "whsec_" + base64.RawURLEncoding.EncodeToString(b)
}

func newID() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return "sub_" + base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) sealedSecret(secret string) (string, error) {
	return seal.Put(s.Sealer, "relay.secret", []byte(secret))
}

// OpenSecret returns the plain secret of a subscription loaded from the store.
func (s *Store) OpenSecret(sub *Subscription) (string, error) {
	b, err := seal.Get(s.Sealer, "relay.secret", sub.Secret)
	return string(b), err
}

// CreateSubscription stores a subscription starting at the newest event (or at fromSeq if given); it returns it with the plain secret, which cannot be read again.
func (s *Store) CreateSubscription(ctx context.Context, sub Subscription, fromSeq *int64) (*Subscription, string, error) {
	sub.ID = newID()
	sub.Enabled = true
	sub.CreatedAt = s.now()
	secret := newSecret()
	sealed, err := s.sealedSecret(secret)
	if err != nil {
		return nil, "", err
	}
	sub.Secret = sealed
	if fromSeq != nil {
		sub.Cursor = *fromSeq
	} else if sub.Cursor, err = s.LastSeq(ctx); err != nil {
		return nil, "", err
	}
	_, err = s.db.Collection("relay_subscriptions").InsertOne(ctx, s.stampDoc(sub, s.key("s", sub.ID)))
	return &sub, secret, err
}

func (s *Store) stampDoc(v any, id string) bson.D {
	b, _ := bson.Marshal(v)
	var d bson.D
	_ = bson.Unmarshal(b, &d)
	return s.stamp(append(bson.D{{Key: "_id", Value: id}}, d...))
}

// Subscriptions lists them.
func (s *Store) Subscriptions(ctx context.Context) ([]Subscription, error) {
	cur, err := s.db.Collection("relay_subscriptions").Find(ctx, s.scope(bson.D{}), options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}))
	if err != nil {
		return nil, err
	}
	var out []Subscription
	return out, cur.All(ctx, &out)
}

// Subscription returns one; nil if none.
func (s *Store) Subscription(ctx context.Context, id string) (*Subscription, error) {
	var sub Subscription
	err := s.db.Collection("relay_subscriptions").FindOne(ctx, bson.D{{Key: "_id", Value: s.key("s", id)}}).Decode(&sub)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &sub, err
}

// UpdateSubscription changes fields of a subscription.
func (s *Store) UpdateSubscription(ctx context.Context, id string, set bson.D) error {
	res, err := s.db.Collection("relay_subscriptions").UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key("s", id)}}, bson.D{{Key: "$set", Value: set}})
	if err == nil && res.MatchedCount == 0 {
		return fmt.Errorf("no such subscription")
	}
	return err
}

// DeleteSubscription removes a subscription and its delivery records.
func (s *Store) DeleteSubscription(ctx context.Context, id string) error {
	if _, err := s.db.Collection("relay_subscriptions").DeleteOne(ctx, bson.D{{Key: "_id", Value: s.key("s", id)}}); err != nil {
		return err
	}
	_, err := s.db.Collection("relay_deliveries").DeleteMany(ctx, s.scope(bson.D{{Key: "subscription", Value: id}}))
	return err
}

// RecordDelivery keeps an attempt.
func (s *Store) RecordDelivery(ctx context.Context, d Delivery) {
	_, _ = s.db.Collection("relay_deliveries").InsertOne(ctx, s.stamp(bson.D{{Key: "subscription", Value: d.Subscription}, {Key: "seq", Value: d.Seq}, {Key: "event", Value: d.Event}, {Key: "at", Value: d.At}, {Key: "status", Value: d.Status}, {Key: "ok", Value: d.OK}, {Key: "error", Value: d.Error}, {Key: "millis", Value: d.Millis}}))
}

// Deliveries returns the latest attempts of a subscription, newest first.
func (s *Store) Deliveries(ctx context.Context, id string, limit int) ([]Delivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	cur, err := s.db.Collection("relay_deliveries").Find(ctx, s.scope(bson.D{{Key: "subscription", Value: id}}), options.Find().SetSort(bson.D{{Key: "at", Value: -1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	var out []Delivery
	return out, cur.All(ctx, &out)
}
