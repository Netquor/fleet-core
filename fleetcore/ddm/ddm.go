// Package ddm is Apple's declarative device management: the server keeps, per device, the set of declarations it should have, and the device pulls them (and reports status) over the
// protocol Apple defines for the MDM "DeclarativeManagement" check-in. It is the way to configure and update current Apple devices; Apple deprecated the classic software-update
// commands in OS 26 and removed them in 27.
//
// The protocol, in short: the server tells the device to sync (a DeclarativeManagement command with no data); the device asks for the tokens, and if the declarations token changed for the
// declaration items, and fetches each declaration whose server token it does not have; it reports the status of what it processed. Everything the server answers comes from MongoDB, so any
// number of server processes can answer any device.
package ddm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	cDeclarations = "ddm_declarations"
	cDevices      = "ddm_devices"
	cStatus       = "ddm_status"
)

// Kinds of declaration, as the protocol names them.
const (
	KindConfiguration = "configuration"
	KindActivation    = "activation"
	KindAsset         = "asset"
	KindManagement    = "management"
)

// Declaration is one declaration for a device.
type Declaration struct {
	Identifier string         `json:"Identifier"`
	Kind       string         `json:"-"`
	Type       string         `json:"Type"` // com.apple.configuration.softwareupdate.enforcement.specific
	Payload    map[string]any `json:"Payload"`
	// Source says where it came from ("blueprint/item"), or "system".
	Source string `json:"-"`
}

// Token is the declaration's ServerToken: it changes when, and only when, the declaration's content does.
func (d Declaration) Token() string {
	b, _ := json.Marshal(d.Payload) // encoding/json sorts map keys
	h := sha256.Sum256([]byte(d.Kind + "\x00" + d.Type + "\x00" + d.Identifier + "\x00" + string(b)))
	return hex.EncodeToString(h[:16])
}

// Wire is the declaration as the device receives it.
func (d Declaration) Wire() ([]byte, error) {
	return json.Marshal(struct {
		Type        string         `json:"Type"`
		Identifier  string         `json:"Identifier"`
		ServerToken string         `json:"ServerToken"`
		Payload     map[string]any `json:"Payload"`
	}{d.Type, d.Identifier, d.Token(), d.Payload})
}

// SetToken is the DeclarationsToken for a set: it changes when any declaration is added, removed or changed.
func SetToken(ds []Declaration) string {
	lines := make([]string, len(ds))
	for i, d := range ds {
		lines[i] = d.Kind + "/" + d.Identifier + "/" + d.Token()
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Store keeps declarations, per-device sync state and status reports in MongoDB. With a tenant, tenants share the collections.
type Store struct {
	db  *mongo.Database
	tid string
	Now func() time.Time
}

// NewStore returns the store and makes its indexes.
func NewStore(ctx context.Context, db *mongo.Database, tenant string) (*Store, error) {
	s := &Store{db: db, tid: tenant}
	lead := func(k bson.D) bson.D {
		if tenant == "" {
			return k
		}
		return append(bson.D{{Key: "t", Value: 1}}, k...)
	}
	if _, err := db.Collection(cDeclarations).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: lead(bson.D{{Key: "device", Value: 1}, {Key: "identifier", Value: 1}}), Options: options.Index().SetUnique(true)},
		{Keys: lead(bson.D{{Key: "source", Value: 1}})},
	}); err != nil {
		return nil, err
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
	k := ""
	for i, p := range parts {
		if i > 0 {
			k += "\x1f"
		}
		k += p
	}
	if s.tid == "" {
		return k
	}
	return s.tid + "\x1f" + k
}

func (s *Store) scope(f bson.D) bson.D {
	if s.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, f...)
}

func (s *Store) stamp(d bson.D) bson.D {
	if s.tid == "" {
		return d
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, d...)
}

type row struct {
	Identifier string `bson:"identifier"`
	Kind       string `bson:"kind"`
	Type       string `bson:"type"`
	Payload    string `bson:"payload"`
	Token      string `bson:"token"`
	Source     string `bson:"source"`
}

func (r row) declaration() (Declaration, error) {
	d := Declaration{Identifier: r.Identifier, Kind: r.Kind, Type: r.Type, Source: r.Source}
	return d, json.Unmarshal([]byte(r.Payload), &d.Payload)
}

// State is what the server knows about a device's sync.
type State struct {
	Token         string    `bson:"token"`          // the DeclarationsToken now
	UpdatedAt     time.Time `bson:"updated_at"`     // when it last changed
	NotifiedToken string    `bson:"notified_token"` // the token the device was last told to sync for
	NotifiedAt    time.Time `bson:"notified_at"`
	SyncedToken   string    `bson:"synced_token"` // the token the device last fetched the items for
	SyncedAt      time.Time `bson:"synced_at"`
}

// Replace makes the device's declarations exactly ds. It writes only the difference and reports whether anything changed.
func (s *Store) Replace(ctx context.Context, device string, ds []Declaration) (changed bool, st State, err error) {
	cur, err := s.db.Collection(cDeclarations).Find(ctx, s.scope(bson.D{{Key: "device", Value: device}}))
	if err != nil {
		return false, st, err
	}
	var have []row
	if err := cur.All(ctx, &have); err != nil {
		return false, st, err
	}
	old := make(map[string]string, len(have))
	for _, r := range have {
		old[r.Identifier] = r.Token
	}
	var ops []mongo.WriteModel
	want := make(map[string]bool, len(ds))
	for _, d := range ds {
		want[d.Identifier] = true
		tok := d.Token()
		if old[d.Identifier] == tok {
			continue
		}
		b, err := json.Marshal(d.Payload)
		if err != nil {
			return false, st, err
		}
		doc := s.stamp(bson.D{{Key: "device", Value: device}, {Key: "identifier", Value: d.Identifier}, {Key: "kind", Value: d.Kind}, {Key: "type", Value: d.Type}, {Key: "payload", Value: string(b)}, {Key: "token", Value: tok}, {Key: "source", Value: d.Source}})
		ops = append(ops, mongo.NewReplaceOneModel().SetFilter(bson.D{{Key: "_id", Value: s.key(device, d.Identifier)}}).SetReplacement(doc).SetUpsert(true))
	}
	for id := range old {
		if !want[id] {
			ops = append(ops, mongo.NewDeleteOneModel().SetFilter(bson.D{{Key: "_id", Value: s.key(device, id)}}))
		}
	}
	token := SetToken(ds)
	st, err = s.State(ctx, device)
	if err != nil {
		return false, st, err
	}
	if len(ops) == 0 && st.Token == token {
		return false, st, nil
	}
	if len(ops) > 0 {
		if _, err := s.db.Collection(cDeclarations).BulkWrite(ctx, ops, options.BulkWrite().SetOrdered(false)); err != nil {
			return false, st, err
		}
	}
	st.Token, st.UpdatedAt = token, s.now()
	_, err = s.db.Collection(cDevices).UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key(device)}},
		bson.D{{Key: "$set", Value: s.stamp(bson.D{{Key: "device", Value: device}, {Key: "token", Value: token}, {Key: "updated_at", Value: st.UpdatedAt}})}}, options.UpdateOne().SetUpsert(true))
	return true, st, err
}

// State returns the sync state of a device (zero if it has none).
func (s *Store) State(ctx context.Context, device string) (State, error) {
	var st State
	err := s.db.Collection(cDevices).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(device)}}).Decode(&st)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return State{}, nil
	}
	return st, err
}

func (s *Store) setState(ctx context.Context, device string, fields bson.D) error {
	_, err := s.db.Collection(cDevices).UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key(device)}},
		bson.D{{Key: "$set", Value: s.stamp(append(bson.D{{Key: "device", Value: device}}, fields...))}}, options.UpdateOne().SetUpsert(true))
	return err
}

// Notified records that the device was told to sync for a token.
func (s *Store) Notified(ctx context.Context, device, token string) error {
	return s.setState(ctx, device, bson.D{{Key: "notified_token", Value: token}, {Key: "notified_at", Value: s.now()}})
}

// Synced records that the device fetched the items for a token.
func (s *Store) Synced(ctx context.Context, device, token string) error {
	return s.setState(ctx, device, bson.D{{Key: "synced_token", Value: token}, {Key: "synced_at", Value: s.now()}})
}

// List returns a device's declarations.
func (s *Store) List(ctx context.Context, device string) ([]Declaration, error) {
	cur, err := s.db.Collection(cDeclarations).Find(ctx, s.scope(bson.D{{Key: "device", Value: device}}))
	if err != nil {
		return nil, err
	}
	var rows []row
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]Declaration, 0, len(rows))
	for _, r := range rows {
		d, err := r.declaration()
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identifier < out[j].Identifier })
	return out, nil
}

// Get returns one declaration of a device by its kind and identifier.
func (s *Store) Get(ctx context.Context, device, kind, identifier string) (*Declaration, error) {
	var r row
	err := s.db.Collection(cDeclarations).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(device, identifier)}}).Decode(&r)
	if errors.Is(err, mongo.ErrNoDocuments) || (err == nil && r.Kind != kind) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d, err := r.declaration()
	return &d, err
}

// BySource returns the identifiers the declarations of a source have on a device (used to map status back to blueprint items).
func (s *Store) BySource(ctx context.Context, device string) (map[string]string, error) {
	ds, err := s.List(ctx, device)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(ds))
	for _, d := range ds {
		m[d.Identifier] = d.Source
	}
	return m, nil
}
