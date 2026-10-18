// Package vault keeps the secrets a device management server ends up holding about devices: FileVault recovery keys, recovery lock and firmware passwords, Activation Lock bypass codes.
// They are sealed with the tenant's key, kept with their history (the key before the last rotation is the one a locked-out person needs), and never read without a recorded reason.
package vault

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/seal"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Kinds of secret.
const (
	FileVaultRecoveryKey   = "filevault-recovery-key"
	RecoveryLock           = "recovery-lock"
	FirmwarePassword       = "firmware-password"
	ActivationLockBypass   = "activation-lock-bypass"
	BootstrapTokenEscrowed = "bootstrap-token"
)

// Meta describes a stored secret without revealing it.
type Meta struct {
	Device    string    `bson:"device" json:"device"`
	Kind      string    `bson:"kind" json:"kind"`
	Version   int       `bson:"version" json:"version"`
	Current   bool      `bson:"current" json:"current"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	CreatedBy string    `bson:"created_by" json:"created_by"`
}

// Access is one entry of the audit trail.
type Access struct {
	Device string    `bson:"device" json:"device"`
	Kind   string    `bson:"kind" json:"kind"`
	Action string    `bson:"action" json:"action"` // stored, revealed
	Who    string    `bson:"who" json:"who"`
	Reason string    `bson:"reason,omitempty" json:"reason,omitempty"`
	At     time.Time `bson:"at" json:"at"`
}

// Store keeps the secrets and the audit trail in MongoDB. With a tenant, tenants share the collections.
type Store struct {
	db     *mongo.Database
	tid    string
	Sealer seal.Interface
	Now    func() time.Time
}

// NewStore returns the store and makes its indexes. tenant may be empty.
func NewStore(ctx context.Context, db *mongo.Database, tenant string) (*Store, error) {
	s := &Store{db: db, tid: tenant}
	lead := func(k bson.D) bson.D {
		if tenant == "" {
			return k
		}
		return append(bson.D{{Key: "t", Value: 1}}, k...)
	}
	if _, err := db.Collection("vault_secrets").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: lead(bson.D{{Key: "device", Value: 1}, {Key: "kind", Value: 1}, {Key: "version", Value: -1}}), Options: options.Index().SetUnique(true)}); err != nil {
		return nil, err
	}
	if _, err := db.Collection("vault_audit").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: lead(bson.D{{Key: "device", Value: 1}, {Key: "at", Value: -1}})}); err != nil {
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
	k := strings.Join(parts, "\x1f")
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

func purpose(kind string) string { return "vault." + kind }

// Put stores a new version of a secret and makes it the current one. by says who or what stored it.
func (s *Store) Put(ctx context.Context, device, kind, value, by string) (int, error) {
	sealed, err := seal.Put(s.Sealer, purpose(kind), []byte(value))
	if err != nil {
		return 0, err
	}
	cur, err := s.latest(ctx, device, kind)
	if err != nil {
		return 0, err
	}
	version := 1
	if cur != nil {
		version = cur.Version + 1
	}
	doc := s.stamp(bson.D{{Key: "_id", Value: s.key(device, kind, itoa(version))}, {Key: "device", Value: device}, {Key: "kind", Value: kind}, {Key: "version", Value: version}, {Key: "current", Value: true},
		{Key: "value", Value: sealed}, {Key: "created_at", Value: s.now()}, {Key: "created_by", Value: by}})
	if _, err := s.db.Collection("vault_secrets").InsertOne(ctx, doc); err != nil {
		return 0, err
	}
	if _, err := s.db.Collection("vault_secrets").UpdateMany(ctx, s.scope(bson.D{{Key: "device", Value: device}, {Key: "kind", Value: kind}, {Key: "version", Value: bson.D{{Key: "$lt", Value: version}}}}), bson.D{{Key: "$set", Value: bson.D{{Key: "current", Value: false}}}}); err != nil {
		return 0, err
	}
	return version, s.audit(ctx, device, kind, "stored", by, "")
}

func itoa(n int) string { return strconv.Itoa(n) }

func (s *Store) latest(ctx context.Context, device, kind string) (*Meta, error) {
	var m Meta
	err := s.db.Collection("vault_secrets").FindOne(ctx, s.scope(bson.D{{Key: "device", Value: device}, {Key: "kind", Value: kind}}), options.FindOne().SetSort(bson.D{{Key: "version", Value: -1}})).Decode(&m)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &m, err
}

// Peek returns the current version of a secret for the server's own use (a workflow that needs the old key to rotate it). It is not audited: nothing a person sees comes through here.
func (s *Store) Peek(ctx context.Context, device, kind string) (string, bool, error) {
	var d struct {
		Value string `bson:"value"`
	}
	err := s.db.Collection("vault_secrets").FindOne(ctx, s.scope(bson.D{{Key: "device", Value: device}, {Key: "kind", Value: kind}, {Key: "current", Value: true}})).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	b, err := seal.Get(s.Sealer, purpose(kind), d.Value)
	return string(b), err == nil, err
}

// ErrNoReason is returned when a secret is asked for without saying why.
var ErrNoReason = errors.New("say why the secret is needed: it is recorded")

// Reveal returns a secret to a person (version 0: the current one), recording who asked and why.
func (s *Store) Reveal(ctx context.Context, device, kind string, version int, who, reason string) (string, *Meta, error) {
	if strings.TrimSpace(reason) == "" {
		return "", nil, ErrNoReason
	}
	f := bson.D{{Key: "device", Value: device}, {Key: "kind", Value: kind}}
	if version > 0 {
		f = append(f, bson.E{Key: "version", Value: version})
	} else {
		f = append(f, bson.E{Key: "current", Value: true})
	}
	var d struct {
		Meta  `bson:",inline"`
		Value string `bson:"value"`
	}
	err := s.db.Collection("vault_secrets").FindOne(ctx, s.scope(f)).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil, mongo.ErrNoDocuments
	}
	if err != nil {
		return "", nil, err
	}
	// The access is recorded first: no record, no secret.
	if err := s.audit(ctx, device, kind, "revealed", who, reason); err != nil {
		return "", nil, err
	}
	b, err := seal.Get(s.Sealer, purpose(kind), d.Value)
	return string(b), &d.Meta, err
}

func (s *Store) audit(ctx context.Context, device, kind, action, who, reason string) error {
	_, err := s.db.Collection("vault_audit").InsertOne(ctx, s.stamp(bson.D{{Key: "device", Value: device}, {Key: "kind", Value: kind}, {Key: "action", Value: action}, {Key: "who", Value: who}, {Key: "reason", Value: reason}, {Key: "at", Value: s.now()}}))
	return err
}

// Record writes an audit entry for a secret that lives elsewhere (the bootstrap token in the MDM storage).
func (s *Store) Record(ctx context.Context, device, kind, action, who, reason string) error {
	return s.audit(ctx, device, kind, action, who, reason)
}

// List returns what is stored for a device, without values.
func (s *Store) List(ctx context.Context, device string) ([]Meta, error) {
	cur, err := s.db.Collection("vault_secrets").Find(ctx, s.scope(bson.D{{Key: "device", Value: device}}), options.Find().SetProjection(bson.D{{Key: "value", Value: 0}}))
	if err != nil {
		return nil, err
	}
	var out []Meta
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Version > out[j].Version
	})
	return out, nil
}

// Audit returns the access trail of a device, newest first.
func (s *Store) Audit(ctx context.Context, device string, limit int) ([]Access, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	cur, err := s.db.Collection("vault_audit").Find(ctx, s.scope(bson.D{{Key: "device", Value: device}}), options.Find().SetSort(bson.D{{Key: "at", Value: -1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	var out []Access
	return out, cur.All(ctx, &out)
}

// Password makes a random password of n characters from letters and digits that cannot be misread.
func Password(n int) (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	for i := range out {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[j.Int64()]
	}
	return string(out), nil
}
