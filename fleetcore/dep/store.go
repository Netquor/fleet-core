// Package dep is Apple's Automated Device Enrollment (DEP) inside fleetcore: NanoDEP's storage on MongoDB, its API routes, and a manager that runs one syncer and assigner per DEP name.
package dep

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/micromdm/nanodep/client"
	"github.com/micromdm/nanodep/storage"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/micromdm/nanomdm/fleetcore/pki"
	"github.com/micromdm/nanomdm/fleetcore/seal"
)

const collection = "dep_names"

// Store implements nanodep's storage.AllStorage on MongoDB. One document holds everything about a DEP name: OAuth tokens, config, assigner profile, sync cursor and the token exchange key pairs.
// Secrets (OAuth secrets and tokens, private keys) are sealed with the passphrase. With a tenant, tenants share the collection and every document carries it.
type Store struct {
	c    *mongo.Collection
	tid  string
	pass string
	// Sealer, if set, seals secrets with the tenant's key. Values written before (sealed with the passphrase) still open; the rekey command seals them with the key.
	Sealer seal.Interface
}

var _ storage.AllStorage = (*Store)(nil)

// New returns the store. tenant may be empty. pass seals secrets at rest (empty: stored plain, development only).
func New(ctx context.Context, db *mongo.Database, tenant, pass string) (*Store, error) {
	s := &Store{c: db.Collection(collection), tid: tenant, pass: pass}
	if tenant != "" {
		if _, err := s.c.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "t", Value: 1}, {Key: "name", Value: 1}}}); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) key(name string) string {
	if s.tid == "" {
		return name
	}
	return s.tid + "\x1f" + name
}

func (s *Store) set(ctx context.Context, name string, fields bson.D) error {
	set := append(bson.D{{Key: "name", Value: name}}, fields...)
	if s.tid != "" {
		set = append(set, bson.E{Key: "t", Value: s.tid})
	}
	_, err := s.c.UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key(name)}}, bson.D{{Key: "$set", Value: set}}, options.UpdateOne().SetUpsert(true))
	return err
}

type doc struct {
	Name   string `bson:"name"`
	Tokens *struct {
		ConsumerKey, ConsumerSecret, AccessToken, AccessSecret string
		Expiry                                                 time.Time
	} `bson:"tokens"`
	Config       string    `bson:"config"`
	AssignerUUID string    `bson:"assigner_uuid"`
	AssignerMod  time.Time `bson:"assigner_mod"`
	Cursor       string    `bson:"cursor"`
	Staging      *pair     `bson:"pki_staging"`
	Current      *pair     `bson:"pki"`
}

type pair struct {
	Cert string `bson:"cert"`
	Key  string `bson:"key"`
}

func (s *Store) get(ctx context.Context, name string) (*doc, error) {
	var d doc
	err := s.c.FindOne(ctx, bson.D{{Key: "_id", Value: s.key(name)}}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &d, err
}

func (s *Store) sealed(b string) (string, error) { return s.seal("dep.secret", []byte(b)) }

func (s *Store) seal(purpose string, b []byte) (string, error) {
	if s.Sealer != nil {
		return s.Sealer.Seal(purpose, b)
	}
	return pki.Seal(b, s.pass)
}

// open reads a sealed value: ones sealed with the passphrase (before the key was configured) as well as ones sealed with the tenant's key.
func (s *Store) open(purpose, v string) ([]byte, error) {
	if s.Sealer != nil && strings.HasPrefix(v, "s1.") {
		return s.Sealer.Open(purpose, v)
	}
	return pki.Open(v, s.pass)
}

func (s *Store) StoreAuthTokens(ctx context.Context, name string, t *client.OAuth1Tokens) error {
	var enc [4]string
	for i, v := range []string{t.ConsumerKey, t.ConsumerSecret, t.AccessToken, t.AccessSecret} {
		x, err := s.sealed(v)
		if err != nil {
			return err
		}
		enc[i] = x
	}
	return s.set(ctx, name, bson.D{{Key: "tokens", Value: bson.D{
		{Key: "consumerkey", Value: enc[0]}, {Key: "consumersecret", Value: enc[1]}, {Key: "accesstoken", Value: enc[2]}, {Key: "accesssecret", Value: enc[3]},
		{Key: "expiry", Value: t.AccessTokenExpiry.UTC()},
	}}})
}

func (s *Store) RetrieveAuthTokens(ctx context.Context, name string) (*client.OAuth1Tokens, error) {
	d, err := s.get(ctx, name)
	if err != nil {
		return nil, err
	}
	if d == nil || d.Tokens == nil {
		return nil, storage.ErrNotFound
	}
	out := &client.OAuth1Tokens{AccessTokenExpiry: d.Tokens.Expiry}
	for i, dst := range []*string{&out.ConsumerKey, &out.ConsumerSecret, &out.AccessToken, &out.AccessSecret} {
		v := []string{d.Tokens.ConsumerKey, d.Tokens.ConsumerSecret, d.Tokens.AccessToken, d.Tokens.AccessSecret}[i]
		b, err := s.open("dep.secret", v)
		if err != nil {
			return nil, err
		}
		*dst = string(b)
	}
	return out, nil
}

func (s *Store) StoreConfig(ctx context.Context, name string, c *client.Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.set(ctx, name, bson.D{{Key: "config", Value: string(b)}})
}

// RetrieveConfig returns nil, nil when there is no config.
func (s *Store) RetrieveConfig(ctx context.Context, name string) (*client.Config, error) {
	d, err := s.get(ctx, name)
	if err != nil || d == nil || d.Config == "" {
		return nil, err
	}
	c := new(client.Config)
	return c, json.Unmarshal([]byte(d.Config), c)
}

func (s *Store) StoreAssignerProfile(ctx context.Context, name, profileUUID string) error {
	return s.set(ctx, name, bson.D{{Key: "assigner_uuid", Value: profileUUID}, {Key: "assigner_mod", Value: time.Now().UTC()}})
}

func (s *Store) RetrieveAssignerProfile(ctx context.Context, name string) (string, time.Time, error) {
	d, err := s.get(ctx, name)
	if err != nil || d == nil {
		return "", time.Time{}, err
	}
	return d.AssignerUUID, d.AssignerMod, nil
}

func (s *Store) StoreCursor(ctx context.Context, name, cursor string) error {
	return s.set(ctx, name, bson.D{{Key: "cursor", Value: cursor}})
}

func (s *Store) RetrieveCursor(ctx context.Context, name string) (string, error) {
	d, err := s.get(ctx, name)
	if err != nil || d == nil {
		return "", err
	}
	return d.Cursor, nil
}

func (s *Store) StoreTokenPKI(ctx context.Context, name string, pemCert, pemKey []byte) error {
	k, err := s.seal("dep.pki.key", pemKey)
	if err != nil {
		return err
	}
	return s.set(ctx, name, bson.D{{Key: "pki_staging", Value: bson.D{{Key: "cert", Value: string(pemCert)}, {Key: "key", Value: k}}}})
}

func (s *Store) openPair(p *pair) ([]byte, []byte, error) {
	if p == nil {
		return nil, nil, storage.ErrNotFound
	}
	k, err := s.open("dep.pki.key", p.Key)
	return []byte(p.Cert), k, err
}

func (s *Store) RetrieveStagingTokenPKI(ctx context.Context, name string) ([]byte, []byte, error) {
	d, err := s.get(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	if d == nil {
		return nil, nil, storage.ErrNotFound
	}
	return s.openPair(d.Staging)
}

func (s *Store) RetrieveCurrentTokenPKI(ctx context.Context, name string) ([]byte, []byte, error) {
	d, err := s.get(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	if d == nil {
		return nil, nil, storage.ErrNotFound
	}
	return s.openPair(d.Current)
}

// UpstageTokenPKI promotes the staged key pair to current in one write.
func (s *Store) UpstageTokenPKI(ctx context.Context, name string) error {
	d, err := s.get(ctx, name)
	if err != nil {
		return err
	}
	if d == nil || d.Staging == nil {
		return storage.ErrNotFound
	}
	return s.set(ctx, name, bson.D{{Key: "pki", Value: bson.D{{Key: "cert", Value: d.Staging.Cert}, {Key: "key", Value: d.Staging.Key}}}})
}

// QueryDEPNames lists the names that have a staged certificate (the same rule as NanoDEP's other backends), sorted, with offset pagination.
func (s *Store) QueryDEPNames(ctx context.Context, req *storage.DEPNamesQueryRequest) (*storage.DEPNamesQueryResult, error) {
	var offset, limit int
	if req != nil {
		if req.Pagination != nil && req.Pagination.Cursor != nil {
			return nil, storage.ErrOnlyOffset
		}
		var err error
		if _, offset, limit, err = req.Pagination.ValidateDefaultOffsetLimit(100); err != nil {
			return nil, err
		}
	} else {
		limit = 100
	}
	f := s.scopeF(bson.D{{Key: "pki_staging", Value: bson.D{{Key: "$exists", Value: true}}}})
	if req != nil && req.Filter != nil && len(req.Filter.DEPNames) > 0 {
		f = append(f, bson.E{Key: "name", Value: bson.D{{Key: "$in", Value: req.Filter.DEPNames}}})
	}
	cur, err := s.c.Find(ctx, f, options.Find().SetProjection(bson.D{{Key: "name", Value: 1}}).SetSort(bson.D{{Key: "name", Value: 1}}).SetSkip(int64(offset)).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Name string `bson:"name"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return &storage.DEPNamesQueryResult{DEPNames: names}, nil
}

// Rewrap seals every secret (OAuth tokens, token exchange keys) with the tenant's current key, including those sealed with the passphrase before. It returns how many documents it changed.
func (s *Store) Rewrap(ctx context.Context) (int, error) {
	if s.Sealer == nil {
		return 0, errors.New("no sealer configured")
	}
	cur, err := s.c.Find(ctx, s.scopeF(bson.D{}))
	if err != nil {
		return 0, err
	}
	var rows []bson.M
	if err := cur.All(ctx, &rows); err != nil {
		return 0, err
	}
	n := 0
	var re func(purpose string, v any) (any, bool, error)
	re = func(purpose string, v any) (any, bool, error) {
		str, ok := v.(string)
		if !ok || str == "" {
			return v, false, nil
		}
		if strings.HasPrefix(str, "s1.") {
			out, changed, err := seal.Reseal(s.Sealer, purpose, str)
			return out, changed, err
		}
		plain, err := s.open(purpose, str)
		if err != nil {
			return v, false, err
		}
		out, err := s.Sealer.Seal(purpose, plain)
		return out, true, err
	}
	for _, r := range rows {
		set := bson.D{}
		if t, ok := asM(r["tokens"]); ok {
			for _, k := range []string{"consumerkey", "consumersecret", "accesstoken", "accesssecret"} {
				if out, changed, err := re("dep.secret", t[k]); err != nil {
					return n, err
				} else if changed {
					set = append(set, bson.E{Key: "tokens." + k, Value: out})
				}
			}
		}
		for _, g := range []string{"pki_staging", "pki"} {
			if t, ok := asM(r[g]); ok {
				if out, changed, err := re("dep.pki.key", t["key"]); err != nil {
					return n, err
				} else if changed {
					set = append(set, bson.E{Key: g + ".key", Value: out})
				}
			}
		}
		if len(set) > 0 {
			// tenant-ok: _id comes from the scoped read above
			if _, err := s.c.UpdateOne(ctx, bson.D{{Key: "_id", Value: r["_id"]}}, bson.D{{Key: "$set", Value: set}}); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

func (s *Store) scopeF(f bson.D) bson.D {
	if s.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, f...)
}

// asM reads an embedded document, which the driver returns as an ordered document.
func asM(v any) (bson.M, bool) {
	switch t := v.(type) {
	case bson.M:
		return t, true
	case bson.D:
		m := make(bson.M, len(t))
		for _, e := range t {
			m[e.Key] = e.Value
		}
		return m, true
	}
	return nil, false
}
