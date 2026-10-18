package acme

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Store keeps accounts, orders, authorizations, challenges and issued certificates, and the nonces that make each request usable once. With a tenant, tenants share the collections.
type Store struct {
	db  *mongo.Database
	tid string
	Now func() time.Time
}

// NewStore returns the store and makes its indexes (nonces and old orders expire on their own).
func NewStore(ctx context.Context, db *mongo.Database, tenant string) (*Store, error) {
	s := &Store{db: db, tid: tenant}
	for coll, ttl := range map[string]int32{"acme_nonces": 3600, "acme_orders": 7 * 24 * 3600, "acme_authz": 7 * 24 * 3600} {
		if _, err := db.Collection(coll).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "created_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(ttl)}); err != nil {
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

func newID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Nonce makes a fresh nonce.
func (s *Store) Nonce(ctx context.Context) (string, error) {
	n := newID(18)
	_, err := s.db.Collection("acme_nonces").InsertOne(ctx, s.stamp(bson.D{{Key: "_id", Value: s.key(n)}, {Key: "created_at", Value: s.now()}}))
	return n, err
}

// useNonce spends a nonce; false if it was never made or was spent.
func (s *Store) useNonce(ctx context.Context, n string) (bool, error) {
	res, err := s.db.Collection("acme_nonces").DeleteOne(ctx, bson.D{{Key: "_id", Value: s.key(n)}})
	return err == nil && res.DeletedCount == 1, err
}

type account struct {
	ID         string    `bson:"id"`
	Thumbprint string    `bson:"thumbprint"`
	JWK        jwk       `bson:"jwk"`
	Contact    []string  `bson:"contact"`
	CreatedAt  time.Time `bson:"created_at"`
}

func (s *Store) accountByThumbprint(ctx context.Context, tp string) (*account, error) {
	var a account
	err := s.db.Collection("acme_accounts").FindOne(ctx, bson.D{{Key: "_id", Value: s.key("tp", tp)}}).Decode(&a)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &a, err
}

func (s *Store) account(ctx context.Context, id string) (*account, error) {
	var a account
	err := s.db.Collection("acme_accounts").FindOne(ctx, bson.D{{Key: "_id", Value: s.key("id", id)}}).Decode(&a)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &a, err
}

func (s *Store) putAccount(ctx context.Context, a account) error {
	for _, k := range []string{s.key("id", a.ID), s.key("tp", a.Thumbprint)} {
		doc := s.stamp(bson.D{{Key: "_id", Value: k}, {Key: "id", Value: a.ID}, {Key: "thumbprint", Value: a.Thumbprint}, {Key: "jwk", Value: a.JWK}, {Key: "contact", Value: a.Contact}, {Key: "created_at", Value: a.CreatedAt}})
		// tenant-ok: the _id is tenant-prefixed by s.key
		if _, err := s.db.Collection("acme_accounts").ReplaceOne(ctx, bson.D{{Key: "_id", Value: k}}, doc, options.Replace().SetUpsert(true)); err != nil {
			return err
		}
	}
	return nil
}

// Identifier is what an order asks a certificate for.
type Identifier struct {
	Type  string `bson:"type" json:"type"`
	Value string `bson:"value" json:"value"`
}

type order struct {
	ID          string       `bson:"id"`
	Account     string       `bson:"account"`
	Identifiers []Identifier `bson:"identifiers"`
	Status      string       `bson:"status"` // pending, ready, valid, invalid
	Authz       []string     `bson:"authz"`
	Cert        string       `bson:"cert"`
	CreatedAt   time.Time    `bson:"created_at"`
	Expires     time.Time    `bson:"expires"`
}

type authz struct {
	ID         string     `bson:"id"`
	Account    string     `bson:"account"`
	Order      string     `bson:"order"`
	Identifier Identifier `bson:"identifier"`
	Status     string     `bson:"status"` // pending, valid, invalid
	Token      string     `bson:"token"`
	Challenge  string     `bson:"challenge"` // the challenge's own id
	// AttestedKey is the public key (DER) the device proved it holds in hardware; the certificate can be issued only for it.
	AttestedKey []byte    `bson:"attested_key,omitempty"`
	Attested    bson.M    `bson:"attested,omitempty"`
	CreatedAt   time.Time `bson:"created_at"`
	Expires     time.Time `bson:"expires"`
}

func (s *Store) put(ctx context.Context, coll, id string, v any, created time.Time) error {
	b, _ := bson.Marshal(v)
	var d bson.D
	_ = bson.Unmarshal(b, &d)
	filtered := bson.D{{Key: "_id", Value: s.key(id)}}
	for _, e := range d {
		if e.Key != "_id" {
			filtered = append(filtered, e)
		}
	}
	_, err := s.db.Collection(coll).ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}}, s.stamp(filtered), options.Replace().SetUpsert(true))
	return err
}

func (s *Store) get(ctx context.Context, coll, id string, v any) (bool, error) {
	err := s.db.Collection(coll).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}}).Decode(v)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return false, nil
	}
	return err == nil, err
}
