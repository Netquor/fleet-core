package userauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Store keeps the challenges handed out (each usable once, for five minutes) and the hash of the AuthToken of each user session. With a tenant, tenants share the collections.
type Store struct {
	db  *mongo.Database
	tid string
	Now func() time.Time
}

// TokenState is the outcome of checking a request's AuthToken.
type TokenState int

const (
	// NoToken: no handshake was completed for this user.
	NoToken TokenState = iota
	// TokenOK: the token matches.
	TokenOK
	// TokenWrong: a token exists and this is not it.
	TokenWrong
)

// NewStore returns the store and makes its indexes (challenges and tokens expire on their own).
func NewStore(ctx context.Context, db *mongo.Database, tenant string) (*Store, error) {
	s := &Store{db: db, tid: tenant}
	if _, err := db.Collection("ua_nonces").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "created_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(300)}); err != nil {
		return nil, err
	}
	if _, err := db.Collection("ua_tokens").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}); err != nil {
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

func (s *Store) stamp(d bson.D) bson.D {
	if s.tid == "" {
		return d
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, d...)
}

// NewNonce makes the challenge for one enrollment's handshake.
func (s *Store) NewNonce(ctx context.Context, enrollID string) (string, error) {
	b := make([]byte, 33)
	_, _ = rand.Read(b)
	n := base64.RawURLEncoding.EncodeToString(b)
	_, err := s.db.Collection("ua_nonces").InsertOne(ctx, s.stamp(bson.D{{Key: "_id", Value: s.key(enrollID, n)}, {Key: "created_at", Value: s.now()}}))
	return n, err
}

// UseNonce spends a challenge; false if it was not made for this enrollment, is spent, or is old.
func (s *Store) UseNonce(ctx context.Context, enrollID, nonce string) (bool, error) {
	var doc struct {
		CreatedAt time.Time `bson:"created_at"`
	}
	err := s.db.Collection("ua_nonces").FindOneAndDelete(ctx, bson.D{{Key: "_id", Value: s.key(enrollID, nonce)}}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return s.now().Sub(doc.CreatedAt) <= 5*time.Minute, nil
}

// IssueToken makes the AuthToken for a user session, replacing the previous one (a token lasts until the next handshake).
func (s *Store) IssueToken(ctx context.Context, enrollID, user string, life time.Duration) (string, error) {
	token := randomToken()
	_, err := s.db.Collection("ua_tokens").ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(enrollID)}}, // tenant-ok: the _id is tenant-prefixed by s.key
		s.stamp(bson.D{{Key: "_id", Value: s.key(enrollID)}, {Key: "user", Value: user}, {Key: "token", Value: hashToken(token)}, {Key: "issued_at", Value: s.now()}, {Key: "expires_at", Value: s.now().Add(life)}}),
		options.Replace().SetUpsert(true))
	return token, err
}

// CheckToken compares a request's token with the one issued.
func (s *Store) CheckToken(ctx context.Context, enrollID, token string) (TokenState, error) {
	var doc struct {
		Token string `bson:"token"`
	}
	err := s.db.Collection("ua_tokens").FindOne(ctx, bson.D{{Key: "_id", Value: s.key(enrollID)}}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return NoToken, nil
	}
	if err != nil {
		return NoToken, err
	}
	if token != "" && subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(doc.Token)) == 1 {
		return TokenOK, nil
	}
	return TokenWrong, nil
}

// Forget removes a user's token (at checkout).
func (s *Store) Forget(ctx context.Context, enrollID string) error {
	_, err := s.db.Collection("ua_tokens").DeleteOne(ctx, bson.D{{Key: "_id", Value: s.key(enrollID)}})
	return err
}
