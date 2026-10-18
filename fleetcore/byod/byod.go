// Package byod is account-driven User Enrollment: a person signs in on their own iPhone, iPad or Mac with a Managed Apple Account, the device finds this server, the person
// authenticates to the organization's identity provider, and the device receives an enrollment profile for that person. The organization then manages only its own data on the device.
//
// The server side of that conversation: a discovery document (which Apple's devices read from the account's domain), an endpoint that wants an access token from the identity provider
// (and says where to get one: Apple's "apple-as-web" sign-in) and answers with a profile naming the person, and a record of which person each identity certificate belongs to.
package byod

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"crypto/rand"

	"github.com/golang-jwt/jwt/v5"
	"github.com/micromdm/nanomdm/fleetcore/enroll"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Identity is who signed in.
type Identity struct {
	// ManagedAppleID is the person's Managed Apple Account, for example alice@example.com.
	ManagedAppleID string
	// Subject is the identity provider's stable identifier for the person.
	Subject string
}

// Authenticator decides who is asking. A request that carries no valid token returns an error; the handler then sends the device to sign in.
type Authenticator interface {
	Authenticate(r *http.Request) (*Identity, error)
}

// ErrUnauthenticated means the request has no valid sign-in.
var ErrUnauthenticated = errors.New("not signed in")

// OIDC authenticates with an access token (a JWT) issued by an OpenID Connect provider: signature checked against the provider's published keys, issuer, audience and expiry checked.
type OIDC struct {
	Issuer   string
	JWKSURL  string
	Audience string
	// Claim holds the Managed Apple Account in the token (default "email").
	Claim string
	// Algorithms allowed for the token's signature (default RS256 and ES256).
	Algorithms []string
	HTTP       *http.Client

	mu      sync.Mutex
	keys    map[string]any
	fetched time.Time
}

func (o *OIDC) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (o *OIDC) key(ctx context.Context, kid string) (any, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if k, ok := o.keys[kid]; ok && time.Since(o.fetched) < 15*time.Minute {
		return k, nil
	}
	// A new key id, or a stale cache: fetch again (but not more often than every 30 seconds).
	if o.keys != nil && time.Since(o.fetched) < 30*time.Second {
		return nil, errors.New("unknown signing key")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", o.JWKSURL, nil)
	resp, err := o.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetching the signing keys: HTTP %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty, Kid, N, E, Crv, X, Y string
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]any{}
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			n, e := b64int(k.N), b64int(k.E)
			if n != nil && e != nil && e.IsInt64() {
				keys[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
			}
		case "EC":
			var c elliptic.Curve
			switch k.Crv {
			case "P-256":
				c = elliptic.P256()
			case "P-384":
				c = elliptic.P384()
			}
			if x, y := b64int(k.X), b64int(k.Y); c != nil && x != nil && y != nil {
				keys[k.Kid] = &ecdsa.PublicKey{Curve: c, X: x, Y: y}
			}
		}
	}
	o.keys, o.fetched = keys, time.Now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown signing key")
}

func b64int(s string) *big.Int {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil
	}
	return new(big.Int).SetBytes(b)
}

// Authenticate checks the bearer token.
func (o *OIDC) Authenticate(r *http.Request) (*Identity, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, ErrUnauthenticated
	}
	algs := o.Algorithms
	if len(algs) == 0 {
		algs = []string{"RS256", "ES256"}
	}
	claim := o.Claim
	if claim == "" {
		claim = "email"
	}
	tok, err := jwt.Parse(strings.TrimPrefix(h, "Bearer "), func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return o.key(r.Context(), kid)
	}, jwt.WithValidMethods(algs), jwt.WithIssuer(o.Issuer), jwt.WithAudience(o.Audience), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return nil, ErrUnauthenticated
	}
	claims, _ := tok.Claims.(jwt.MapClaims)
	id := &Identity{}
	id.ManagedAppleID, _ = claims[claim].(string)
	id.Subject, _ = claims["sub"].(string)
	if id.ManagedAppleID == "" {
		return nil, fmt.Errorf("%w: the token has no %q claim", ErrUnauthenticated, claim)
	}
	return id, nil
}

// Store remembers which person each identity certificate name was issued for, so that when the device enrolls, the enrollment can be tied to the person.
type Store struct {
	c   *mongo.Collection
	tid string
}

// NewStore returns the store. tenant may be empty (the database belongs to one tenant).
func NewStore(ctx context.Context, db *mongo.Database, tenant string) (*Store, error) {
	s := &Store{c: db.Collection("byod_enrollments"), tid: tenant}
	_, err := s.c.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "created_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(7 * 24 * 3600)})
	return s, err
}

func (s *Store) key(cn string) string {
	if s.tid == "" {
		return cn
	}
	return s.tid + "\x1f" + cn
}

// Put records that the certificate name belongs to the person.
func (s *Store) Put(ctx context.Context, cn string, id Identity) error {
	doc := s.stamp(bson.D{{Key: "_id", Value: s.key(cn)}, {Key: "cn", Value: cn}, {Key: "managed_apple_id", Value: id.ManagedAppleID}, {Key: "subject", Value: id.Subject}, {Key: "created_at", Value: time.Now().UTC()}})
	_, err := s.c.ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(cn)}}, doc, options.Replace().SetUpsert(true))
	return err
}

func (s *Store) stamp(d bson.D) bson.D {
	if s.tid == "" {
		return d
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, d...)
}

// ManagedAppleID returns the person a certificate name was issued for; empty if unknown.
func (s *Store) ManagedAppleID(ctx context.Context, cn string) string {
	var d struct {
		ID string `bson:"managed_apple_id"`
	}
	if err := s.c.FindOne(ctx, bson.D{{Key: "_id", Value: s.key(cn)}}).Decode(&d); err != nil {
		return ""
	}
	return d.ID
}

// Config is the account-driven enrollment endpoint.
type Config struct {
	Auth Authenticator
	// LoginURL is where a device without a token signs in (the identity provider's page, which returns the access token to the device through Apple's sign-in flow).
	LoginURL string
	Profile  enroll.Options
	// Challenges makes the one-use SCEP challenge in the profile.
	Challenges enroll.ChallengeSource
	Store      *Store
}

// Handler is the enrollment endpoint (serve it at /enroll/byod). A request without a valid token gets 401 and the sign-in address; with one, it gets the enrollment profile for that person.
func Handler(c Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := c.Auth.Authenticate(r)
		if err != nil {
			h := `Bearer`
			if c.LoginURL != "" {
				h = fmt.Sprintf(`Bearer method="apple-as-web" url="%s"`, c.LoginURL)
			}
			w.Header().Set("WWW-Authenticate", h)
			http.Error(w, "sign in required", http.StatusUnauthorized)
			return
		}
		pw, err := c.Challenges.SCEPChallenge()
		if err != nil {
			http.Error(w, "could not make a challenge", http.StatusInternalServerError)
			return
		}
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		cn := "ue-" + base64.RawURLEncoding.EncodeToString(b)
		o := c.Profile
		o.BYOD, o.ManagedAppleID, o.SubjectCN = true, id.ManagedAppleID, cn
		body, err := enroll.Build(o, pw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if c.Store != nil {
			if err := c.Store.Put(r.Context(), cn, *id); err != nil {
				http.Error(w, "could not record the enrollment", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	})
}

// WellKnown serves the discovery document Apple's devices read from https://<domain of the account>/.well-known/com.apple.remotemanagement. The organization's web server for that domain
// serves it (or redirects the path here).
func WellKnown(enrollURL string) http.Handler {
	doc, _ := json.Marshal(map[string]any{"Servers": []any{map[string]any{"Version": "mdm-byod", "BaseURL": enrollURL}}})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	})
}
