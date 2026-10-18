// Package pki is the certificate authority of a fleetcore server: the SCEP depot (the CA, the certificates it has issued, their serial numbers) and the challenge passwords, kept in MongoDB
// so the server needs no files and no separate SCEP service. It plugs into github.com/micromdm/scep/v2.
package pki

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	scepdepot "github.com/micromdm/scep/v2/depot"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/scrypt"
)

const (
	cCA         = "pki_ca"
	cCerts      = "pki_certs"
	cCounter    = "pki_counter"
	cChallenges = "pki_challenges"
)

// MongoDepot implements the SCEP depot on MongoDB. With a tenant, tenants share the collections and every document carries the tenant (the same layout as the mdm storage backend's shared mode).
type MongoDepot struct {
	db  *mongo.Database
	tid string
}

// NewMongoDepot returns the depot. tenant may be empty (the database belongs to one tenant).
func NewMongoDepot(ctx context.Context, db *mongo.Database, tenant string) (*MongoDepot, error) {
	d := &MongoDepot{db: db, tid: tenant}
	lead := func(k bson.D) bson.D {
		if tenant == "" {
			return k
		}
		return append(bson.D{{Key: "t", Value: 1}}, k...)
	}
	if _, err := db.Collection(cCerts).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: lead(bson.D{{Key: "cn", Value: 1}})},
		{Keys: lead(bson.D{{Key: "serial", Value: 1}}), Options: options.Index().SetUnique(true)},
	}); err != nil {
		return nil, err
	}
	// Challenges expire on their own.
	if _, err := db.Collection(cChallenges).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *MongoDepot) key(id string) string {
	if d.tid == "" {
		return id
	}
	return d.tid + "\x1f" + id
}
func (d *MongoDepot) scope(f bson.D) bson.D {
	if d.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: d.tid}}, f...)
}
func (d *MongoDepot) stamp(f bson.D) bson.D {
	if d.tid == "" {
		return f
	}
	return append(f, bson.E{Key: "t", Value: d.tid})
}

// ---- the CA ----

// CAOptions describe a CA made on first start.
type CAOptions struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Years              int
	KeyBits            int
}

// EnsureCA makes the CA if there is none, and returns its certificate. The private key is stored encrypted under pass (empty pass stores it as is: only for development).
func (d *MongoDepot) EnsureCA(ctx context.Context, pass string, o CAOptions) (*x509.Certificate, error) {
	crt, _, err := d.CA([]byte(pass))
	if err == nil {
		return crt[0], nil
	}
	if !errors.Is(err, errNoCA) {
		return nil, err
	}
	if o.KeyBits == 0 {
		o.KeyBits = 2048
	}
	if o.Years == 0 {
		o.Years = 10
	}
	key, err := rsa.GenerateKey(rand.Reader, o.KeyBits)
	if err != nil {
		return nil, err
	}
	der, err := scepdepot.NewCACert(
		scepdepot.WithYears(o.Years), scepdepot.WithCommonName(o.CommonName), scepdepot.WithOrganization(o.Organization),
		scepdepot.WithOrganizationalUnit(o.OrganizationalUnit), scepdepot.WithCountry(o.Country),
	).SelfSign(rand.Reader, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	sealed, err := seal(x509.MarshalPKCS1PrivateKey(key), pass)
	if err != nil {
		return nil, err
	}
	_, err = d.db.Collection(cCA).InsertOne(ctx, d.stamp(bson.D{{Key: "_id", Value: d.key("ca")}, {Key: "cert_pem", Value: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, {Key: "key", Value: sealed}, {Key: "created_at", Value: time.Now().UTC()}}))
	if mongo.IsDuplicateKeyError(err) { // another instance made it first: use theirs
		crts, _, err := d.CA([]byte(pass))
		if err != nil {
			return nil, err
		}
		return crts[0], nil
	}
	return cert, err
}

var errNoCA = errors.New("no certificate authority yet")

// CA returns the CA certificate and key (the scep depot interface).
func (d *MongoDepot) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	var doc struct {
		Cert string `bson:"cert_pem"`
		Key  string `bson:"key"`
	}
	err := d.db.Collection(cCA).FindOne(context.Background(), bson.D{{Key: "_id", Value: d.key("ca")}}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil, errNoCA
	}
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode([]byte(doc.Cert))
	if block == nil {
		return nil, nil, errors.New("the stored CA certificate is not PEM")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	raw, err := open(doc.Key, string(pass))
	if err != nil {
		return nil, nil, fmt.Errorf("opening the CA key (wrong passphrase?): %w", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(raw)
	if err != nil {
		return nil, nil, err
	}
	return []*x509.Certificate{crt}, key, nil
}

// CertPEM is the CA certificate as PEM (public: it is what a device may be given to trust).
func (d *MongoDepot) CertPEM(ctx context.Context) (string, error) {
	var doc struct {
		Cert string `bson:"cert_pem"`
	}
	err := d.db.Collection(cCA).FindOne(ctx, bson.D{{Key: "_id", Value: d.key("ca")}}).Decode(&doc)
	return doc.Cert, err
}

// ---- issued certificates ----

// Serial returns the next serial number.
func (d *MongoDepot) Serial() (*big.Int, error) {
	var doc struct {
		N int64 `bson:"n"`
	}
	err := d.db.Collection(cCounter).FindOneAndUpdate(context.Background(), bson.D{{Key: "_id", Value: d.key("serial")}},
		bson.D{{Key: "$inc", Value: bson.D{{Key: "n", Value: 1}}}, {Key: "$setOnInsert", Value: d.stamp(bson.D{})}},
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)).Decode(&doc)
	if err != nil {
		return nil, err
	}
	return big.NewInt(doc.N), nil
}

// Put records an issued certificate.
func (d *MongoDepot) Put(name string, crt *x509.Certificate) error {
	_, err := d.db.Collection(cCerts).InsertOne(context.Background(), d.stamp(bson.D{
		{Key: "serial", Value: crt.SerialNumber.String()}, {Key: "cn", Value: crt.Subject.CommonName}, {Key: "name", Value: name}, {Key: "subject", Value: crt.Subject.String()},
		{Key: "not_before", Value: crt.NotBefore}, {Key: "not_after", Value: crt.NotAfter}, {Key: "cert_pem", Value: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw}))},
		{Key: "issued_at", Value: time.Now().UTC()}, {Key: "revoked", Value: false},
	}))
	return err
}

// HasCN, like the file depot's: with allowTime days or fewer as the renewal window, a certificate of the same name that still has longer than that to run is a refusal; with allowTime 0 (what MDM wants:
// a device that enrolls again gets a new identity, and the MDM layer decides whether it may) nothing is refused. revokeOld marks the earlier certificates of the name revoked.
func (d *MongoDepot) HasCN(_ string, allowTime int, cert *x509.Certificate, revokeOld bool) (bool, error) {
	ctx := context.Background()
	f := d.scope(bson.D{{Key: "cn", Value: cert.Subject.CommonName}, {Key: "revoked", Value: false}, {Key: "serial", Value: bson.D{{Key: "$ne", Value: cert.SerialNumber.String()}}}})
	if allowTime > 0 {
		n, err := d.db.Collection(cCerts).CountDocuments(ctx, append(f, bson.E{Key: "not_after", Value: bson.D{{Key: "$gt", Value: time.Now().AddDate(0, 0, allowTime)}}}), options.Count().SetLimit(1))
		if err != nil {
			return false, err
		}
		if n > 0 {
			return false, errors.New("DN " + cert.Subject.String() + " already exists")
		}
	}
	if revokeOld {
		if _, err := d.db.Collection(cCerts).UpdateMany(ctx, f, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}, {Key: "revoked_at", Value: time.Now().UTC()}}}}); err != nil {
			return false, err
		}
	}
	return true, nil
}

// ---- challenge passwords (scep challenge.Store) ----

// ChallengeStore hands out one-use challenge passwords that expire.
type ChallengeStore struct {
	d   *MongoDepot
	ttl time.Duration
}

// Challenges returns the challenge store; a challenge lives ttl (default 24 hours) and works once.
func (d *MongoDepot) Challenges(ttl time.Duration) *ChallengeStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &ChallengeStore{d: d, ttl: ttl}
}

// SCEPChallenge makes a new challenge password.
func (c *ChallengeStore) SCEPChallenge() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	pw := base64.RawURLEncoding.EncodeToString(b)
	// Only a hash of the challenge is stored: a copy of the database cannot be used to enroll a device.
	_, err := c.d.db.Collection(cChallenges).InsertOne(context.Background(), c.d.stamp(bson.D{{Key: "_id", Value: c.d.key(challengeHash(pw))}, {Key: "expires_at", Value: time.Now().Add(c.ttl)}}))
	return pw, err
}

func challengeHash(pw string) string {
	h := sha256.Sum256([]byte("fleetcore-challenge\x00" + pw))
	return hex.EncodeToString(h[:])
}

// HasChallenge reports whether pw is a live challenge, and uses it up.
func (c *ChallengeStore) HasChallenge(pw string) (bool, error) {
	if pw == "" {
		return false, nil
	}
	err := c.d.db.Collection(cChallenges).FindOneAndDelete(context.Background(), bson.D{{Key: "_id", Value: c.d.key(challengeHash(pw))}, {Key: "expires_at", Value: bson.D{{Key: "$gt", Value: time.Now()}}}}).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return false, nil
	}
	return err == nil, err
}

// ---- sealing the CA key ----

// seal encrypts b under a passphrase (scrypt and AES-256-GCM); an empty passphrase stores it marked as plain.
func seal(b []byte, pass string) (string, error) {
	if pass == "" {
		return "plain:" + base64.StdEncoding.EncodeToString(b), nil
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	k, err := scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return "aesgcm:" + base64.StdEncoding.EncodeToString(append(append(salt, nonce...), g.Seal(nil, nonce, b, nil)...)), nil
}

func open(s, pass string) ([]byte, error) {
	switch {
	case strings.HasPrefix(s, "plain:"):
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "plain:"))
	case strings.HasPrefix(s, "aesgcm:"):
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "aesgcm:"))
		if err != nil || len(raw) < 16+12 {
			return nil, errors.New("malformed")
		}
		k, err := scrypt.Key([]byte(pass), raw[:16], 1<<15, 8, 1, 32)
		if err != nil {
			return nil, err
		}
		blk, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		return g.Open(nil, raw[16:16+g.NonceSize()], raw[16+g.NonceSize():], nil)
	}
	return nil, errors.New("unknown key format")
}

// Seal and Open protect secrets kept beside the CA (DEP tokens, keys) with the same passphrase scheme as the CA key.
func Seal(b []byte, pass string) (string, error) { return seal(b, pass) }
func Open(s, pass string) ([]byte, error)        { return open(s, pass) }
