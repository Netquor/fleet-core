package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/micromdm/nanomdm/fleetcore/pki"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ---- a pretend Apple: a root, an intermediate and the leaf a device would hold ----

type pretendApple struct {
	root  *x509.Certificate
	rkey  *ecdsa.PrivateKey
	inter *x509.Certificate
	ikey  *ecdsa.PrivateKey
}

func mk(t *testing.T, cn string, tmplExtra func(*x509.Certificate), parent *x509.Certificate, pkey *ecdsa.PrivateKey, ca bool, key *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	if key == nil {
		key, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true}
	if ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	if tmplExtra != nil {
		tmplExtra(tmpl)
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, pkey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func newApple(t *testing.T) *pretendApple {
	root, rkey := mk(t, "Pretend Apple Enterprise Attestation Root CA", nil, nil, nil, true, nil)
	inter, ikey := mk(t, "Pretend Apple Enterprise Attestation Sub CA", nil, root, rkey, true, nil)
	return &pretendApple{root, rkey, inter, ikey}
}

func (a *pretendApple) pool() *x509.CertPool { p := x509.NewCertPool(); p.AddCert(a.root); return p }

func ext(oid asn1.ObjectIdentifier, v []byte) pkix.Extension {
	return pkix.Extension{Id: oid, Value: v}
}

func utf8(s string) []byte { b, _ := asn1.MarshalWithParams(s, "utf8"); return b }

// attest builds what a device sends for a challenge: its hardware key's attestation, with the serial, UDID and the nonce for this key authorization.
func (a *pretendApple) attest(t *testing.T, devKey *ecdsa.PrivateKey, serial, udid, keyAuth string) string {
	h := sha256.Sum256([]byte(keyAuth))
	nonce, _ := asn1.Marshal(h[:])
	leaf, _ := mk(t, "attested key", func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{ext(oidSerial, utf8(serial)), ext(oidUDID, utf8(udid)), ext(oidNonce, nonce)}
	}, a.inter, a.ikey, false, devKey)
	obj := map[string]any{"fmt": "apple", "attStmt": map[string]any{"x5c": [][]byte{leaf.Raw, a.inter.Raw}}}
	b, err := cbor.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- a small ACME client ----

type client struct {
	t    *testing.T
	srv  *httptest.Server
	key  *ecdsa.PrivateKey
	kid  string
	base string
}

func (c *client) nonce() string {
	r, err := http.Head(c.srv.URL + "/acme/new-nonce")
	if err != nil {
		c.t.Fatal(err)
	}
	r.Body.Close()
	return r.Header.Get("Replay-Nonce")
}

func (c *client) jwkMap() map[string]string {
	pad := func(b *big.Int) string {
		x := make([]byte, 32)
		b.FillBytes(x)
		return base64.RawURLEncoding.EncodeToString(x)
	}
	return map[string]string{"kty": "EC", "crv": "P-256", "x": pad(c.key.X), "y": pad(c.key.Y)}
}

func (c *client) post(url string, payload any, nonce string, useJWK bool) (*http.Response, []byte) {
	prot := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
	if useJWK {
		prot["jwk"] = c.jwkMap()
	} else {
		prot["kid"] = c.kid
	}
	pb, _ := json.Marshal(prot)
	var payloadB64 string
	if payload != nil {
		p, _ := json.Marshal(payload)
		payloadB64 = base64.RawURLEncoding.EncodeToString(p)
	}
	protB64 := base64.RawURLEncoding.EncodeToString(pb)
	h := sha256.Sum256([]byte(protB64 + "." + payloadB64))
	r, s, _ := ecdsa.Sign(rand.Reader, c.key, h[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	body, _ := json.Marshal(map[string]string{"protected": protB64, "payload": payloadB64, "signature": base64.RawURLEncoding.EncodeToString(sig)})
	resp, err := http.Post(url, "application/jose+json", bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// call posts with a fresh nonce.
func (c *client) call(path string, payload any) (*http.Response, map[string]any) {
	resp, b := c.post(c.srv.URL+path, payload, c.nonce(), false)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp, m
}

func (c *client) thumb() string {
	return jwk{Kty: "EC", Crv: "P-256", X: c.jwkMap()["x"], Y: c.jwkMap()["y"]}.thumbprint()
}

func setup(t *testing.T, authorize func(context.Context, Identifier) error) (*client, *pretendApple, *Server, func(string) string) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	mc, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mc.Disconnect(context.Background()) })
	db := mc.Database("fleetcore_acme_test")
	db.Drop(ctx)
	t.Cleanup(func() { db.Drop(context.Background()) })
	st, err := NewStore(ctx, db, "acme")
	if err != nil {
		t.Fatal(err)
	}
	depot, err := pki.NewMongoDepot(ctx, db, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := depot.EnsureCA(ctx, "pw", pki.CAOptions{CommonName: "Test CA", Organization: "Example"}); err != nil {
		t.Fatal(err)
	}
	apple := newApple(t)
	s := &Server{Store: st, Issuer: &CAIssuer{Depot: depot, Pass: "pw", Organization: "Example"}, Roots: apple.pool(), Authorize: authorize}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	s.BaseURL = ts.URL
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &client{t: t, srv: ts, key: key}
	// register the account
	resp, b := c.post(ts.URL+"/acme/new-account", map[string]any{"termsOfServiceAgreed": true}, c.nonce(), true)
	if resp.StatusCode != 201 {
		t.Fatalf("new-account: %d %s", resp.StatusCode, b)
	}
	c.kid = resp.Header.Get("Location")
	caPEM := func(chain string) string { return chain }
	return c, apple, s, caPEM
}

func (c *client) order(serial string) (orderURL string, o map[string]any, resp *http.Response) {
	resp, b := c.post(c.srv.URL+"/acme/new-order", map[string]any{"identifiers": []map[string]string{{"type": "permanent-identifier", "value": serial}}}, c.nonce(), false)
	_ = json.Unmarshal(b, &o)
	return resp.Header.Get("Location"), o, resp
}

func (c *client) csr(key *ecdsa.PrivateKey) string {
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}, key)
	return base64.RawURLEncoding.EncodeToString(der)
}

func path(c *client, url string) string { return strings.TrimPrefix(url, c.srv.URL) }

// A device proves what it is with a certificate chain from Apple, and gets an identity certificate for the key it holds in hardware.
func TestDeviceAttestationIssuesACertificate(t *testing.T) {
	c, apple, s, _ := setup(t, func(_ context.Context, id Identifier) error {
		if id.Value != "C02ASSIGNED" {
			return errors.New("not assigned")
		}
		return nil
	})
	devKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	// not assigned: no order
	if _, _, resp := c.order("C02STRANGER"); resp.StatusCode != 403 {
		t.Fatalf("an unassigned device got an order: %d", resp.StatusCode)
	}
	orderURL, o, resp := c.order("C02ASSIGNED")
	if resp.StatusCode != 201 || o["status"] != "pending" {
		t.Fatalf("order: %d %v", resp.StatusCode, o)
	}
	authzURL := o["authorizations"].([]any)[0].(string)
	_, az := c.call(path(c, authzURL), nil)
	ch := az["challenges"].([]any)[0].(map[string]any)
	if ch["type"] != "device-attest-01" {
		t.Fatalf("challenge: %v", ch)
	}
	token := ch["token"].(string)
	chURL := path(c, ch["url"].(string))

	// finalizing before the device is attested is refused
	if resp, _ := c.call(path(c, o["finalize"].(string)), map[string]any{"csr": c.csr(devKey)}); resp.StatusCode != 403 {
		t.Errorf("finalize before attestation: %d", resp.StatusCode)
	}
	keyAuth := token + "." + c.thumb()

	// attestations that are not good enough
	other := newApple(t) // a root nobody trusts
	for name, att := range map[string]string{
		"untrusted root":    other.attest(t, devKey, "C02ASSIGNED", "UDID", keyAuth),
		"another challenge": apple.attest(t, devKey, "C02ASSIGNED", "UDID", "some-other-token."+c.thumb()),
		"another device":    apple.attest(t, devKey, "C02OTHER", "UDID", keyAuth),
	} {
		if resp, _ := c.call(chURL, map[string]any{"attObj": att}); resp.StatusCode != 403 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
		// a failed attempt closes the authorization: a fresh order is needed
		orderURL, o, _ = c.order("C02ASSIGNED")
		_, az = c.call(path(c, o["authorizations"].([]any)[0].(string)), nil)
		ch = az["challenges"].([]any)[0].(map[string]any)
		token, chURL = ch["token"].(string), path(c, ch["url"].(string))
		keyAuth = token + "." + c.thumb()
	}
	if resp, _ := c.call(chURL, map[string]any{"attObj": "!!not base64!!"}); resp.StatusCode != 400 {
		t.Errorf("garbage attObj: %d", resp.StatusCode)
	}
	// a good one
	if resp, m := c.call(chURL, map[string]any{"attObj": apple.attest(t, devKey, "C02ASSIGNED", "UDID-1", keyAuth)}); resp.StatusCode != 200 || m["status"] != "valid" {
		t.Fatalf("attestation: %d %v", resp.StatusCode, m)
	}
	if _, m := c.call(path(c, orderURL), nil); m["status"] != "ready" {
		t.Fatalf("order after attestation: %v", m)
	}
	// a CSR for another key is refused: the certificate is for the attested key only
	otherKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if resp, _ := c.call(path(c, o["finalize"].(string)), map[string]any{"csr": c.csr(otherKey)}); resp.StatusCode != 400 {
		t.Errorf("a CSR for a key that was not attested: %d", resp.StatusCode)
	}
	resp, fin := c.call(path(c, o["finalize"].(string)), map[string]any{"csr": c.csr(devKey)})
	if resp.StatusCode != 200 || fin["status"] != "valid" || fin["certificate"] == nil {
		t.Fatalf("finalize: %d %v", resp.StatusCode, fin)
	}
	r2, b := c.post(fin["certificate"].(string), nil, c.nonce(), false)
	if r2.StatusCode != 200 || r2.Header.Get("Content-Type") != "application/pem-certificate-chain" {
		t.Fatalf("certificate: %d %s", r2.StatusCode, r2.Header.Get("Content-Type"))
	}
	blk, rest := pem.Decode(b)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caBlk, _ := pem.Decode(rest)
	ca, _ := x509.ParseCertificate(caBlk.Bytes)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the identity does not verify against the server's CA: %v", err)
	}
	if leaf.Subject.CommonName != "C02ASSIGNED" || !publicKeysEqual(leaf.PublicKey, &devKey.PublicKey) {
		t.Errorf("subject %q, key matches: %v", leaf.Subject.CommonName, publicKeysEqual(leaf.PublicKey, &devKey.PublicKey))
	}
	_ = s
}

func poolOf(c *x509.Certificate) *x509.CertPool { p := x509.NewCertPool(); p.AddCert(c); return p }

func publicKeysEqual(a, b any) bool {
	x, _ := x509.MarshalPKIXPublicKey(a)
	y, _ := x509.MarshalPKIXPublicKey(b)
	return bytes.Equal(x, y)
}

// The protocol is strict: every request is signed, uses a nonce once, and names its url.
func TestACMEProtocolRules(t *testing.T) {
	c, _, _, _ := setup(t, nil)
	// a nonce is good once
	n := c.nonce()
	if resp, _ := c.post(c.srv.URL+"/acme/new-order", map[string]any{"identifiers": []map[string]string{{"type": "permanent-identifier", "value": "X"}}}, n, false); resp.StatusCode != 201 {
		t.Fatalf("first use: %d", resp.StatusCode)
	}
	resp, b := c.post(c.srv.URL+"/acme/new-order", map[string]any{"identifiers": []map[string]string{{"type": "permanent-identifier", "value": "X"}}}, n, false)
	if resp.StatusCode != 400 || !strings.Contains(string(b), "badNonce") || resp.Header.Get("Replay-Nonce") == "" {
		t.Errorf("a spent nonce: %d %s", resp.StatusCode, b)
	}
	// a signature for another url does not work here
	body := func(url string) []byte {
		prot, _ := json.Marshal(map[string]any{"alg": "ES256", "nonce": c.nonce(), "url": url, "kid": c.kid})
		pb := base64.RawURLEncoding.EncodeToString(prot)
		h := sha256.Sum256([]byte(pb + "."))
		r, s, _ := ecdsa.Sign(rand.Reader, c.key, h[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		out, _ := json.Marshal(map[string]string{"protected": pb, "payload": "", "signature": base64.RawURLEncoding.EncodeToString(sig)})
		return out
	}
	r2, _ := http.Post(c.srv.URL+"/acme/new-order", "application/jose+json", bytes.NewReader(body(c.srv.URL+"/acme/new-account")))
	if r2.StatusCode != 401 {
		t.Errorf("a request signed for another url: %d", r2.StatusCode)
	}
	// a request signed by someone else's key under this account is refused
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sc := &client{t: t, srv: c.srv, key: stranger, kid: c.kid}
	if resp, _ := sc.post(c.srv.URL+"/acme/new-order", map[string]any{"identifiers": []map[string]string{{"type": "permanent-identifier", "value": "X"}}}, c.nonce(), false); resp.StatusCode != 401 {
		t.Errorf("a stranger using the account's kid: %d", resp.StatusCode)
	}
	// unsupported identifiers
	if resp, _ := c.call("/acme/new-order", map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}}}); resp.StatusCode != 400 {
		t.Errorf("a dns identifier: %d", resp.StatusCode)
	}
	// the directory
	r3, _ := http.Get(c.srv.URL + "/acme/directory")
	var dir map[string]any
	json.NewDecoder(r3.Body).Decode(&dir)
	if dir["newOrder"] == nil || dir["newNonce"] == nil || dir["newAccount"] == nil {
		t.Errorf("directory: %v", dir)
	}
	// accounts: the same key finds the same account
	resp, _ = c.post(c.srv.URL+"/acme/new-account", map[string]any{}, c.nonce(), true)
	if resp.StatusCode != 200 || resp.Header.Get("Location") != c.kid {
		t.Errorf("registering the same key again: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAppleRootLoads(t *testing.T) {
	if n := len(AppleAttestationRoots().Subjects()); n != 1 {
		t.Fatalf("%d certificates", n)
	}
}
