package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/storage/mongodb"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, cn string) *testCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &testCA{c, key, pool}
}

func (ca *testCA) client(t *testing.T, cn string) *tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The management API of a tenant's server is reached with a client certificate from an admin CA (and the API key too, when one is set): nothing else gets in, and the call is logged.
func TestAdminAPIMutualTLS(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	mc, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Disconnect(ctx)
	db := mc.Database("fleetcore_admin_test")
	db.Drop(ctx)
	defer db.Drop(ctx)
	store, err := mongodb.New(ctx, mongodb.WithClient(mc), mongodb.WithDatabase("fleetcore_admin_test"))
	if err != nil {
		t.Fatal(err)
	}
	admin, stranger := newTestCA(t, "admin ca"), newTestCA(t, "someone else")

	for _, withKey := range []bool{false, true} {
		cfg := Config{BaseURL: "https://mdm.test", Organization: "Test", Storage: store, PKIDB: db, CAPass: "p", CertSource: CertFromTLS, AdminCA: admin.pool, Version: "test", NoFeeds: true}
		if withKey {
			cfg.APIKey = "secret"
		}
		srv, err := New(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewUnstartedServer(srv.Handler)
		ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
		ts.StartTLS()
		get := func(cert *tls.Certificate, key string) int {
			cfg := &tls.Config{InsecureSkipVerify: true}
			if cert != nil {
				cfg.Certificates = []tls.Certificate{*cert}
			}
			req, _ := http.NewRequest("GET", ts.URL+"/v1/commands/types", nil)
			if key != "" {
				req.SetBasicAuth("fleetcore", key)
			}
			r, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			r.Body.Close()
			return r.StatusCode
		}
		good, bad := admin.client(t, "operator"), stranger.client(t, "operator")
		if code := get(nil, "secret"); code != 401 {
			t.Errorf("key %v: no certificate got %d", withKey, code)
		}
		if code := get(bad, "secret"); code != 401 {
			t.Errorf("key %v: a certificate from another CA got %d", withKey, code)
		}
		if withKey {
			if code := get(good, ""); code != 401 {
				t.Errorf("a valid certificate without the key got %d", code)
			}
			if code := get(good, "wrong"); code != 401 {
				t.Errorf("a valid certificate with the wrong key got %d", code)
			}
			if code := get(good, "secret"); code != 200 {
				t.Errorf("certificate and key got %d", code)
			}
		} else if code := get(good, ""); code != 200 {
			t.Errorf("a certificate from the admin CA got %d", code)
		}
		ts.Close()
	}
}
