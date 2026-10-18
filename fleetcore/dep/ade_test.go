package dep

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanodep/client"
	nanolog "github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/fleetcore/enroll"
	"github.com/smallstep/pkcs7"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type chain struct {
	root  *x509.Certificate
	inter *x509.Certificate
	leaf  *x509.Certificate
	key   crypto.PrivateKey
}

func mkCert(t *testing.T, cn string, parent *x509.Certificate, parentKey crypto.PrivateKey, ca bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true}
	if ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	signerCert, signerKey := tmpl, any(key)
	if parent != nil {
		signerCert, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func deviceChain(t *testing.T) chain {
	root, rkey := mkCert(t, "Test Apple Root", nil, nil, true)
	inter, ikey := mkCert(t, "Test Apple iPhone Device CA", root, rkey, true)
	leaf, lkey := mkCert(t, "device", inter, ikey, false)
	return chain{root, inter, leaf, lkey}
}

func (c chain) sign(t *testing.T, content string) []byte {
	sd, err := pkcs7.NewSignedData([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSignerChain(c.leaf, c.key, []*x509.Certificate{c.inter}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type onePW struct{ n int }

func (o *onePW) SCEPChallenge() (string, error) { o.n++; return "chal", nil }

func TestAppleRootsLoad(t *testing.T) {
	if n := len(AppleRoots().Subjects()); n != 1 {
		t.Fatalf("expected Apple's root, got %d certificates", n)
	}
}

// A device Apple assigned to this server gets its enrollment profile with nothing but the proof of what it is; any other device gets nothing.
func TestADEEnrollmentSkipsTheCode(t *testing.T) {
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
	db := mc.Database("fleetcore_ade_test")
	db.Drop(ctx)
	defer db.Drop(ctx)
	store, _ := New(ctx, db, "acme", "")
	svc, _ := NewService(ctx, db, store, "acme", nanolog.NopLogger)
	// Apple assigned one device
	svc.record(ctx, "org", fetched("C02ASSIGNED"))

	good := deviceChain(t)
	pw := &onePW{}
	ade := &ADE{Roots: poolOf(good.root), Service: svc, Challenges: pw, Profile: enroll.Options{Organization: "Example", Identifier: "com.example.ade", ServerURL: "https://mdm.example.com/mdm", SCEPURL: "https://mdm.example.com/scep", Topic: "com.apple.mgmt.External.x"}}
	var enrolling []string
	ade.OnEnroll = func(_ context.Context, serial, udid, name string) { enrolling = append(enrolling, serial+"/"+name) }
	srv := httptest.NewServer(ade.Handler())
	defer srv.Close()
	post := func(body []byte) (int, string) {
		r, err := http.Post(srv.URL, "application/pkcs7-signature", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	req := func(serial string) string {
		return `<?xml version="1.0"?><plist version="1.0"><dict><key>SERIAL</key><string>` + serial + `</string><key>UDID</key><string>UDID-1</string><key>PRODUCT</key><string>Mac15,6</string><key>VERSION</key><string>24A335</string></dict></plist>`
	}

	if code, b := post(good.sign(t, req("C02ASSIGNED"))); code != 200 || !strings.Contains(b, "com.apple.security.scep") || !strings.Contains(b, "chal") {
		t.Fatalf("an assigned device: %d %.200s", code, b)
	}
	if len(enrolling) != 1 || enrolling[0] != "C02ASSIGNED/org" {
		t.Errorf("enrolling: %v", enrolling)
	}
	if code, _ := post(good.sign(t, req("C02STRANGER"))); code != 403 {
		t.Errorf("a device Apple did not assign got %d", code)
	}
	other := deviceChain(t) // signed by a root we do not trust
	if code, _ := post(other.sign(t, req("C02ASSIGNED"))); code != 401 {
		t.Errorf("a request signed under another root got %d", code)
	}
	signed := good.sign(t, req("C02ASSIGNED"))
	tampered := bytes.Replace(signed, []byte("C02ASSIGNED"), []byte("C02STRANGEXX"), 1)
	if code, _ := post(tampered); code == 200 {
		t.Error("a tampered request was accepted")
	}
	if code, _ := post([]byte("not pkcs7")); code != 400 {
		t.Errorf("garbage got %d", code)
	}
	if code, _ := post(nil); code != 400 {
		t.Errorf("an empty body got %d", code)
	}
	if pw.n != 1 {
		t.Errorf("%d challenges were made, want 1 (refused requests must not make one)", pw.n)
	}
}

func poolOf(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

// Defining a DEP profile from typed fields, with safe defaults, and assigning it.
func TestDefineProfile(t *testing.T) {
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
	db := mc.Database("fleetcore_defprofile_test")
	db.Drop(ctx)
	defer db.Drop(ctx)
	var defined map[string]any
	var assigned map[string]any
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/session":
			io.WriteString(w, `{"auth_session_token":"tok"}`)
		case r.URL.Path == "/profile" && r.Method == "POST":
			_ = json.NewDecoder(r.Body).Decode(&defined)
			io.WriteString(w, `{"profile_uuid":"PROFILE-1","devices":{}}`)
		case r.URL.Path == "/profile/devices":
			_ = json.NewDecoder(r.Body).Decode(&assigned)
			io.WriteString(w, `{"profile_uuid":"PROFILE-1","devices":{"C02A":"SUCCESS","C02B":"NOT_ACCESSIBLE"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()
	store, _ := New(ctx, db, "", "")
	svc, _ := NewService(ctx, db, store, "", nanolog.NopLogger)
	svc.EnrollURL = "https://mdm.example.com/enroll/ade"
	_ = store.StoreConfig(ctx, "org", &client.Config{BaseURL: fake.URL})
	_ = store.StoreAuthTokens(ctx, "org", &client.OAuth1Tokens{ConsumerKey: "a", ConsumerSecret: "b", AccessToken: "c", AccessSecret: "d", AccessTokenExpiry: time.Now().Add(time.Hour)})
	svc.record(ctx, "org", fetched("C02A", "C02B"))

	res, err := svc.DefineProfile(ctx, "org", ProfileSpec{Name: "Standard", SkipSetupItems: []string{"Siri", "Welcome", "BrandNewPane"}, AssignExisting: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.ProfileUUID != "PROFILE-1" || len(res.UnknownPanes) != 1 || res.UnknownPanes[0] != "BrandNewPane" || res.Assigned != 1 || len(res.NotAssigned) != 1 || res.NotAssigned[0] != "C02B" {
		t.Errorf("result: %+v", res)
	}
	// safe defaults: supervised, mandatory, not removable, held in Setup Assistant; the enrollment URL is ours
	for k, want := range map[string]any{"is_supervised": true, "is_mandatory": true, "is_mdm_removable": false, "await_device_configured": true, "url": "https://mdm.example.com/enroll/ade", "profile_name": "Standard"} {
		if defined[k] != want {
			t.Errorf("%s: got %v want %v", k, defined[k], want)
		}
	}
	if u, _, _ := store.RetrieveAssignerProfile(ctx, "org"); u != "PROFILE-1" {
		t.Errorf("the profile was not made the one new devices get: %q", u)
	}
	if sup, await := svc.ProfileFacts(ctx, "org"); !sup || !await {
		t.Errorf("facts: %v %v", sup, await)
	}
	// a profile for devices that are not supervised is remembered as such
	f := false
	if _, err := svc.DefineProfile(ctx, "org", ProfileSpec{Name: "BYO", Supervised: &f}); err != nil {
		t.Fatal(err)
	}
	if sup, _ := svc.ProfileFacts(ctx, "org"); sup {
		t.Error("an unsupervised profile is remembered as supervised")
	}
	if _, err := svc.DefineProfile(ctx, "org", ProfileSpec{}); err == nil {
		t.Error("a profile without a name was accepted")
	}
	_ = assigned
	_ = bson.D{}
}
