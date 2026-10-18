package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	kitlog "github.com/go-kit/kit/log"
	"github.com/micromdm/nanomdm/storage/mongodb"
	"github.com/micromdm/plist"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/micromdm/scep/v2/cryptoutil/x509util"
	"github.com/smallstep/scep"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// A device enrolls with nothing but this one process: it downloads the profile, gets its identity certificate from the SCEP service, then checks in over TLS with that certificate,
// receives a queued command and acknowledges it.
//
//	NANOMDM_MONGODB_STORAGE_TEST_URI='mongodb://127.0.0.1:27117/?replicaSet=rs0' go test ./fleetcore/server
func TestEnrollEndToEnd(t *testing.T) {
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
	db := mc.Database("fleetcore_test")
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := mongodb.New(ctx, mongodb.WithClient(mc), mongodb.WithDatabase("fleetcore_test"))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(ctx, Config{
		BaseURL: "https://mdm.test", Organization: "Test Org", ProfileIdentifier: "test.mdm.enroll", Topic: "com.apple.mgmt.External.test",
		Storage: store, PKIDB: db, CAPass: "correct horse", CertSource: CertFromTLS, APIKey: "apikey", Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv.Handler)
	ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	defer ts.Close()
	insecure := &tls.Config{InsecureSkipVerify: true}
	// The SCEP client uses the default transport; the server's certificate is a throwaway one.
	old := http.DefaultTransport
	http.DefaultTransport = &http.Transport{TLSClientConfig: insecure}
	defer func() { http.DefaultTransport = old }()

	// 1. The profile.
	resp, err := http.Get(ts.URL + "/enroll")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Fatalf("profile: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var prof struct {
		PayloadContent []map[string]interface{}
	}
	if err := plist.Unmarshal(body, &prof); err != nil {
		t.Fatal(err)
	}
	var scepPayload, mdmPayload map[string]interface{}
	for _, p := range prof.PayloadContent {
		switch p["PayloadType"] {
		case "com.apple.security.scep":
			scepPayload = p["PayloadContent"].(map[string]interface{})
		case "com.apple.mdm":
			mdmPayload = p
		}
	}
	if scepPayload == nil || mdmPayload == nil || mdmPayload["Topic"] != "com.apple.mgmt.External.test" || mdmPayload["ServerURL"] != "https://mdm.test/mdm" || scepPayload["URL"] != "https://mdm.test/scep" {
		t.Fatalf("the profile is not what a device needs: %v", prof)
	}
	challenge, _ := scepPayload["Challenge"].(string)
	if challenge == "" {
		t.Fatal("no challenge in the profile")
	}

	// 2. The device asks for its identity (the profile's URLs are for the public name; the test talks to the test server).
	const udid = "11111111-2222-3333-4444-555555555555"
	enrollIdentity := func(challenge string) (*tls.Certificate, error) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		csrDER, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
			CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: udid, Organization: []string{"Test Org"}}, SignatureAlgorithm: x509.SHA256WithRSA},
			ChallengePassword:  challenge,
		}, key)
		if err != nil {
			return nil, err
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, err
		}
		self := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: csr.Subject, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		selfDER, err := x509.CreateCertificate(rand.Reader, self, self, key.Public(), key)
		if err != nil {
			return nil, err
		}
		selfCert, _ := x509.ParseCertificate(selfDER)
		c, err := scepclient.New(ts.URL+"/scep", kitlog.NewNopLogger())
		if err != nil {
			return nil, err
		}
		caResp, n, err := c.GetCACert(ctx, "")
		if err != nil {
			return nil, err
		}
		var caCerts []*x509.Certificate
		if n > 1 {
			caCerts, err = scep.CACerts(caResp)
		} else {
			caCerts, err = x509.ParseCertificates(caResp)
		}
		if err != nil {
			return nil, err
		}
		msg, err := scep.NewCSRRequest(csr, &scep.PKIMessage{MessageType: scep.PKCSReq, Recipients: caCerts, SignerKey: key, SignerCert: selfCert, CSRReqMessage: &scep.CSRReqMessage{ChallengePassword: challenge}})
		if err != nil {
			return nil, err
		}
		raw, err := c.PKIOperation(ctx, msg.Raw)
		if err != nil {
			return nil, err
		}
		rm, err := scep.ParsePKIMessage(raw, scep.WithCACerts(caCerts))
		if err != nil {
			return nil, err
		}
		if rm.PKIStatus != scep.SUCCESS {
			return nil, &scepFailure{rm.FailInfo.String()}
		}
		if err := rm.DecryptPKIEnvelope(selfCert, key); err != nil {
			return nil, err
		}
		return &tls.Certificate{Certificate: [][]byte{rm.CertRepMessage.Certificate.Raw}, PrivateKey: key, Leaf: rm.CertRepMessage.Certificate}, nil
	}
	id, err := enrollIdentity(challenge)
	if err != nil {
		t.Fatalf("scep: %v", err)
	}
	if id.Leaf.Subject.CommonName != udid {
		t.Errorf("identity names %q", id.Leaf.Subject.CommonName)
	}
	if _, err := id.Leaf.Verify(x509.VerifyOptions{Roots: srv.CAPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the identity does not verify against the server's CA: %v", err)
	}
	if _, err := enrollIdentity(challenge); err == nil {
		t.Error("a challenge worked twice")
	}
	if _, err := enrollIdentity("not-a-challenge"); err == nil {
		t.Error("a wrong challenge worked")
	}

	// 3. MDM over TLS with that identity.
	post := func(path, ct string, cert *tls.Certificate, body string, basic bool) (int, string) {
		cfg := &tls.Config{InsecureSkipVerify: true}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		if basic {
			req.SetBasicAuth("fleetcore", "apikey")
		}
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	const checkin, mdmCT = "application/x-apple-aspen-mdm-checkin", "application/x-apple-aspen-mdm"
	authenticate := `<?xml version="1.0"?><plist version="1.0"><dict><key>BuildVersion</key><string>24A335</string><key>MessageType</key><string>Authenticate</string><key>OSVersion</key><string>15.0</string><key>ProductName</key><string>Mac15,6</string><key>SerialNumber</key><string>C02TEST</string><key>Topic</key><string>com.apple.mgmt.External.test</string><key>UDID</key><string>` + udid + `</string></dict></plist>`
	tokenUpdate := `<?xml version="1.0"?><plist version="1.0"><dict><key>MessageType</key><string>TokenUpdate</string><key>PushMagic</key><string>magic-123</string><key>Token</key><data>AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=</data><key>Topic</key><string>com.apple.mgmt.External.test</string><key>UDID</key><string>` + udid + `</string></dict></plist>`

	if code, _ := post("/mdm", checkin, nil, authenticate, false); code < 400 || code >= 500 {
		t.Errorf("a check-in without a certificate got %d, want a 4xx refusal", code)
	}
	strangerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	strangerTmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: udid}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	strangerDER, _ := x509.CreateCertificate(rand.Reader, strangerTmpl, strangerTmpl, strangerKey.Public(), strangerKey)
	stranger := &tls.Certificate{Certificate: [][]byte{strangerDER}, PrivateKey: strangerKey}
	if code, _ := post("/mdm", checkin, stranger, authenticate, false); code < 400 || code >= 500 {
		t.Errorf("a certificate from another CA got %d, want a 4xx refusal", code)
	}
	if code, b := post("/mdm", checkin, id, authenticate, false); code != 200 {
		t.Fatalf("Authenticate: %d %s", code, b)
	}
	if code, b := post("/mdm", checkin, id, tokenUpdate, false); code != 200 {
		t.Fatalf("TokenUpdate: %d %s", code, b)
	}
	// The same identity cannot speak for another device.
	other := strings.ReplaceAll(authenticate, udid, "99999999-2222-3333-4444-555555555555")
	if code, _ := post("/mdm", checkin, id, other, false); code == 200 {
		t.Error("an identity enrolled a different device")
	}

	// 4. A command through the API, picked up by the device and acknowledged.
	cmd := `<?xml version="1.0"?><plist version="1.0"><dict><key>CommandUUID</key><string>CMD-1</string><key>Command</key><dict><key>RequestType</key><string>DeviceInformation</string></dict></dict></plist>`
	if code, b := post("/v1/enqueue/"+udid+"?nopush=1", "application/xml", nil, cmd, true); code != 200 && code != 201 && code != 204 {
		t.Fatalf("enqueue: %d %s", code, b)
	}
	idle := `<?xml version="1.0"?><plist version="1.0"><dict><key>Status</key><string>Idle</string><key>UDID</key><string>` + udid + `</string></dict></plist>`
	code, b := post("/mdm", mdmCT, id, idle, false)
	if code != 200 || !bytes.Contains([]byte(b), []byte("CMD-1")) {
		t.Fatalf("the device was not handed its command: %d %s", code, b)
	}
	ack := `<?xml version="1.0"?><plist version="1.0"><dict><key>CommandUUID</key><string>CMD-1</string><key>Status</key><string>Acknowledged</string><key>UDID</key><string>` + udid + `</string></dict></plist>`
	if code, b := post("/mdm", mdmCT, id, ack, false); code != 200 {
		t.Fatalf("acknowledge: %d %s", code, b)
	}
	if code, b := post("/mdm", mdmCT, id, idle, false); code != 200 || bytes.Contains([]byte(b), []byte("CMD-1")) {
		t.Errorf("the command came again after it was acknowledged: %d %s", code, b)
	}

	// 5. The management API wants its key; the CA certificate is public.
	if code, _ := post("/v1/enqueue/"+udid, "application/xml", nil, cmd, false); code != 401 {
		t.Errorf("the API without a key got %d, want 401", code)
	}
	r, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: insecure}}).Get(ts.URL + "/ca.pem")
	if err != nil || r.StatusCode != 200 {
		t.Errorf("ca.pem: %v", err)
	}
}

type scepFailure struct{ info string }

func (e *scepFailure) Error() string { return "SCEP failed: " + e.info }
