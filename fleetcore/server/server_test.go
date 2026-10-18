package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	kitlog "github.com/go-kit/kit/log"
	"github.com/micromdm/nanomdm/fleetcore/seal"
	"github.com/micromdm/nanomdm/fleetcore/tenantlint"
	"github.com/micromdm/nanomdm/storage/mongodb"
	"github.com/micromdm/plist"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/micromdm/scep/v2/cryptoutil/x509util"
	"github.com/smallstep/scep"
	"go.mongodb.org/mongo-driver/v2/bson"
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
	// The server runs as one tenant of a shared database; the tenant check watches every command it sends. The test's own look into the database uses a client of its own.
	mon := tenantlint.NewMonitor("acme", "os_releases", "schema_sets")
	mc, err := mongo.Connect(options.Client().ApplyURI(uri).SetMonitor(mon.CommandMonitor()))
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Disconnect(ctx)
	peek, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer peek.Disconnect(ctx)
	db := peek.Database("fleetcore_test")
	defer func() {
		if v := mon.Violations(); len(v) > 0 {
			t.Errorf("commands that were not scoped to the tenant:\n%s", strings.Join(v, "\n"))
		}
		if mon.Checked() < 50 {
			t.Errorf("the tenant check saw only %d commands", mon.Checked())
		}
	}()
	if err := db.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	ring, err := seal.NewKeyring(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := mongodb.New(ctx, mongodb.WithClient(mc), mongodb.WithDatabase("fleetcore_test"), mongodb.WithTenant("acme"), mongodb.WithSealer(ring.For("acme")))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(ctx, Config{
		BaseURL: "https://mdm.test", Organization: "Test Org", ProfileIdentifier: "test.mdm.enroll", Topic: "com.apple.mgmt.External.test",
		Storage: store, PKIDB: mc.Database("fleetcore_test"), PKITenant: "acme", CAPass: "correct horse", CertSource: CertFromTLS, APIKey: "apikey", Version: "test", NoFeeds: true, Sealer: ring.For("acme"),
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

	// 4b. The JSON command API: validated, built into a plist, queued, and the answer read back as JSON.
	jpost := func(body string) (int, map[string]any) {
		code, b := post("/v1/commands", "application/json", nil, body, true)
		var m map[string]any
		_ = json.Unmarshal([]byte(b), &m)
		return code, m
	}
	if code, m := jpost(`{"request_type":"DeviceInformation","params":{"Queries":["SerialNumber"]},"devices":["` + udid + `"],"no_push":true}`); code != 200 || m["command_uuid"] == nil {
		t.Fatalf("json command: %d %v", code, m)
	} else {
		juuid := m["command_uuid"].(string)
		if code, m := jpost(`{"request_type":"DeviceInformation","params":{"Queries":[5]},"devices":["` + udid + `"]}`); code != 422 || m["problems"] == nil {
			t.Errorf("a bad query list got %d %v", code, m)
		}
		if code, _ := jpost(`{"request_type":"EraseDevice","params":{},"devices":["` + udid + `"]}`); code != 422 {
			t.Errorf("erase without confirm got %d", code)
		}
		code, b := post("/mdm", mdmCT, id, idle, false)
		if code != 200 || !strings.Contains(b, juuid) || !strings.Contains(b, "<key>RequestType</key>") {
			t.Fatalf("the device was not handed the JSON command: %d %s", code, b)
		}
		answer := `<?xml version="1.0"?><plist version="1.0"><dict><key>CommandUUID</key><string>` + juuid + `</string><key>QueryResponses</key><dict><key>SerialNumber</key><string>C02TEST</string></dict><key>Status</key><string>Acknowledged</string><key>UDID</key><string>` + udid + `</string></dict></plist>`
		if code, b := post("/mdm", mdmCT, id, answer, false); code != 200 {
			t.Fatalf("answer: %d %s", code, b)
		}
		req, _ := http.NewRequest("GET", ts.URL+"/v1/commands/"+juuid, nil)
		req.SetBasicAuth("fleetcore", "apikey")
		r, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: insecure}}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Devices []struct {
				ID, Status string
				Result     map[string]any
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		r.Body.Close()
		qr, _ := func() (map[string]any, bool) {
			if len(got.Devices) != 1 {
				return nil, false
			}
			m, ok := got.Devices[0].Result["QueryResponses"].(map[string]any)
			return m, ok
		}()
		if len(got.Devices) != 1 || got.Devices[0].Status != "Acknowledged" || qr["SerialNumber"] != "C02TEST" {
			t.Errorf("results: %+v", got)
		}
	}

	// 4c. Blueprints: a profile defined once reaches the enrolled Mac, which learned its platform from its Authenticate message.
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	go srv.Run(runCtx)
	api := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.SetBasicAuth("fleetcore", "apikey")
		r, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: insecure}}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	waitFor := func(what string, cond func() bool) {
		for i := 0; i < 100; i++ {
			if cond() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	waitFor("the device in the inventory", func() bool {
		code, b := api("GET", "/v1/devices/"+udid, "")
		return code == 200 && strings.Contains(b, `"platform":"macOS"`)
	})
	wifiProfile := `<?xml version="1.0"?><plist version="1.0"><dict><key>PayloadType</key><string>Configuration</string><key>PayloadVersion</key><integer>1</integer><key>PayloadIdentifier</key><string>com.test.wifi</string><key>PayloadUUID</key><string>AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA</string><key>PayloadContent</key><array><dict><key>PayloadType</key><string>com.apple.wifi.managed</string><key>PayloadVersion</key><integer>1</integer><key>PayloadIdentifier</key><string>com.test.wifi.x</string><key>PayloadUUID</key><string>BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB</string><key>SSID_STR</key><string>corp</string></dict></array></dict></plist>`
	bpBody, _ := json.Marshal(map[string]any{"id": "wifi", "name": "Wi-Fi", "enabled": true, "scope": map[string]any{"field": "platform", "op": "eq", "value": "macOS"},
		"items": []any{map[string]any{"kind": "profile", "payload": []byte(wifiProfile)}}})
	if code, b := api("POST", "/v1/blueprints", string(bpBody)); code != 201 {
		t.Fatalf("create blueprint: %d %s", code, b)
	}
	if code, _ := api("POST", "/v1/blueprints", string(bpBody)); code != 409 {
		t.Errorf("creating a blueprint twice got %d, want 409", code)
	}
	got := ""
	for i := 0; i < 100 && got == ""; i++ {
		code, b := post("/mdm", mdmCT, id, idle, false)
		if code != 200 || len(strings.TrimSpace(b)) == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		var c struct {
			CommandUUID string
			Command     struct{ RequestType string }
		}
		if err := plist.Unmarshal([]byte(b), &c); err != nil {
			t.Fatal(err)
		}
		reply := `<?xml version="1.0"?><plist version="1.0"><dict><key>CommandUUID</key><string>` + c.CommandUUID + `</string><key>Status</key><string>Acknowledged</string><key>UDID</key><string>` + udid + `</string></dict></plist>`
		if c.Command.RequestType == "InstallProfile" {
			got = c.CommandUUID
		}
		post("/mdm", mdmCT, id, reply, false)
	}
	if got == "" {
		t.Fatal("the profile never reached the device")
	}
	waitFor("the blueprint to show the profile applied", func() bool {
		_, b := api("GET", "/v1/blueprints/wifi/status", "")
		return strings.Contains(b, `"applied":1`)
	})
	// 4d. Declarative device management: the device is told to sync, fetches its declarations over the DeclarativeManagement check-in, and reports status.
	if err := srv.Blueprints.Store.SetDeviceFields(ctx, udid, bson.D{{Key: "supervised", Value: true}}, true); err != nil {
		t.Fatal(err)
	}
	pwBody, _ := json.Marshal(map[string]any{"id": "pw", "name": "Passcode", "enabled": true, "scope": map[string]any{"field": "platform", "op": "eq", "value": "macOS"},
		"items": []any{map[string]any{"id": "passcode", "kind": "declaration", "declaration_type": "com.apple.configuration.passcode.settings", "declaration": map[string]any{"RequirePasscode": true, "MinimumLength": 10}}}})
	if code, b := api("POST", "/v1/blueprints", string(pwBody)); code != 201 {
		t.Fatalf("create declaration blueprint: %d %s", code, b)
	}
	dmSync := false
	for i := 0; i < 100 && !dmSync; i++ {
		code, b := post("/mdm", mdmCT, id, idle, false)
		if code != 200 || len(strings.TrimSpace(b)) == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		var c struct {
			CommandUUID string
			Command     struct{ RequestType string }
		}
		if err := plist.Unmarshal([]byte(b), &c); err != nil {
			t.Fatal(err)
		}
		dmSync = dmSync || c.Command.RequestType == "DeclarativeManagement"
		post("/mdm", mdmCT, id, `<?xml version="1.0"?><plist version="1.0"><dict><key>CommandUUID</key><string>`+c.CommandUUID+`</string><key>Status</key><string>Acknowledged</string><key>UDID</key><string>`+udid+`</string></dict></plist>`, false)
	}
	if !dmSync {
		t.Fatal("the device was never told to sync its declarations")
	}
	dm := func(endpoint, data string) (int, string) {
		d := ""
		if data != "" {
			d = `<key>Data</key><data>` + base64.StdEncoding.EncodeToString([]byte(data)) + `</data>`
		}
		return post("/mdm", checkin, id, `<?xml version="1.0"?><plist version="1.0"><dict><key>MessageType</key><string>DeclarativeManagement</string><key>UDID</key><string>`+udid+`</string><key>Endpoint</key><string>`+endpoint+`</string>`+d+`</dict></plist>`, false)
	}
	code, b = dm("tokens", "")
	if code != 200 || !strings.Contains(b, "DeclarationsToken") {
		t.Fatalf("tokens: %d %s", code, b)
	}
	var pwToken string
	waitFor("the passcode declaration in the device's items", func() bool {
		code, b = dm("declaration-items", "")
		var items struct {
			Declarations struct {
				Configurations []struct{ Identifier, ServerToken string }
			}
		}
		_ = json.Unmarshal([]byte(b), &items)
		for _, c := range items.Declarations.Configurations {
			if c.Identifier == "fc.pw.passcode" {
				pwToken = c.ServerToken
			}
		}
		return pwToken != ""
	})
	if code != 200 || pwToken == "" {
		t.Fatalf("declaration-items: %d %s", code, b)
	}
	if code, b := dm("declaration/configuration/fc.pw.passcode", ""); code != 200 || !strings.Contains(b, `"MinimumLength":10`) {
		t.Fatalf("declaration: %d %s", code, b)
	}
	if code, _ := dm("declaration/configuration/nope", ""); code != 404 {
		t.Errorf("a missing declaration got %d, want 404", code)
	}
	report := `{"StatusItems":{"device.operating-system.version":"15.0","management.declarations":{"configurations":[{"identifier":"fc.pw.passcode","server-token":"` + pwToken + `","active":true,"valid":"valid"}],"activations":[],"assets":[],"management":[]}},"Errors":[]}`
	if code, b := dm("status", report); code != 200 {
		t.Fatalf("status: %d %s", code, b)
	}
	waitFor("the declaration to show applied", func() bool {
		_, b := api("GET", "/v1/blueprints/pw/status", "")
		return strings.Contains(b, `"applied":1`)
	})

	// 4e. The profile of the first blueprint now reaches the (supervised) Mac as a legacy-profile declaration; the device downloads it with its identity, and nobody else can.
	var profileURL string
	waitFor("the Wi-Fi profile to move to declarative delivery", func() bool {
		_, b := dm("declaration/configuration/fc.wifi.item-1", "")
		var wire struct{ Payload struct{ ProfileURL string } }
		_ = json.Unmarshal([]byte(b), &wire)
		profileURL = wire.Payload.ProfileURL
		return profileURL != ""
	})
	path := profileURL[strings.Index(profileURL, "/ddm/profile/"):]
	if code, b := post(path, "application/x-apple-aspen-config", id, "", false); code != 200 || !strings.Contains(b, "com.test.wifi") {
		t.Errorf("the device could not download its profile: %d %.80s", code, b)
	}
	if code, _ := post(path, "application/x-apple-aspen-config", stranger, "", false); code < 400 {
		t.Errorf("a certificate from another CA downloaded the profile: %d", code)
	}
	if code, _ := post(path, "application/x-apple-aspen-config", nil, "", false); code < 400 {
		t.Errorf("an anonymous download got %d", code)
	}

	pwProfile := `<?xml version="1.0"?><plist version="1.0"><dict><key>PayloadType</key><string>Configuration</string><key>PayloadVersion</key><integer>1</integer><key>PayloadIdentifier</key><string>t.pw</string><key>PayloadUUID</key><string>C</string><key>PayloadContent</key><array><dict><key>PayloadType</key><string>com.apple.mobiledevice.passwordpolicy</string><key>PayloadVersion</key><integer>1</integer><key>PayloadIdentifier</key><string>t.pw.x</string><key>PayloadUUID</key><string>D</string><key>minLength</key><integer>8</integer><key>unknownSetting</key><true/></dict></array></dict></plist>`
	trBody, _ := json.Marshal(map[string]any{"profile": []byte(pwProfile)})
	if code, b := api("POST", "/v1/ddm/translate", string(trBody)); code != 200 || !strings.Contains(b, `"MinimumLength":8`) || !strings.Contains(b, "unknownSetting") {
		t.Errorf("translate: %d %.300s", code, b)
	}
	if code, b := api("GET", "/v1/ddm/translate/coverage", ""); code != 200 || !strings.Contains(b, "com.apple.mail.managed") {
		t.Errorf("translate coverage: %d %.300s", code, b)
	}
	if code, b := api("GET", "/v1/ddm/support", ""); code != 200 || !strings.Contains(b, "software_update") {
		t.Errorf("support: %d %.200s", code, b)
	}
	// 4g. Enrollments and the queue, in pages.
	code, b = api("GET", "/v1/enrollments?limit=1", "")
	var enr struct {
		Enrollments []struct{ ID, Type string }
		Next        string
	}
	_ = json.Unmarshal([]byte(b), &enr)
	if code != 200 || len(enr.Enrollments) != 1 || enr.Enrollments[0].ID != udid || enr.Enrollments[0].Type != "Device" {
		t.Errorf("enrollments: %d %s", code, b)
	}
	if code, b := api("GET", "/v1/enrollments/"+udid+"/queue?status=acknowledged&limit=2", ""); code != 200 || !strings.Contains(b, `"status":"Acknowledged"`) || !strings.Contains(b, `"request_type"`) {
		t.Errorf("queue: %d %.300s", code, b)
	}
	var q1 struct {
		Queue []struct {
			CommandUUID string `json:"command_uuid"`
		}
		Next string
	}
	_, b = api("GET", "/v1/queue?id="+udid+"&limit=2", "")
	_ = json.Unmarshal([]byte(b), &q1)
	if len(q1.Queue) != 2 || q1.Next == "" {
		t.Fatalf("first page of the queue: %s", b)
	}
	var q2 struct {
		Queue []struct {
			CommandUUID string `json:"command_uuid"`
		}
	}
	_, b = api("GET", "/v1/queue?id="+udid+"&limit=2&cursor="+q1.Next, "")
	_ = json.Unmarshal([]byte(b), &q2)
	if len(q2.Queue) == 0 || q2.Queue[0].CommandUUID == q1.Queue[0].CommandUUID || q2.Queue[0].CommandUUID == q1.Queue[1].CommandUUID {
		t.Errorf("the second page repeats the first: first %v second %s", q1.Queue, b)
	}
	if code, b := api("GET", "/v1/commands?type=DeviceInformation&limit=5", ""); code != 200 || !strings.Contains(b, `"request_type":"DeviceInformation"`) {
		t.Errorf("command history: %d %.200s", code, b)
	}
	if code, b := api("GET", "/v1/devices?platform=macOS&limit=5", ""); code != 200 || !strings.Contains(b, udid) {
		t.Errorf("device list: %d %.200s", code, b)
	}
	if code, _ := api("GET", "/v1/queue?cursor=garbage", ""); code != 400 {
		t.Errorf("a bad cursor got %d", code)
	}

	if code, b := api("GET", "/v1/ddm/coverage", ""); code != 200 || !strings.Contains(b, "com.apple.wifi.managed") || !strings.Contains(b, "applications_by_delivery") {
		t.Errorf("coverage: %d %.200s", code, b)
	}
	if code, b := api("GET", "/v1/ddm/devices/"+udid, ""); code != 200 || !strings.Contains(b, "fc.pw.passcode") {
		t.Errorf("ddm device: %d %.200s", code, b)
	}
	if code, b := api("GET", "/v1/schemas", ""); code != 200 || !strings.Contains(b, `"commands"`) {
		t.Errorf("schemas: %d %s", code, b)
	}

	// 4f. Nothing that holds a secret is readable in the database: not the profile (its Wi-Fi settings), not the declaration's settings, not the queued commands.
	for _, coll := range []string{"bp_blueprints", "bp_revisions", "ddm_declarations", "ddm_profiles", "commands", "enrollment_queue", "devices"} {
		cur, err := db.Collection(coll).Find(ctx, bson.D{})
		if err != nil {
			t.Fatal(err)
		}
		var docs []bson.M
		if err := cur.All(ctx, &docs); err != nil {
			t.Fatal(err)
		}
		if len(docs) == 0 {
			t.Errorf("%s is empty: the check proves nothing", coll)
		}
		for _, d := range docs {
			b, _ := json.Marshal(d)
			for _, secret := range []string{"SSID_STR", "MinimumLength", "RequirePasscode", "com.apple.wifi.managed"} {
				if bytes.Contains(b, []byte(secret)) {
					t.Errorf("%s holds %q in the clear: %.120s", coll, secret, b)
				}
			}
		}
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
