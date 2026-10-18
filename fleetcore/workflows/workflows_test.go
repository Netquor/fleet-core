package workflows

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/admin"
	"github.com/micromdm/nanomdm/fleetcore/blueprints"
	"github.com/micromdm/nanomdm/fleetcore/seal"
	"github.com/micromdm/nanomdm/fleetcore/vault"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type rec struct {
	mu   sync.Mutex
	sent [][]byte
}

func (r *rec) Enqueue(_ context.Context, _ []string, body []byte) error {
	r.mu.Lock()
	r.sent = append(r.sent, body)
	r.mu.Unlock()
	return nil
}

func (r *rec) last(t *testing.T) (uuid, requestType string, command map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sent) == 0 {
		t.Fatal("nothing was sent")
	}
	var c struct {
		CommandUUID string
		Command     map[string]any
	}
	if err := plist.Unmarshal(r.sent[len(r.sent)-1], &c); err != nil {
		t.Fatal(err)
	}
	rt, _ := c.Command["RequestType"].(string)
	return c.CommandUUID, rt, c.Command
}

type env struct {
	ctx context.Context
	s   *Service
	st  *blueprints.Store
	enq *rec
	api http.Handler
}

func setup(t *testing.T) *env {
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
	db := mc.Database("fleetcore_wf_test")
	db.Drop(ctx)
	t.Cleanup(func() { db.Drop(context.Background()) })
	st, err := blueprints.NewStore(ctx, db, "acme")
	if err != nil {
		t.Fatal(err)
	}
	ring, _ := seal.NewKeyring(bytes.Repeat([]byte{8}, 32))
	sealer := ring.For("acme")
	v, err := vault.NewStore(ctx, db, "acme")
	if err != nil {
		t.Fatal(err)
	}
	v.Sealer = sealer
	enq := &rec{}
	s, err := New(ctx, db, "acme", st, enq, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Sealer = sealer
	api := (&API{S: s}).Handler(nil)
	return &env{ctx, s, st, enq, api}
}

func (e *env) device(t *testing.T, id, platform, version string, supervised bool, enrollType string) {
	if err := e.st.UpsertDevice(e.ctx, blueprints.DeviceUpdate{ID: id, Platform: platform, OSVersion: version, EnrollType: enrollType}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetDeviceFields(e.ctx, id, bson.D{{Key: "supervised", Value: supervised}}, false); err != nil {
		t.Fatal(err)
	}
}

func (e *env) answer(device, uuid, status string, extra string) {
	raw := `<?xml version="1.0"?><plist version="1.0"><dict><key>CommandUUID</key><string>` + uuid + `</string><key>Status</key><string>` + status + `</string>` + extra + `</dict></plist>`
	e.s.HandleResult(e.ctx, device, &mdm.CommandResults{CommandUUID: uuid, Status: status, Raw: []byte(raw)})
}

func TestLostMode(t *testing.T) {
	e := setup(t)
	e.device(t, "phone", "iOS", "18.2", true, "Device")
	e.device(t, "byod", "iOS", "18.2", true, "User Enrollment")
	e.device(t, "loose", "iOS", "18.2", false, "Device")
	e.device(t, "mac", "macOS", "15.0", true, "Device")

	// the schema and the enrollment decide who can be put in Lost Mode
	for _, id := range []string{"byod", "loose", "mac"} {
		if _, err := e.s.EnableLostMode(e.ctx, id, "alice", LostModeRequest{Message: "Call me"}); err == nil {
			t.Errorf("%s was put in Lost Mode", id)
		} else if _, ok := err.(ErrUnavailable); !ok {
			t.Errorf("%s: %v", id, err)
		}
	}
	if _, err := e.s.EnableLostMode(e.ctx, "phone", "alice", LostModeRequest{}); err == nil {
		t.Error("Lost Mode with nothing to show")
	}
	if _, err := e.s.Locate(e.ctx, "phone", "alice"); err == nil {
		t.Error("located a device that is not in Lost Mode")
	}
	u, err := e.s.EnableLostMode(e.ctx, "phone", "alice", LostModeRequest{Message: "Lost: call me", Phone: "555-0100"})
	if err != nil {
		t.Fatal(err)
	}
	if _, rt, c := e.enq.last(t); rt != "EnableLostMode" || c["Message"] != "Lost: call me" || c["PhoneNumber"] != "555-0100" {
		t.Errorf("command: %s %v", rt, c)
	}
	if d, _ := e.st.GetDevice(e.ctx, "phone"); d.LostMode != nil {
		t.Error("Lost Mode is recorded before the device confirmed")
	}
	e.answer("phone", u, "Acknowledged", "")
	if d, _ := e.st.GetDevice(e.ctx, "phone"); d.LostMode == nil || !d.LostMode.Enabled || d.LostMode.Message != "Lost: call me" {
		t.Fatalf("after the acknowledgement: %+v", d.LostMode)
	}
	loc, err := e.s.Locate(e.ctx, "phone", "alice")
	if err != nil {
		t.Fatal(err)
	}
	e.answer("phone", loc, "Acknowledged", `<key>Latitude</key><real>41.88</real><key>Longitude</key><real>-87.63</real><key>HorizontalAccuracy</key><real>12.5</real>`)
	if d, _ := e.st.GetDevice(e.ctx, "phone"); d.Location == nil || d.Location.Latitude != 41.88 || d.Location.Longitude != -87.63 {
		t.Errorf("location: %+v", d.Location)
	}
	if _, err := e.s.PlaySound(e.ctx, "phone", "alice"); err != nil {
		t.Error(err)
	}
	off, _ := e.s.DisableLostMode(e.ctx, "phone", "alice")
	e.answer("phone", off, "Acknowledged", "")
	if d, _ := e.st.GetDevice(e.ctx, "phone"); d.LostMode == nil || d.LostMode.Enabled {
		t.Errorf("Lost Mode still on: %+v", d.LostMode)
	}
	// a result for another device's command does nothing
	e.answer("loose", u, "Acknowledged", "")
	if d, _ := e.st.GetDevice(e.ctx, "loose"); d.LostMode != nil {
		t.Error("another device took the result")
	}
}

func TestActivationLockBypassCode(t *testing.T) {
	e := setup(t)
	e.device(t, "phone", "iOS", "18.2", true, "Device")
	u, err := e.s.RequestBypassCode(e.ctx, "phone", "alice")
	if err != nil {
		t.Fatal(err)
	}
	e.answer("phone", u, "Acknowledged", `<key>ActivationLockBypassCode</key><string>ABCD-1234</string>`)
	if code, ok, _ := e.s.Vault.Peek(e.ctx, "phone", vault.ActivationLockBypass); !ok || code != "ABCD-1234" {
		t.Errorf("the code was not kept: %q", code)
	}
	// an Error answer keeps nothing
	e.device(t, "phone2", "iOS", "18.2", true, "Device")
	u2, _ := e.s.RequestBypassCode(e.ctx, "phone2", "alice")
	e.answer("phone2", u2, "Error", "")
	if _, ok, _ := e.s.Vault.Peek(e.ctx, "phone2", vault.ActivationLockBypass); ok {
		t.Error("a failed request left a code")
	}
}

func TestFileVaultRotation(t *testing.T) {
	e := setup(t)
	e.device(t, "mac", "macOS", "15.0", false, "Device")
	if _, err := e.s.RotateFileVault(e.ctx, "mac", "alice", ""); err == nil {
		t.Error("rotation with no password and no stored key")
	}
	rotate := func(pw, newKey string) map[string]any {
		u, err := e.s.RotateFileVault(e.ctx, "mac", "alice", pw)
		if err != nil {
			t.Fatal(err)
		}
		_, rt, c := e.enq.last(t)
		if rt != "RotateFileVaultKey" || c["KeyType"] != "personal" {
			t.Fatalf("command: %v", c)
		}
		// The Mac encrypts the new key to the one-time certificate in the command.
		cert, err := x509.ParseCertificate(c["ReplyEncryptionCertificate"].([]byte))
		if err != nil {
			t.Fatal(err)
		}
		enc, err := pkcs7.Encrypt([]byte(newKey+"\n"), []*x509.Certificate{cert})
		if err != nil {
			t.Fatal(err)
		}
		e.answer("mac", u, "Acknowledged", `<key>RotateResult</key><string>Success</string><key>EncryptedNewRecoveryKey</key><data>`+base64.StdEncoding.EncodeToString(enc)+`</data>`)
		return c
	}
	c := rotate("user-password", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")
	if c["FileVaultUnlock"].(map[string]any)["Password"] != "user-password" {
		t.Errorf("unlock: %v", c["FileVaultUnlock"])
	}
	if k, ok, _ := e.s.Vault.Peek(e.ctx, "mac", vault.FileVaultRecoveryKey); !ok || k != "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF" {
		t.Fatalf("the new key was not kept: %q", k)
	}
	// next time the stored key unlocks
	c = rotate("", "GGGG-HHHH-JJJJ-KKKK-LLLL-MMMM")
	if c["FileVaultUnlock"].(map[string]any)["Password"] != "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF" {
		t.Errorf("the stored key was not used: %v", c["FileVaultUnlock"])
	}
	metas, _ := e.s.Vault.List(e.ctx, "mac")
	if len(metas) != 2 || metas[0].Version != 2 {
		t.Errorf("history: %+v", metas)
	}
	// a message that was not encrypted to our key keeps nothing
	other, _ := x509.ParseCertificate(c["ReplyEncryptionCertificate"].([]byte))
	_ = other
	u, _ := e.s.RotateFileVault(e.ctx, "mac", "alice", "")
	e.answer("mac", u, "Acknowledged", `<key>EncryptedNewRecoveryKey</key><data>`+base64.StdEncoding.EncodeToString([]byte("not cms"))+`</data>`)
	if k, _, _ := e.s.Vault.Peek(e.ctx, "mac", vault.FileVaultRecoveryKey); k != "GGGG-HHHH-JJJJ-KKKK-LLLL-MMMM" {
		t.Errorf("garbage replaced the key: %q", k)
	}
}

func TestRecoveryLock(t *testing.T) {
	e := setup(t)
	e.device(t, "mac", "macOS", "15.0", false, "Device")
	u, err := e.s.SetRecoveryLock(e.ctx, "mac", "alice", "", false)
	if err != nil {
		t.Fatal(err)
	}
	_, rt, c := e.enq.last(t)
	pw, _ := c["NewPassword"].(string)
	if rt != "SetRecoveryLock" || len(pw) != 16 || c["CurrentPassword"] != nil {
		t.Fatalf("command: %v", c)
	}
	if _, ok, _ := e.s.Vault.Peek(e.ctx, "mac", vault.RecoveryLock); ok {
		t.Error("the password is kept before the Mac accepted it")
	}
	e.answer("mac", u, "Error", "")
	if _, ok, _ := e.s.Vault.Peek(e.ctx, "mac", vault.RecoveryLock); ok {
		t.Error("a refused password was kept")
	}
	e.answer("mac", u, "Acknowledged", "")
	if v, ok, _ := e.s.Vault.Peek(e.ctx, "mac", vault.RecoveryLock); !ok || v != pw {
		t.Fatalf("the password: %q", v)
	}
	// changing it presents the current one
	u2, _ := e.s.SetRecoveryLock(e.ctx, "mac", "alice", "", false)
	_, _, c2 := e.enq.last(t)
	if c2["CurrentPassword"] != pw || c2["NewPassword"] == pw {
		t.Errorf("rotation: %v", c2)
	}
	e.answer("mac", u2, "Acknowledged", "")
	// clearing
	u3, _ := e.s.SetRecoveryLock(e.ctx, "mac", "alice", "", true)
	_, _, c3 := e.enq.last(t)
	if c3["NewPassword"] != "" || c3["CurrentPassword"] != c2["NewPassword"] {
		t.Errorf("clear: %v", c3)
	}
	e.answer("mac", u3, "Acknowledged", "")
	if v, _, _ := e.s.Vault.Peek(e.ctx, "mac", vault.RecoveryLock); v != "" {
		t.Errorf("a cleared lock still has a password: %q", v)
	}
	// an iPhone has none of this
	e.device(t, "phone", "iOS", "18.2", true, "Device")
	if _, err := e.s.SetRecoveryLock(e.ctx, "phone", "alice", "", false); err == nil {
		t.Error("recovery lock on an iPhone")
	}
}

func TestAPIRevealIsAudited(t *testing.T) {
	e := setup(t)
	e.s.Vault.Put(e.ctx, "mac", vault.RecoveryLock, "s3cr3t-pass", "system")
	call := func(method, path, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(admin.With(e.ctx, "CN=operator,O=ops"))
		rec := httptest.NewRecorder()
		e.api.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, b := call("GET", "/devices/mac/secrets", ""); code != 200 || strings.Contains(b, "s3cr3t") || !strings.Contains(b, "recovery-lock") {
		t.Errorf("list: %d %s", code, b)
	}
	if code, _ := call("POST", "/devices/mac/secrets/recovery-lock/reveal", `{}`); code != 400 {
		t.Errorf("reveal without a reason: %d", code)
	}
	if code, b := call("POST", "/devices/mac/secrets/recovery-lock/reveal", `{"reason":"ticket 9"}`); code != 200 || !strings.Contains(b, "s3cr3t-pass") {
		t.Errorf("reveal: %d %s", code, b)
	}
	if code, b := call("GET", "/devices/mac/secrets/audit", ""); code != 200 || !strings.Contains(b, "CN=operator,O=ops") || !strings.Contains(b, "ticket 9") {
		t.Errorf("audit: %d %s", code, b)
	}
	if code, _ := call("POST", "/devices/mac/secrets/filevault-recovery-key/reveal", `{"reason":"x"}`); code != 404 {
		t.Errorf("a secret that does not exist: %d", code)
	}
	// a command the device cannot take is a 422 that says why
	e.device(t, "phone", "iOS", "18.2", false, "Device")
	if code, b := call("POST", "/devices/phone/lost-mode", `{"message":"hi"}`); code != 422 || !strings.Contains(b, "supervised") {
		t.Errorf("unsupervised: %d %s", code, b)
	}
}

func TestInstalledApps(t *testing.T) {
	e := setup(t)
	e.device(t, "phone", "iOS", "18.2", true, "Device")
	e.device(t, "byod", "iOS", "18.2", false, "User Enrollment")
	u, err := e.s.RefreshApps(e.ctx, "phone", "alice")
	if err != nil {
		t.Fatal(err)
	}
	e.answer("phone", u, "Acknowledged", `<key>InstalledApplicationList</key><array><dict><key>Identifier</key><string>com.tinyspeck.chatlyio</string><key>Name</key><string>Slack</string><key>Version</key><string>123</string><key>ShortVersion</key><string>4.1</string><key>IsManaged</key><true/></dict><dict><key>Identifier</key><string>com.apple.mobilesafari</string><key>Name</key><string>Safari</string></dict></array>`)
	d, _ := e.st.GetDevice(e.ctx, "phone")
	if len(d.Apps) != 2 || d.Apps[0].Identifier != "com.tinyspeck.chatlyio" || !d.Apps[0].Managed || d.Apps[0].ShortVersion != "4.1" || d.AppsAt.IsZero() {
		t.Errorf("apps: %+v", d.Apps)
	}
	// a User Enrollment device is asked for managed apps only
	if _, err := e.s.RefreshApps(e.ctx, "byod", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, c := e.enq.last(t); c["ManagedAppsOnly"] != true {
		t.Errorf("a BYOD device was asked for everything: %v", c)
	}
}
