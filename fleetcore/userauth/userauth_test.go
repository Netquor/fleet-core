package userauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/plist"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestDigestMatchesRFC2617Example(t *testing.T) {
	// RFC 2617 section 3.5 (without qop it is the RFC 2069 form): the digest for Mufasa / Circle Of Life.
	ha1 := HA1("Mufasa", "testrealm@host.com", "Circle Of Life")
	d, err := ParseDigest(`Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", qop=auth, nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1"`)
	if err != nil {
		t.Fatal(err)
	}
	// that example is computed with GET; the check accepts the methods a check-in could use, and GET is among them
	if !d.Matches(ha1) {
		t.Error("the RFC example digest did not match")
	}
	if d.Matches(HA1("Mufasa", "testrealm@host.com", "wrong")) {
		t.Error("a wrong password matched")
	}
	if _, err := ParseDigest("Basic abc"); err == nil {
		t.Error("a non-digest was accepted")
	}
}

func appleStyle(user, realm, pass, nonce, uri string) string {
	ha1 := HA1(user, realm, pass)
	resp := md5hex(ha1 + ":" + nonce + ":" + md5hex("PUT:"+uri))
	return fmt.Sprintf(`Digest username="%s",realm="%s",nonce="%s", uri="%s",response="%s"`, user, realm, nonce, uri, resp)
}

func TestHandshakeAndEnforcement(t *testing.T) {
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
	db := mc.Database("fleetcore_userauth_test")
	db.Drop(ctx)
	defer db.Drop(context.Background())
	st, err := NewStore(ctx, db, "ua")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: st, Realm: "fusion.home", Directory: FileDirectory{"net1:fusion.home": HA1("net1", "fusion.home", "s3cret")}}
	req := &mdm.Request{EnrollID: &mdm.EnrollID{ID: "UDID:USER", ParentID: "UDID"}}
	req = req.WithContext(ctx)

	challenge := func() string {
		out, err := svc.UserAuthenticate(req, &mdm.UserAuthenticate{})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]string
		if err := plist.Unmarshal(out, &m); err != nil {
			t.Fatal(err)
		}
		c := m["DigestChallenge"]
		if !strings.Contains(c, `realm="fusion.home"`) {
			t.Fatalf("challenge %q", c)
		}
		i := strings.Index(c, `nonce="`) + 7
		return c[i : i+strings.Index(c[i:], `"`)]
	}
	respond := func(resp string) string {
		out, err := svc.UserAuthenticate(req, &mdm.UserAuthenticate{DigestResponse: resp})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]string
		if err := plist.Unmarshal(out, &m); err != nil {
			t.Fatal(err)
		}
		return m["AuthToken"]
	}

	// a wrong password gets 200 and an empty token
	if tok := respond(appleStyle("net1", "fusion.home", "nope", challenge(), "/")); tok != "" {
		t.Errorf("a wrong password got a token: %q", tok)
	}
	// a challenge is good once
	n := challenge()
	good := appleStyle("net1", "fusion.home", "s3cret", n, "/")
	tok := respond(good)
	if tok == "" {
		t.Fatal("the right password got no token")
	}
	if again := respond(good); again != "" {
		t.Error("a challenge was used twice")
	}
	// an unknown person
	if tok := respond(appleStyle("nobody", "fusion.home", "x", challenge(), "/")); tok != "" {
		t.Error("an unknown person got a token")
	}
	// the token is held to on the user channel, and the device channel is untouched
	e := &Enforcer{Store: st}
	if err := e.Check(req, tok); err != nil {
		t.Errorf("the issued token was refused: %v", err)
	}
	if err := e.Check(req, "other"); err == nil {
		t.Error("a wrong token passed")
	}
	if err := e.Check(req, ""); err == nil {
		t.Error("a missing token passed for a user who has one")
	}
	device := (&mdm.Request{EnrollID: &mdm.EnrollID{ID: "UDID"}}).WithContext(ctx)
	if err := e.Check(device, ""); err != nil {
		t.Errorf("the device channel was held to a token: %v", err)
	}
	stranger := (&mdm.Request{EnrollID: &mdm.EnrollID{ID: "UDID:OTHER", ParentID: "UDID"}}).WithContext(ctx)
	if err := e.Check(stranger, ""); err != nil {
		t.Errorf("a user without a handshake was refused without -require: %v", err)
	}
	if err := (&Enforcer{Store: st, Require: true}).Check(stranger, ""); err == nil {
		t.Error("a user without a handshake passed with require")
	}
	// the next handshake replaces the token
	tok2 := respond(appleStyle("net1", "fusion.home", "s3cret", challenge(), "/"))
	if err := e.Check(req, tok); err == nil || e.Check(req, tok2) != nil {
		t.Error("the old token still works or the new one does not")
	}
}

func TestHTTPVerifier(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sekrit" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"ok": true}`)
	}))
	defer ts.Close()
	v := &HTTPVerifier{URL: ts.URL, Secret: "sekrit"}
	ok, err := v.Verify(context.Background(), Digest{Username: "u"}, "U", "G")
	if err != nil || !ok {
		t.Errorf("%v %v", ok, err)
	}
	if ok, _ := (&HTTPVerifier{URL: ts.URL, Secret: "bad"}).Verify(context.Background(), Digest{}, "", ""); ok {
		t.Error("a wrong secret was accepted")
	}
}
