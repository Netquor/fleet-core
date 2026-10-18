// Package userauth answers the MDM UserAuthenticate handshake for macOS network and mobile users and Shared iPad users: it issues an HTTP digest challenge, checks the
// digest the device builds from the person's short name and password, and hands back an AuthToken that the device then sends on every request of that user.
//
// The password is never seen by this server. A person is checked either against a stored digest hash (HA1 = MD5(user:realm:password), made with `fleetcore ua-hash`) or by
// asking a bridge to your directory (Open Directory, LDAP, an identity provider) that holds the password and can verify the digest.
package userauth

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"
	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/plist"
)

// Digest is what the device sent back, parsed.
type Digest struct {
	Username, Realm, Nonce, URI, Response string
	QOP, NC, CNonce                       string
}

// ParseDigest reads a "Digest username=..., realm=..." header-style string.
func ParseDigest(s string) (Digest, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToLower(s), "digest") {
		return Digest{}, errors.New("not a digest response")
	}
	s = strings.TrimSpace(s[len("digest"):])
	var d Digest
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			break
		}
		key := strings.ToLower(strings.Trim(strings.TrimSpace(s[:eq]), ", "))
		s = strings.TrimSpace(s[eq+1:])
		var val string
		if strings.HasPrefix(s, `"`) {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				return Digest{}, errors.New("unterminated quoted value")
			}
			val, s = s[1:1+end], s[end+2:]
		} else {
			end := strings.IndexByte(s, ',')
			if end < 0 {
				end = len(s)
			}
			val, s = strings.TrimSpace(s[:end]), s[end:]
		}
		s = strings.TrimLeft(s, ", ")
		switch key {
		case "username":
			d.Username = val
		case "realm":
			d.Realm = val
		case "nonce":
			d.Nonce = val
		case "uri":
			d.URI = val
		case "response":
			d.Response = val
		case "qop":
			d.QOP = val
		case "nc":
			d.NC = val
		case "cnonce":
			d.CNonce = val
		}
	}
	if d.Username == "" || d.Nonce == "" || d.Response == "" {
		return Digest{}, errors.New("the digest lacks a user name, nonce or response")
	}
	return d, nil
}

func md5hex(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }

// HA1 is the stored form of a password for a realm: MD5(user:realm:password).
func HA1(user, realm, password string) string { return md5hex(user + ":" + realm + ":" + password) }

// methods are tried because Apple's description names neither the HTTP method nor the URI the digest is computed over (the example uses uri="/"); the check-in itself is a PUT.
var methods = []string{"PUT", "POST", "GET"}

// Matches reports whether the digest was built from the password behind ha1 (RFC 2617, with or without qop=auth).
func (d Digest) Matches(ha1 string) bool {
	for _, m := range methods {
		ha2 := md5hex(m + ":" + d.URI)
		var want string
		if strings.EqualFold(d.QOP, "auth") {
			want = md5hex(ha1 + ":" + d.Nonce + ":" + d.NC + ":" + d.CNonce + ":" + d.QOP + ":" + ha2)
		} else {
			want = md5hex(ha1 + ":" + d.Nonce + ":" + ha2)
		}
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(d.Response)), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// Directory finds the stored digest hash for a person.
type Directory interface {
	HA1(ctx context.Context, user, realm string) (ha1 string, found bool, err error)
}

// Verifier decides whether a digest is right when the password is held elsewhere.
type Verifier interface {
	Verify(ctx context.Context, d Digest, udid, userID string) (bool, error)
}

// FileDirectory is a set of "user:realm:ha1" lines, for small installations and tests.
type FileDirectory map[string]string

// LoadFileDirectory reads lines of user:realm:ha1 (blank lines and # comments are skipped).
func LoadFileDirectory(path string) (FileDirectory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := FileDirectory{}
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 || len(parts[2]) != 32 {
			return nil, fmt.Errorf("%s line %d: want user:realm:ha1 (32 hex characters)", path, n+1)
		}
		m[parts[0]+":"+parts[1]] = strings.ToLower(parts[2])
	}
	return m, nil
}

// HA1 implements Directory.
func (f FileDirectory) HA1(_ context.Context, user, realm string) (string, bool, error) {
	h, ok := f[user+":"+realm]
	return h, ok, nil
}

// HTTPVerifier asks a bridge that can check the digest: it receives the digest fields as JSON, authenticated by a bearer secret, and answers {"ok": true}.
type HTTPVerifier struct {
	URL    string
	Secret string
	Client *http.Client
}

// Verify implements Verifier.
func (v *HTTPVerifier) Verify(ctx context.Context, d Digest, udid, userID string) (bool, error) {
	body, _ := json.Marshal(map[string]string{"username": d.Username, "realm": d.Realm, "nonce": d.Nonce, "uri": d.URI, "response": d.Response, "qop": d.QOP, "nc": d.NC, "cnonce": d.CNonce, "udid": udid, "user_id": userID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.URL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if v.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+v.Secret)
	}
	c := v.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("the verifier answered %d", resp.StatusCode)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<16)).Decode(&out); err != nil {
		return false, err
	}
	return out.OK, nil
}

// Service implements the UserAuthenticate check-in.
type Service struct {
	Store     *Store
	Realm     string
	Directory Directory
	Verifier  Verifier
	// Messages keeps the check-in messages (sealed by the storage); optional.
	Messages storage.UserAuthenticateStore
	// Fallback answers when neither a directory nor a verifier is set (decline, or the zero-length challenge).
	Fallback service.UserAuthenticate
	// TokenLife is how long an AuthToken lasts without another handshake (default 24 hours; a login session normally ends sooner and the next login makes a new token).
	TokenLife time.Duration
}

func plistBytes(v any) ([]byte, error) { return plist.MarshalIndent(v, "\t") }

// UserAuthenticate implements service.UserAuthenticate.
func (s *Service) UserAuthenticate(r *mdm.Request, msg *mdm.UserAuthenticate) ([]byte, error) {
	if s.Directory == nil && s.Verifier == nil {
		if s.Fallback == nil {
			return nil, service.NewHTTPStatusError(http.StatusGone, errors.New("declining management of user"))
		}
		return s.Fallback.UserAuthenticate(r, msg)
	}
	if s.Messages != nil {
		if err := s.Messages.StoreUserAuthenticate(r, msg); err != nil {
			return nil, err
		}
	}
	ctx := r.Context()
	if msg.DigestResponse == "" {
		nonce, err := s.Store.NewNonce(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		return plistBytes(map[string]string{"DigestChallenge": fmt.Sprintf(`Digest nonce="%s",realm="%s"`, nonce, s.Realm)})
	}
	rejected := func() ([]byte, error) { return plistBytes(map[string]string{"AuthToken": ""}) }
	d, err := ParseDigest(msg.DigestResponse)
	if err != nil {
		return rejected()
	}
	ok, err := s.Store.UseNonce(ctx, r.ID, d.Nonce)
	if err != nil {
		return nil, err
	}
	if !ok || (d.Realm != "" && d.Realm != s.Realm) {
		return rejected()
	}
	valid := false
	if s.Directory != nil {
		ha1, found, err := s.Directory.HA1(ctx, d.Username, s.Realm)
		if err != nil {
			return nil, err
		}
		valid = found && d.Matches(ha1)
	}
	if !valid && s.Verifier != nil {
		if valid, err = s.Verifier.Verify(ctx, d, msg.UDID, msg.UserID); err != nil {
			return nil, err
		}
	}
	if !valid {
		return rejected()
	}
	life := s.TokenLife
	if life == 0 {
		life = 24 * time.Hour
	}
	token, err := s.Store.IssueToken(ctx, r.ID, d.Username, life)
	if err != nil {
		return nil, err
	}
	return plistBytes(map[string]string{"AuthToken": token})
}

// Enforcer wraps the MDM service so that requests on a user channel must carry the AuthToken issued to that user. With Require, a user channel that never completed the handshake
// is refused too; without it, only users who have a token are held to it.
type Enforcer struct {
	Store   *Store
	Require bool
}

// Check returns an error (an HTTP 401) when a user-channel request does not carry the right token.
func (e *Enforcer) Check(r *mdm.Request, token string) error {
	if r.ParentID == "" { // the device channel
		return nil
	}
	st, err := e.Store.CheckToken(r.Context(), r.ID, token)
	if err != nil {
		return err
	}
	switch st {
	case TokenOK:
		return nil
	case NoToken:
		if !e.Require {
			return nil
		}
	}
	return service.NewHTTPStatusError(http.StatusUnauthorized, errors.New("the AuthToken for this user is missing or wrong"))
}

func randomToken() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func hashToken(t string) string { h := sha256.Sum256([]byte(t)); return hex.EncodeToString(h[:]) }
