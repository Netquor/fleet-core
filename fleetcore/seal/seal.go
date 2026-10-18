// Package seal encrypts secrets before they reach the database. Every secret is sealed with a key that belongs to its tenant and its purpose, so a copy of the database holds no usable
// secrets without the master key, and a sealed value moved to another tenant (or another field) does not open.
//
// A master key never leaves the server's configuration. Each tenant's key is derived from it (HKDF-SHA-256, the tenant as context), so there is nothing per tenant to store, lose or
// back up, and every tenant's data is encrypted under a different key. AES-256-GCM binds the tenant and purpose as authenticated data. Keys have an ID, several can be configured, and
// a value sealed with an older key opens until the data is re-sealed with the current one (Rewrap, and the rekey command).
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// Version prefix of a sealed value: "s1.<key id>.<base64(nonce|ciphertext)>".
const prefix = "s1."

// Keyring holds the master keys. The first is the current one, used to seal; all open.
type Keyring struct {
	keys  [][]byte
	ids   []string
	plain bool
}

// KeyID names a master key: a short fingerprint, safe to store beside the data.
func KeyID(master []byte) string {
	h := sha256.Sum256(append([]byte("fleetcore-key-id\x00"), master...))
	return hex.EncodeToString(h[:4])
}

// NewKeyring makes a keyring from 32-byte master keys, current first.
func NewKeyring(masters ...[]byte) (*Keyring, error) {
	if len(masters) == 0 {
		return nil, errors.New("seal: at least one master key is required")
	}
	k := &Keyring{}
	for _, m := range masters {
		if len(m) != 32 {
			return nil, errors.New("seal: a master key is 32 bytes")
		}
		k.keys = append(k.keys, m)
		k.ids = append(k.ids, KeyID(m))
	}
	return k, nil
}

// FromPassphrase derives a master key from a passphrase (scrypt, with a fixed salt: the passphrase is the secret). It lets an installation that only has a passphrase today
// (the CA passphrase) get per-tenant sealing without new configuration; a generated 32-byte key is better and is what NewKeyring takes.
func FromPassphrase(pass string) (*Keyring, error) {
	m, err := scrypt.Key([]byte(pass), []byte("fleetcore-master-v1"), 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return NewKeyring(m)
}

// ParseKeys reads master keys written as base64 (standard or URL), separated by commas or newlines, current first.
func ParseKeys(s string) ([][]byte, error) {
	var out [][]byte
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		b, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			if b, err = base64.RawStdEncoding.DecodeString(part); err != nil {
				if b, err = base64.URLEncoding.DecodeString(part); err != nil {
					return nil, errors.New("seal: a master key is not valid base64")
				}
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// Plain returns a keyring that stores values as they are, marked "plain". It exists for development and tests; a server should not run on it.
func Plain() *Keyring { return &Keyring{plain: true} }

// IsPlain reports whether the keyring stores values unencrypted.
func (k *Keyring) IsPlain() bool { return k == nil || k.plain }

// Sealer seals and opens the values of one tenant ("" for an installation whose database belongs to a single tenant).
type Sealer struct {
	keys   []tenantKey // the current one first
	tenant string
	plain  bool
}

type tenantKey struct {
	id  string
	key []byte
}

func deriveTenantKey(master []byte, tenant string) []byte {
	r := hkdf.New(sha256.New, master, []byte("fleetcore-tenant-key"), []byte("tenant:"+tenant))
	out := make([]byte, 32)
	_, _ = io.ReadFull(r, out)
	return out
}

// For returns the sealer of a tenant, from a keyring that holds the master keys.
func (k *Keyring) For(tenant string) *Sealer {
	s := &Sealer{tenant: tenant, plain: k.IsPlain()}
	if !s.plain {
		for i, m := range k.keys {
			s.keys = append(s.keys, tenantKey{k.ids[i], deriveTenantKey(m, tenant)})
		}
	}
	return s
}

// TenantKey is a tenant's key as "<key id>:<base64>", derived from the current master key. It is all a tenant's own server needs: it seals and opens that tenant's data and nothing else,
// so the master key can stay with whoever provisions tenants and never sit on a tenant's server. Give it to the server as FLEETCORE_TENANT_KEYS.
func (k *Keyring) TenantKey(tenant string) string {
	return k.ids[0] + ":" + base64.StdEncoding.EncodeToString(deriveTenantKey(k.keys[0], tenant))
}

// TenantKeys is TenantKey for every master key in the ring, current first (during a rotation the server needs the old key's version to open older data).
func (k *Keyring) TenantKeys(tenant string) []string {
	out := make([]string, len(k.keys))
	for i := range k.keys {
		out[i] = k.ids[i] + ":" + base64.StdEncoding.EncodeToString(deriveTenantKey(k.keys[i], tenant))
	}
	return out
}

// ForTenantKeys returns the sealer of a tenant from the tenant's own keys ("<id>:<base64>", current first), as TenantKey prints them.
func ForTenantKeys(tenant string, specs ...string) (*Sealer, error) {
	if len(specs) == 0 {
		return nil, errors.New("seal: no tenant key given")
	}
	s := &Sealer{tenant: tenant}
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		i := strings.Index(spec, ":")
		if i <= 0 {
			return nil, errors.New("seal: a tenant key is <id>:<base64>")
		}
		b, err := base64.StdEncoding.DecodeString(spec[i+1:])
		if err != nil || len(b) != 32 {
			return nil, errors.New("seal: a tenant key is 32 bytes, base64")
		}
		s.keys = append(s.keys, tenantKey{spec[:i], b})
	}
	return s, nil
}

// ParseTenantKeys splits a comma or newline separated list of tenant keys.
func ParseTenantKeys(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' })
}

func (s *Sealer) isPlain() bool { return s == nil || s.plain }

func (s *Sealer) aead(i int) (cipher.AEAD, error) {
	b, err := aes.NewCipher(s.keys[i].key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (s *Sealer) aad(purpose string) []byte {
	return []byte("tenant:" + s.tenant + "\x00purpose:" + purpose)
}

// Seal encrypts a value for a purpose (a name for the field it belongs to, such as "push.key"). The same value sealed twice gives different results.
func (s *Sealer) Seal(purpose string, plaintext []byte) (string, error) {
	if s.isPlain() {
		return "plain:" + base64.StdEncoding.EncodeToString(plaintext), nil
	}
	g, err := s.aead(0)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return prefix + s.keys[0].id + "." + base64.RawStdEncoding.EncodeToString(append(nonce, g.Seal(nil, nonce, plaintext, s.aad(purpose))...)), nil
}

// ErrNotSealed is returned by Open for a value that is not in the sealed format (older data, or plain text).
var ErrNotSealed = errors.New("seal: value is not sealed")

// Open decrypts a value sealed for the same tenant and purpose with any key the sealer holds. A "plain:" value (written without a key) opens only on a plain sealer.
func (s *Sealer) Open(purpose, sealed string) ([]byte, error) {
	switch {
	case strings.HasPrefix(sealed, "plain:"):
		if !s.isPlain() {
			return nil, errors.New("seal: an unsealed value in a database that has a key; run the rekey command")
		}
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, "plain:"))
	case !strings.HasPrefix(sealed, prefix):
		return nil, ErrNotSealed
	}
	if s.isPlain() {
		return nil, errors.New("seal: a sealed value but no key is configured")
	}
	parts := strings.SplitN(strings.TrimPrefix(sealed, prefix), ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("seal: malformed value")
	}
	raw, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("seal: malformed value")
	}
	for i, k := range s.keys {
		if k.id != parts[0] {
			continue
		}
		g, err := s.aead(i)
		if err != nil {
			return nil, err
		}
		if len(raw) < g.NonceSize() {
			return nil, errors.New("seal: malformed value")
		}
		out, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], s.aad(purpose))
		if err != nil {
			return nil, errors.New("seal: the value does not open (wrong tenant, wrong field, or it was altered)")
		}
		return out, nil
	}
	return nil, fmt.Errorf("seal: the value was sealed with key %s, which is not configured", parts[0])
}

// Current reports whether a sealed value uses the current key (a value that does not is due to be re-sealed).
func (s *Sealer) Current(sealed string) bool {
	if s.isPlain() {
		return strings.HasPrefix(sealed, "plain:")
	}
	return strings.HasPrefix(sealed, prefix+s.keys[0].id+".")
}

// Rewrap re-seals a value with the current key. A value already under it is returned as it is.
func (s *Sealer) Rewrap(purpose, sealed string) (string, error) {
	if s.Current(sealed) {
		return sealed, nil
	}
	b, err := s.Open(purpose, sealed)
	if err != nil {
		return "", err
	}
	return s.Seal(purpose, b)
}

// Interface is what a store needs to seal its secrets; *Sealer implements it. Stores take the interface so they do not depend on this package's keys.
type Interface interface {
	Seal(purpose string, plaintext []byte) (string, error)
	Open(purpose, sealed string) ([]byte, error)
}

// Put seals a value for storage; with no sealer it stores the value as it is (an installation that has not configured a key).
func Put(s Interface, purpose string, b []byte) (string, error) {
	if s == nil {
		return string(b), nil
	}
	return s.Seal(purpose, b)
}

// Get reads a stored value. Values written before sealing was on (not in the sealed format) are returned as they are, so turning sealing on does not break existing data;
// the rekey command seals them.
func Get(s Interface, purpose, stored string) ([]byte, error) {
	if s == nil {
		return []byte(stored), nil
	}
	b, err := s.Open(purpose, stored)
	if errors.Is(err, ErrNotSealed) {
		return []byte(stored), nil
	}
	return b, err
}

// Sealed reports whether a stored value is in the sealed format.
func Sealed(stored string) bool {
	return strings.HasPrefix(stored, prefix) || strings.HasPrefix(stored, "plain:")
}

// Reseal brings a stored value to the current key. A value already under it is left alone (changed false); one written before sealing was on, or under an older key, is sealed again.
func Reseal(s Interface, purpose, stored string) (out string, changed bool, err error) {
	if s == nil {
		return stored, false, nil
	}
	if c, ok := s.(interface{ Current(string) bool }); ok && Sealed(stored) && c.Current(stored) {
		return stored, false, nil
	}
	b, err := Get(s, purpose, stored)
	if err != nil {
		return "", false, err
	}
	out, err = s.Seal(purpose, b)
	return out, true, err
}
