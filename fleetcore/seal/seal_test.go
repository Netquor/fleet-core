package seal

import (
	"bytes"
	"strings"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSealOpen(t *testing.T) {
	k, _ := NewKeyring(key(1))
	a := k.For("tenant-a")
	s1, err := a.Seal("push.key", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := a.Seal("push.key", []byte("secret"))
	if s1 == s2 || strings.Contains(s1, "secret") {
		t.Error("sealing is not randomized, or leaks")
	}
	if got, err := a.Open("push.key", s1); err != nil || string(got) != "secret" {
		t.Fatalf("%q %v", got, err)
	}
	// another tenant, another field, or a changed value does not open
	if _, err := k.For("tenant-b").Open("push.key", s1); err == nil {
		t.Error("a value opened for another tenant")
	}
	if _, err := a.Open("bootstrap", s1); err == nil {
		t.Error("a value opened for another field")
	}
	if _, err := a.Open("push.key", s1[:len(s1)-3]+"AAA"); err == nil {
		t.Error("an altered value opened")
	}
	// a different master key does not open it
	other, _ := NewKeyring(key(2))
	if _, err := other.For("tenant-a").Open("push.key", s1); err == nil {
		t.Error("opened under the wrong master key")
	}
	if _, err := a.Open("x", "just text"); err != ErrNotSealed {
		t.Errorf("plain text: %v", err)
	}
}

func TestRotation(t *testing.T) {
	old, _ := NewKeyring(key(1))
	sealed, _ := old.For("t").Seal("f", []byte("v"))
	rotated, _ := NewKeyring(key(2), key(1)) // new key first, the old still opens
	s := rotated.For("t")
	if s.Current(sealed) {
		t.Error("an old value reports as current")
	}
	if got, err := s.Open("f", sealed); err != nil || string(got) != "v" {
		t.Fatalf("old value under the rotated keyring: %v", err)
	}
	re, err := s.Rewrap("f", sealed)
	if err != nil || !s.Current(re) {
		t.Fatalf("rewrap: %v", err)
	}
	onlyNew, _ := NewKeyring(key(2))
	if got, err := onlyNew.For("t").Open("f", re); err != nil || string(got) != "v" {
		t.Errorf("after rewrap the old key is no longer needed: %v", err)
	}
	if _, err := onlyNew.For("t").Open("f", sealed); err == nil {
		t.Error("an old value opened without its key")
	}
	if same, _ := s.Rewrap("f", re); same != re {
		t.Error("rewrapping a current value changed it")
	}
}

func TestPlainAndPassphrase(t *testing.T) {
	p := Plain().For("t")
	v, _ := p.Seal("f", []byte("dev"))
	if got, err := p.Open("f", v); err != nil || string(got) != "dev" {
		t.Fatal(err)
	}
	k, _ := FromPassphrase("correct horse")
	if _, err := k.For("t").Open("f", v); err == nil {
		t.Error("an unsealed value was accepted by a keyring with a key")
	}
	k2, _ := FromPassphrase("correct horse")
	sv, _ := k.For("t").Seal("f", []byte("x"))
	if got, err := k2.For("t").Open("f", sv); err != nil || string(got) != "x" {
		t.Errorf("the same passphrase must give the same key: %v", err)
	}
	keys, err := ParseKeys("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=, AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=")
	if err != nil || len(keys) != 2 || len(keys[0]) != 32 {
		t.Errorf("%v %d", err, len(keys))
	}
	if _, err := NewKeyring([]byte("short")); err == nil {
		t.Error("a short key was accepted")
	}
}

// A tenant's server holds only that tenant's key: it opens that tenant's data, nobody else's, and the master key is not on it.
func TestTenantKeysAreEnough(t *testing.T) {
	master, _ := NewKeyring(key(5))
	provisioner := master.For("acme")
	sealed, _ := provisioner.Seal("push.key", []byte("secret"))

	instance, err := ForTenantKeys("acme", master.TenantKey("acme"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := instance.Open("push.key", sealed); err != nil || string(got) != "secret" {
		t.Fatalf("the tenant's own key must open its data: %v", err)
	}
	// what the instance seals, the provisioner (with the master) can open: they agree
	fromInstance, _ := instance.Seal("push.key", []byte("new"))
	if got, err := provisioner.Open("push.key", fromInstance); err != nil || string(got) != "new" {
		t.Errorf("master and tenant key disagree: %v", err)
	}
	// acme's key does not open another tenant's data, even if someone copies it there
	other := master.For("globex")
	otherSealed, _ := other.Seal("push.key", []byte("globex secret"))
	if _, err := instance.Open("push.key", otherSealed); err == nil {
		t.Error("acme's key opened globex's data")
	}
	asGlobex, _ := ForTenantKeys("globex", master.TenantKey("acme"))
	if _, err := asGlobex.Open("push.key", otherSealed); err == nil {
		t.Error("acme's key presented as globex's opened globex's data")
	}
	if _, err := ForTenantKeys("x", "not-a-key"); err == nil {
		t.Error("a malformed tenant key was accepted")
	}
	// rotation: the instance gets both versions of its key
	rotated, _ := NewKeyring(key(6), key(5))
	both, _ := ForTenantKeys("acme", rotated.TenantKeys("acme")...)
	if got, err := both.Open("push.key", sealed); err != nil || string(got) != "secret" {
		t.Errorf("the old key version must still open during rotation: %v", err)
	}
	if both.Current(sealed) {
		t.Error("an old value reports as current")
	}
}
