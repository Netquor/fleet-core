package acme

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

//go:embed certs/apple-enterprise-attestation-root.pem
var appleAttestationRootPEM []byte

// AppleAttestationRoots is the trust anchor for device attestations: Apple's Enterprise Attestation Root CA.
func AppleAttestationRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	for rest := appleAttestationRootPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			pool.AddCert(c)
		}
	}
	return pool
}

// The extensions Apple puts in the attestation certificate.
var (
	oidSerial = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 1}
	oidUDID   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}
	oidNonce  = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 11, 1}
)

// Attestation is what a verified Apple attestation says.
type Attestation struct {
	Serial string
	UDID   string
	// PublicKey is the attested key, as a DER SubjectPublicKeyInfo: the key the device holds in its secure hardware.
	PublicKey []byte
	Leaf      *x509.Certificate
}

type attObject struct {
	Fmt     string `cbor:"fmt"`
	AttStmt struct {
		X5c [][]byte `cbor:"x5c"`
	} `cbor:"attStmt"`
}

// strExt reads a string-valued certificate extension (Apple writes them as DER strings).
func strExt(c *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			var raw asn1.RawValue
			if rest, err := asn1.Unmarshal(e.Value, &raw); err == nil && len(rest) == 0 && raw.Tag != asn1.TagSequence {
				return string(raw.Bytes)
			}
			return string(e.Value)
		}
	}
	return ""
}

// hasNonce reports whether the freshness extension carries want. The value may be wrapped as DER octet strings (how many layers is not fixed), and a
// hash can itself parse as DER, so each layer is compared rather than peeling blindly until nothing parses.
func hasNonce(c *x509.Certificate, want []byte) bool {
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidNonce) {
			continue
		}
		v := e.Value
		for i := 0; i < 4; i++ {
			if bytes.Equal(v, want) {
				return true
			}
			var raw asn1.RawValue
			rest, err := asn1.Unmarshal(v, &raw)
			if err != nil || len(rest) != 0 {
				break
			}
			v = raw.Bytes
		}
	}
	return false
}

// VerifyAttestation checks a device attestation object (CBOR, format "apple"): the certificate chain leads to the roots, and the leaf carries the freshness nonce that ties it to this
// challenge (the SHA-256 of the key authorization). It returns who the device says it is and the key it attested.
func VerifyAttestation(attObj []byte, keyAuthorization string, roots *x509.CertPool, now time.Time) (*Attestation, error) {
	var o attObject
	if err := cbor.Unmarshal(attObj, &o); err != nil {
		return nil, fmt.Errorf("the attestation is not a CBOR object: %w", err)
	}
	if o.Fmt != "apple" {
		return nil, fmt.Errorf("attestation format %q is not supported", o.Fmt)
	}
	if len(o.AttStmt.X5c) < 2 {
		return nil, errors.New("the attestation carries no certificate chain")
	}
	var certs []*x509.Certificate
	for _, der := range o.AttStmt.X5c {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("a certificate in the attestation is malformed")
		}
		certs = append(certs, c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	leaf := certs[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, errors.New("the attestation does not lead to Apple's attestation root")
	}
	want := sha256.Sum256([]byte(keyAuthorization))
	if !hasNonce(leaf, want[:]) {
		return nil, errors.New("the attestation is not for this challenge (its freshness nonce differs)")
	}
	a := &Attestation{Serial: strExt(leaf, oidSerial), UDID: strExt(leaf, oidUDID), PublicKey: leaf.RawSubjectPublicKeyInfo, Leaf: leaf}
	if a.Serial == "" && a.UDID == "" {
		return nil, errors.New("the attestation names no device")
	}
	return a, nil
}
