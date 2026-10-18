package acme

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/pki"
)

// Issuer makes the certificate for a verified request.
type Issuer interface {
	// Issue returns a certificate chain (PEM, leaf first) for the key in the CSR, naming the device the identifiers describe.
	Issue(ctx context.Context, csr *x509.CertificateRequest, ids []Identifier) ([]byte, error)
}

// CAIssuer issues device identity certificates from the server's own CA (the one SCEP uses), so a device that got its identity by ACME is accepted exactly like one that used SCEP.
type CAIssuer struct {
	Depot        *pki.MongoDepot
	Pass         string
	Organization string
	Days         int
	Now          func() time.Time
}

// Issue implements Issuer.
func (c *CAIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest, ids []Identifier) ([]byte, error) {
	if len(ids) == 0 {
		return nil, errors.New("no identifiers")
	}
	crts, key, err := c.Depot.CA([]byte(c.Pass))
	if err != nil {
		return nil, err
	}
	serial, err := c.Depot.Serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	days := c.Days
	if days == 0 {
		days = 365
	}
	cn := ids[0].Value
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{c.Organization}},
		NotBefore:    now.Add(-10 * time.Minute),
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, crts[0], csr.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := c.Depot.Put(cn, leaf); err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, ca := range crts {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
	return out, nil
}
