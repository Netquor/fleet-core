package dep

import (
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"io"
	"net/http"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/enroll"
	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"
)

//go:embed certs/apple-root-ca.pem
var appleRootPEM []byte

// AppleRoots is the trust anchor for the device certificates that sign an Automated Device Enrollment request (Apple Root CA).
func AppleRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	for rest := appleRootPEM; ; {
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

// ADE serves the enrollment profile to a device that Apple assigned to this server, with no code or sign-in: the device proves what it is, the server knows which devices Apple assigned.
// A device in Setup Assistant asks for the profile named in its DEP profile's url, with a request signed by the device's own Apple-issued certificate (serial number, UDID, model, OS).
type ADE struct {
	// Roots are the trust anchors for the device certificate; AppleRoots() unless a test says otherwise.
	Roots *x509.CertPool
	// Service knows which serial numbers Apple assigned to this server.
	Service *Service
	// Profile and Challenges make the enrollment profile.
	Profile    enroll.Options
	Challenges enroll.ChallengeSource
	Now        func() time.Time
	// OnEnroll, if set, is told which device (serial) is enrolling and under which DEP name.
	OnEnroll func(ctx context.Context, serial, udid, depName string)
}

type adeRequest struct {
	Serial  string `plist:"SERIAL"`
	UDID    string `plist:"UDID"`
	Product string `plist:"PRODUCT"`
	Version string `plist:"VERSION"`
}

// Handler is the endpoint (serve it at /enroll/ade).
func (a *ADE) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || len(body) == 0 {
			http.Error(w, "a signed request is expected", http.StatusBadRequest)
			return
		}
		p7, err := pkcs7.Parse(body)
		if err != nil {
			http.Error(w, "not a signed request", http.StatusBadRequest)
			return
		}
		if err := p7.Verify(); err != nil {
			http.Error(w, "the signature does not verify", http.StatusUnauthorized)
			return
		}
		signer := p7.GetOnlySigner()
		if signer == nil {
			http.Error(w, "exactly one signer is expected", http.StatusUnauthorized)
			return
		}
		inter := x509.NewCertPool()
		for _, c := range p7.Certificates {
			inter.AddCert(c)
		}
		now := time.Now()
		if a.Now != nil {
			now = a.Now()
		}
		roots := a.Roots
		if roots == nil {
			roots = AppleRoots()
		}
		if _, err := signer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			http.Error(w, "the device certificate is not Apple's", http.StatusUnauthorized)
			return
		}
		var req adeRequest
		if err := plist.Unmarshal(p7.Content, &req); err != nil || req.Serial == "" {
			http.Error(w, "the request names no device", http.StatusBadRequest)
			return
		}
		depName, ok, err := a.Service.Lookup(r.Context(), req.Serial)
		if err != nil {
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			// Apple has not assigned this device to this server: it gets no profile.
			http.Error(w, "this device is not assigned to this server", http.StatusForbidden)
			return
		}
		pw, err := a.Challenges.SCEPChallenge()
		if err != nil {
			http.Error(w, "could not make a challenge", http.StatusInternalServerError)
			return
		}
		prof, err := enroll.Build(a.Profile, pw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if a.OnEnroll != nil {
			a.OnEnroll(r.Context(), req.Serial, req.UDID, depName)
		}
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(prof)
	})
}
