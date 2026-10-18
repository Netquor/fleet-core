// Package acme is an ACME server (RFC 8555) with Apple's device attestation (device-attest-01), the way a Mac, iPhone or iPad gets its identity certificate with a key that never leaves its
// secure hardware: the device proves, with a certificate chain from Apple, which device it is and that the key was made in its hardware; the server issues a certificate for exactly that key.
// It replaces SCEP for enrollment where the device supports it (iOS 16, macOS 13.1) and is the way to hand a hardware-bound identity to a managed app or a network.
package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// Server is the ACME endpoint.
type Server struct {
	Store *Store
	// BaseURL is the server's public address (https://host); ACME lives under /acme.
	BaseURL string
	Issuer  Issuer
	// Roots are the trust anchors for attestations; AppleAttestationRoots() unless a test says otherwise.
	Roots *x509.CertPool
	// Authorize decides whether a device may have a certificate: it is called with each identifier of an order (permanent-identifier: the serial number; hardware-identifier: the UDID)
	// before anything is attested. Nothing is issued if it refuses.
	Authorize func(ctx context.Context, id Identifier) error
	Now       func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) url(path string) string { return strings.TrimRight(s.BaseURL, "/") + "/acme" + path }

type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, kind, detail string) {
	s.nonce(w, r)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{"urn:ietf:params:acme:error:" + kind, detail, status})
}

func (s *Server) nonce(w http.ResponseWriter, r *http.Request) {
	if n, err := s.Store.Nonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", n)
	}
	w.Header().Set("Cache-Control", "no-store")
}

func (s *Server) write(w http.ResponseWriter, r *http.Request, status int, v any, loc string) {
	s.nonce(w, r)
	w.Header().Set("Content-Type", "application/json")
	if loc != "" {
		w.Header().Set("Location", loc)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// req is a verified request.
type req struct {
	acct    *account
	payload []byte
	key     *jwk // the key of a new account
}

// parse reads a signed request: nonce spent, url right, signature good, and the account known (or its key given, for a new account).
func (s *Server) parse(w http.ResponseWriter, r *http.Request, newAccount bool) (*req, bool) {
	if r.Method != http.MethodPost {
		s.fail(w, r, http.StatusMethodNotAllowed, "malformed", "POST is expected")
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var env envelope
	if err != nil || json.Unmarshal(b, &env) != nil || env.Protected == "" || env.Signature == "" {
		s.fail(w, r, http.StatusBadRequest, "malformed", "the body is not a signed request")
		return nil, false
	}
	var p protected
	ph, err := b64(env.Protected)
	if err != nil || json.Unmarshal(ph, &p) != nil {
		s.fail(w, r, http.StatusBadRequest, "malformed", "the protected header is not valid")
		return nil, false
	}
	if p.URL != s.url(strings.TrimPrefix(r.URL.Path, "/acme")) {
		s.fail(w, r, http.StatusUnauthorized, "unauthorized", "the signed url does not match the request")
		return nil, false
	}
	if ok, _ := s.Store.useNonce(r.Context(), p.Nonce); !ok {
		s.fail(w, r, http.StatusBadRequest, "badNonce", "the nonce is not one this server gave, or it was used")
		return nil, false
	}
	out := &req{}
	var pub any
	switch {
	case p.JWK != nil && p.KID == "":
		if !newAccount {
			s.fail(w, r, http.StatusBadRequest, "malformed", "this request is signed with the account's kid, not a jwk")
			return nil, false
		}
		pub, err = p.JWK.key()
		if err != nil {
			s.fail(w, r, http.StatusBadRequest, "badPublicKey", err.Error())
			return nil, false
		}
		out.key = p.JWK
	case p.KID != "" && p.JWK == nil:
		id := strings.TrimPrefix(p.KID, s.url("/account/"))
		acct, err := s.Store.account(r.Context(), id)
		if err != nil || acct == nil || p.KID != s.url("/account/"+id) {
			s.fail(w, r, http.StatusUnauthorized, "accountDoesNotExist", "no such account")
			return nil, false
		}
		out.acct = acct
		pub, _ = acct.JWK.key()
	default:
		s.fail(w, r, http.StatusBadRequest, "malformed", "the header has either a jwk (new account) or a kid, not both")
		return nil, false
	}
	switch p.Alg {
	case "ES256", "ES384", "RS256":
	default:
		s.fail(w, r, http.StatusBadRequest, "badSignatureAlgorithm", "ES256, ES384 and RS256 are supported")
		return nil, false
	}
	if err := env.verify(pub, p.Alg); err != nil {
		s.fail(w, r, http.StatusUnauthorized, "unauthorized", err.Error())
		return nil, false
	}
	if env.Payload != "" {
		if out.payload, err = b64(env.Payload); err != nil {
			s.fail(w, r, http.StatusBadRequest, "malformed", "the payload is not base64url")
			return nil, false
		}
	}
	return out, true
}

// Handler serves /acme/.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/acme/directory", func(w http.ResponseWriter, r *http.Request) {
		s.write(w, r, 200, map[string]any{"newNonce": s.url("/new-nonce"), "newAccount": s.url("/new-account"), "newOrder": s.url("/new-order"), "meta": map[string]any{"externalAccountRequired": false}}, "")
	})
	mux.HandleFunc("/acme/new-nonce", func(w http.ResponseWriter, r *http.Request) {
		s.nonce(w, r)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/acme/new-account", s.newAccount)
	mux.HandleFunc("/acme/new-order", s.newOrder)
	mux.HandleFunc("/acme/authz/", s.getAuthz)
	mux.HandleFunc("/acme/challenge/", s.challenge)
	mux.HandleFunc("/acme/order/", s.getOrder)
	mux.HandleFunc("/acme/finalize/", s.finalize)
	mux.HandleFunc("/acme/cert/", s.cert)
	return mux
}

func (s *Server) newAccount(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parse(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Contact            []string `json:"contact"`
		OnlyReturnExisting bool     `json:"onlyReturnExisting"`
	}
	if len(q.payload) > 0 {
		_ = json.Unmarshal(q.payload, &body)
	}
	tp := q.key.thumbprint()
	if existing, _ := s.Store.accountByThumbprint(r.Context(), tp); existing != nil {
		s.write(w, r, 200, map[string]any{"status": "valid", "contact": existing.Contact}, s.url("/account/"+existing.ID))
		return
	}
	if body.OnlyReturnExisting {
		s.fail(w, r, http.StatusBadRequest, "accountDoesNotExist", "no account for this key")
		return
	}
	a := account{ID: newID(12), Thumbprint: tp, JWK: *q.key, Contact: body.Contact, CreatedAt: s.now()}
	if err := s.Store.putAccount(r.Context(), a); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "serverInternal", "could not save the account")
		return
	}
	s.write(w, r, 201, map[string]any{"status": "valid", "contact": a.Contact}, s.url("/account/"+a.ID))
}

func (s *Server) orderView(o *order) map[string]any {
	authz := make([]string, len(o.Authz))
	for i, a := range o.Authz {
		authz[i] = s.url("/authz/" + a)
	}
	v := map[string]any{"status": o.Status, "expires": o.Expires.UTC().Format(time.RFC3339), "identifiers": o.Identifiers, "authorizations": authz, "finalize": s.url("/finalize/" + o.ID)}
	if o.Cert != "" {
		v["certificate"] = s.url("/cert/" + o.Cert)
	}
	return v
}

func (s *Server) newOrder(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parse(w, r, false)
	if !ok {
		return
	}
	var body struct {
		Identifiers []Identifier `json:"identifiers"`
	}
	if json.Unmarshal(q.payload, &body) != nil || len(body.Identifiers) == 0 || len(body.Identifiers) > 4 {
		s.fail(w, r, http.StatusBadRequest, "malformed", "an order names one to four identifiers")
		return
	}
	for _, id := range body.Identifiers {
		if id.Type != "permanent-identifier" && id.Type != "hardware-identifier" || id.Value == "" {
			s.fail(w, r, http.StatusBadRequest, "unsupportedIdentifier", "only permanent-identifier (serial number) and hardware-identifier (UDID) are supported")
			return
		}
		if s.Authorize != nil {
			if err := s.Authorize(r.Context(), id); err != nil {
				s.fail(w, r, http.StatusForbidden, "unauthorized", "this server does not issue to that device")
				return
			}
		}
	}
	now := s.now().UTC()
	o := &order{ID: newID(12), Account: q.acct.ID, Identifiers: body.Identifiers, Status: "pending", CreatedAt: now, Expires: now.Add(24 * time.Hour)}
	for _, id := range body.Identifiers {
		a := authz{ID: newID(12), Account: q.acct.ID, Order: o.ID, Identifier: id, Status: "pending", Token: newID(24), Challenge: newID(12), CreatedAt: now, Expires: now.Add(24 * time.Hour)}
		if err := s.Store.put(r.Context(), "acme_authz", a.ID, a, a.CreatedAt); err != nil {
			s.fail(w, r, http.StatusInternalServerError, "serverInternal", "could not save the order")
			return
		}
		o.Authz = append(o.Authz, a.ID)
	}
	if err := s.Store.put(r.Context(), "acme_orders", o.ID, o, o.CreatedAt); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "serverInternal", "could not save the order")
		return
	}
	s.write(w, r, 201, s.orderView(o), s.url("/order/"+o.ID))
}

func (s *Server) authzView(a *authz) map[string]any {
	ch := map[string]any{"type": "device-attest-01", "url": s.url("/challenge/" + a.ID), "token": a.Token, "status": a.Status}
	return map[string]any{"status": a.Status, "identifier": a.Identifier, "expires": a.Expires.UTC().Format(time.RFC3339), "challenges": []any{ch}}
}

func idOf(r *http.Request, prefix string) string { return strings.TrimPrefix(r.URL.Path, prefix) }

func (s *Server) ownAuthz(w http.ResponseWriter, r *http.Request, q *req, id string) *authz {
	var a authz
	ok, err := s.Store.get(r.Context(), "acme_authz", id, &a)
	if err != nil || !ok || a.Account != q.acct.ID {
		s.fail(w, r, http.StatusNotFound, "malformed", "no such authorization")
		return nil
	}
	return &a
}

func (s *Server) getAuthz(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parse(w, r, false)
	if !ok {
		return
	}
	if a := s.ownAuthz(w, r, q, idOf(r, "/acme/authz/")); a != nil {
		s.write(w, r, 200, s.authzView(a), "")
	}
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parse(w, r, false)
	if !ok {
		return
	}
	a := s.ownAuthz(w, r, q, idOf(r, "/acme/challenge/"))
	if a == nil {
		return
	}
	if a.Status == "valid" {
		s.write(w, r, 200, map[string]any{"type": "device-attest-01", "status": "valid", "url": s.url("/challenge/" + a.ID), "token": a.Token}, "")
		return
	}
	if a.Status != "pending" || s.now().After(a.Expires) {
		s.fail(w, r, http.StatusBadRequest, "malformed", "the authorization is no longer pending")
		return
	}
	var body struct {
		AttObj string `json:"attObj"`
	}
	if json.Unmarshal(q.payload, &body) != nil || body.AttObj == "" {
		s.fail(w, r, http.StatusBadRequest, "malformed", "the attestation object (attObj) is required")
		return
	}
	raw, err := b64(strings.TrimRight(body.AttObj, "="))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "malformed", "attObj is not base64url")
		return
	}
	roots := s.Roots
	if roots == nil {
		roots = AppleAttestationRoots()
	}
	keyAuth := a.Token + "." + q.acct.Thumbprint
	att, err := VerifyAttestation(raw, keyAuth, roots, s.now())
	if err != nil {
		a.Status = "invalid"
		_ = s.Store.put(r.Context(), "acme_authz", a.ID, a, a.CreatedAt)
		s.fail(w, r, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	// The attested device must be the one the order names.
	named := att.Serial
	if a.Identifier.Type == "hardware-identifier" {
		named = att.UDID
	}
	if !strings.EqualFold(named, a.Identifier.Value) {
		a.Status = "invalid"
		_ = s.Store.put(r.Context(), "acme_authz", a.ID, a, a.CreatedAt)
		s.fail(w, r, http.StatusForbidden, "unauthorized", "the attestation is for another device than the order names")
		return
	}
	a.Status, a.AttestedKey = "valid", att.PublicKey
	if err := s.Store.put(r.Context(), "acme_authz", a.ID, a, a.CreatedAt); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "serverInternal", "could not save the result")
		return
	}
	// The order is ready when every identifier is attested.
	var o order
	if ok, _ := s.Store.get(r.Context(), "acme_orders", a.Order, &o); ok && o.Status == "pending" {
		ready := true
		for _, id := range o.Authz {
			var other authz
			if ok, _ := s.Store.get(r.Context(), "acme_authz", id, &other); !ok || other.Status != "valid" {
				ready = false
			}
		}
		if ready {
			o.Status = "ready"
			_ = s.Store.put(r.Context(), "acme_orders", o.ID, o, o.CreatedAt)
		}
	}
	s.write(w, r, 200, map[string]any{"type": "device-attest-01", "status": "valid", "url": s.url("/challenge/" + a.ID), "token": a.Token}, "")
}

func (s *Server) ownOrder(w http.ResponseWriter, r *http.Request, q *req, id string) *order {
	var o order
	ok, err := s.Store.get(r.Context(), "acme_orders", id, &o)
	if err != nil || !ok || o.Account != q.acct.ID {
		s.fail(w, r, http.StatusNotFound, "malformed", "no such order")
		return nil
	}
	return &o
}

func (s *Server) getOrder(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parse(w, r, false)
	if !ok {
		return
	}
	if o := s.ownOrder(w, r, q, idOf(r, "/acme/order/")); o != nil {
		s.write(w, r, 200, s.orderView(o), "")
	}
}

func (s *Server) finalize(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parse(w, r, false)
	if !ok {
		return
	}
	o := s.ownOrder(w, r, q, idOf(r, "/acme/finalize/"))
	if o == nil {
		return
	}
	if o.Status != "ready" || s.now().After(o.Expires) {
		s.fail(w, r, http.StatusForbidden, "orderNotReady", "the order is not ready: every identifier must be attested first")
		return
	}
	var body struct {
		CSR string `json:"csr"`
	}
	if json.Unmarshal(q.payload, &body) != nil || body.CSR == "" {
		s.fail(w, r, http.StatusBadRequest, "badCSR", "a csr is required")
		return
	}
	der, err := b64(strings.TrimRight(body.CSR, "="))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "badCSR", "the csr is not base64url")
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		s.fail(w, r, http.StatusBadRequest, "badCSR", "the csr is not valid")
		return
	}
	// The certificate is for the key the device attested, and only that one.
	spki, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	for _, id := range o.Authz {
		var a authz
		if ok, _ := s.Store.get(r.Context(), "acme_authz", id, &a); !ok || string(a.AttestedKey) != string(spki) {
			s.fail(w, r, http.StatusBadRequest, "badCSR", "the csr is for a key the device did not attest")
			return
		}
	}
	chain, err := s.Issuer.Issue(r.Context(), csr, o.Identifiers)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "serverInternal", "the certificate could not be issued")
		return
	}
	certID := newID(12)
	if err := s.Store.put(r.Context(), "acme_certs", certID, map[string]any{"account": q.acct.ID, "pem": string(chain), "created_at": s.now()}, s.now()); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "serverInternal", "could not save the certificate")
		return
	}
	o.Status, o.Cert = "valid", certID
	_ = s.Store.put(r.Context(), "acme_orders", o.ID, o, o.CreatedAt)
	s.write(w, r, 200, s.orderView(o), "")
}

func (s *Server) cert(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parse(w, r, false)
	if !ok {
		return
	}
	var c struct {
		Account string `bson:"account"`
		PEM     string `bson:"pem"`
	}
	found, err := s.Store.get(r.Context(), "acme_certs", idOf(r, "/acme/cert/"), &c)
	if err != nil || !found || c.Account != q.acct.ID {
		s.fail(w, r, http.StatusNotFound, "malformed", "no such certificate")
		return
	}
	s.nonce(w, r)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write([]byte(c.PEM))
}

var _ = base64.RawURLEncoding
var _ = errors.New
