// Package server puts a whole MDM server in one process: the NanoMDM protocol service, a SCEP certificate authority, enrollment profiles, TLS, and the management API, all on one
// HTTP handler and one storage. It is what cmd/fleetcore runs; tests run it in-process.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	kitlog "github.com/go-kit/kit/log"
	nlhttp "github.com/micromdm/nanolib/http"
	"github.com/micromdm/nanolib/http/trace"
	"github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/certverify"
	"github.com/micromdm/nanomdm/cryptoutil"
	"github.com/micromdm/nanomdm/fleetcore/commands"
	"github.com/micromdm/nanomdm/fleetcore/dep"
	"github.com/micromdm/nanomdm/fleetcore/enroll"
	"github.com/micromdm/nanomdm/fleetcore/pki"
	httpapi "github.com/micromdm/nanomdm/http/api"
	httpmdm "github.com/micromdm/nanomdm/http/mdm"
	"github.com/micromdm/nanomdm/push/nanopush"
	pushsvc "github.com/micromdm/nanomdm/push/service"
	"github.com/micromdm/nanomdm/service"
	"github.com/micromdm/nanomdm/service/certauth"
	"github.com/micromdm/nanomdm/service/multi"
	"github.com/micromdm/nanomdm/service/nanomdm"
	"github.com/micromdm/nanomdm/service/webhook"
	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/nanomdm/storage/mongodb"

	scepchallenge "github.com/micromdm/scep/v2/challenge"
	scepdepot "github.com/micromdm/scep/v2/depot"
	scepserver "github.com/micromdm/scep/v2/server"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// CertSource is how the device's identity certificate reaches the MDM handlers.
type CertSource string

const (
	// CertFromTLS: the device presents it in the TLS handshake (this server terminates TLS).
	CertFromTLS CertSource = "tls"
	// CertFromSignature: the device signs each request (Mdm-Signature) and TLS may end anywhere in front (a CDN, a proxy). The enrollment profile sets SignMessage.
	CertFromSignature CertSource = "signature"
	// CertFromHeader: a proxy in front passes the certificate in a header (Config.CertHeader).
	CertFromHeader CertSource = "header"
)

// Config is everything a server needs.
type Config struct {
	// BaseURL is the public address devices use, for example https://mdm.example.com (no trailing slash).
	BaseURL string
	// Organization names the CA and the profile.
	Organization string
	// ProfileIdentifier is the enrollment profile's identifier, for example com.example.mdm.enroll.
	ProfileIdentifier string
	// Topic is the APNs topic of the push certificate (com.apple.mgmt.External.<uuid>); the enrollment profile carries it.
	Topic string

	Storage storage.AllStorage
	// PKIDB and PKITenant: where the CA lives (MongoDB). Tenant empty: the database is one tenant's.
	PKIDB     *mongo.Database
	PKITenant string
	// CAPass encrypts the CA's private key at rest; empty stores it unencrypted (development only).
	CAPass string
	CA     pki.CAOptions
	// SCEPValidityDays is how long a device identity certificate lives (default 365).
	SCEPValidityDays int
	// ChallengeTTL is how long a one-use SCEP challenge works (default 24 hours).
	ChallengeTTL time.Duration

	CertSource CertSource
	CertHeader string
	// AllowRetroactive lets a device that enrolled before certificates were checked be associated with one on its next check-in.
	AllowRetroactive bool

	// APIKey enables the management API under /v1 (HTTP basic auth, user "fleetcore"); empty disables it.
	APIKey string
	// PushURL overrides the APNs server (tests).
	PushURL string
	// WebhookURL receives every MDM event; WebhookHMACKey signs them.
	WebhookURL     string
	WebhookHMACKey string
	// SeparateCheckin serves check-ins at /checkin and commands at /mdm.
	SeparateCheckin bool
	// EnrollAuthorize, if set, decides who may download an enrollment profile (a code, an invite, a session).
	EnrollAuthorize func(*http.Request) error

	Logger log.Logger
	Debug  bool
	// Version is shown at /version.
	Version string
}

// Server is a configured fleetcore.
type Server struct {
	Handler http.Handler
	// CAPool holds the device-identity CA: the roots a client certificate is checked against, and what a TLS listener offers as acceptable client CAs.
	CAPool *x509.CertPool
	Depot  *pki.MongoDepot
	// DEP is Automated Device Enrollment (nil without an API key). Call Run to start its syncers.
	DEP *dep.Service
	cfg Config
}

const (
	endpointMDM     = "/mdm"
	endpointCheckin = "/checkin"
	endpointSCEP    = "/scep"
	endpointEnroll  = "/enroll"
)

// New builds the server: it makes the CA on first start, wires SCEP, the enrollment profile, the MDM service and the API, and returns the handler.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.BaseURL == "" || cfg.Storage == nil || cfg.PKIDB == nil {
		return nil, errors.New("fleetcore needs a base URL, a storage and a database for the CA")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.Logger == nil {
		cfg.Logger = log.NopLogger
	}
	if cfg.CertSource == "" {
		cfg.CertSource = CertFromSignature
	}
	if cfg.SCEPValidityDays == 0 {
		cfg.SCEPValidityDays = 365
	}
	if cfg.ProfileIdentifier == "" {
		cfg.ProfileIdentifier = "mdm.enroll"
	}
	if cfg.CA.CommonName == "" {
		cfg.CA.CommonName = "Device Management CA"
	}
	if cfg.CA.Organization == "" {
		cfg.CA.Organization = cfg.Organization
	}

	// ---- the CA and SCEP ----
	depot, err := pki.NewMongoDepot(ctx, cfg.PKIDB, cfg.PKITenant)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	caCert, err := depot.EnsureCA(ctx, cfg.CAPass, cfg.CA)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	crts, key, err := depot.CA([]byte(cfg.CAPass))
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	challenges := depot.Challenges(cfg.ChallengeTTL)
	signer := scepdepot.NewSigner(depot, scepdepot.WithCAPass(cfg.CAPass), scepdepot.WithAllowRenewalDays(0), scepdepot.WithValidityDays(cfg.SCEPValidityDays))
	csrSigner := scepchallenge.Middleware(challenges, scepserver.SignCSRAdapter(signer))
	scepSvc, err := scepserver.NewService(crts[0], key, csrSigner, scepserver.WithLogger(kitlog.NewNopLogger()))
	if err != nil {
		return nil, fmt.Errorf("scep: %w", err)
	}
	scepHandler := scepserver.MakeHTTPHandler(scepserver.MakeServerEndpoints(scepSvc), scepSvc, kitlog.NewNopLogger())

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	caPEM := cryptoutil.PEMCertificate(caCert.Raw)
	verifier, err := certverify.NewPoolVerifier(caPEM, nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}

	// ---- the MDM service ----
	logger := cfg.Logger
	nano := nanomdm.New(cfg.Storage,
		nanomdm.WithUserAuthenticate(nanomdm.NewUAService(cfg.Storage, false)),
		nanomdm.WithGetToken(nanomdm.NewTokenMux()),
		nanomdm.WithLogger(logger.With("service", "nanomdm")))
	var mdmService service.CheckinAndCommandService = nano
	if cfg.WebhookURL != "" {
		whOpts := []webhook.Option{webhook.WithTokenUpdateTalley(cfg.Storage), webhook.WithEventID(trace.GetTraceID)}
		if cfg.WebhookHMACKey != "" {
			whOpts = append(whOpts, webhook.WithHMACSecret([]byte(cfg.WebhookHMACKey)))
		}
		mdmService = multi.New(logger.With("service", "multi"), mdmService, webhook.New(cfg.WebhookURL, whOpts...))
	}
	certOpts := []certauth.Option{certauth.WithLogger(logger.With("service", "certauth"))}
	if cfg.AllowRetroactive {
		certOpts = append(certOpts, certauth.WithAllowRetroactive())
	}
	mdmService = certauth.New(mdmService, cfg.Storage, certOpts...)

	mux := http.NewServeMux()
	mdmAuth := nlhttp.NewMWMux(mux)
	switch cfg.CertSource {
	case CertFromTLS:
		mdmAuth.Use(func(h http.Handler) http.Handler {
			return httpmdm.CertExtractTLSMiddleware(h, logger.With("handler", "cert-extract"))
		})
	case CertFromHeader:
		if cfg.CertHeader == "" {
			return nil, errors.New("CertFromHeader needs a header name")
		}
		mdmAuth.Use(func(h http.Handler) http.Handler {
			return httpmdm.CertExtractPEMHeaderMiddleware(h, cfg.CertHeader, logger.With("handler", "cert-extract"))
		})
	case CertFromSignature:
		mdmAuth.Use(func(h http.Handler) http.Handler {
			return httpmdm.CertExtractMdmSignatureMiddleware(h, httpmdm.MdmSignatureVerifierFunc(cryptoutil.VerifyMdmSignature), httpmdm.SigLogWithLogger(logger.With("handler", "cert-extract")))
		})
	default:
		return nil, fmt.Errorf("unknown certificate source %q", cfg.CertSource)
	}
	mdmAuth.Use(func(h http.Handler) http.Handler {
		return httpmdm.CertVerifyMiddleware(h, verifier, logger.With("handler", "cert-verify"))
	})
	if cfg.SeparateCheckin {
		mdmAuth.Handle(endpointCheckin, httpmdm.CheckinHandler(mdmService, logger.With("handler", "checkin")))
		mdmAuth.Handle(endpointMDM, httpmdm.CommandAndReportResultsHandler(mdmService, logger.With("handler", "command")))
	} else {
		mdmAuth.Handle(endpointMDM, httpmdm.CheckinAndCommandHandler(mdmService, logger.With("handler", "checkin-command")))
	}

	// ---- SCEP and enrollment ----
	mux.Handle(endpointSCEP, scepHandler)
	prof := enroll.Options{
		Organization: cfg.Organization, Identifier: cfg.ProfileIdentifier, ServerURL: cfg.BaseURL + endpointMDM, SCEPURL: cfg.BaseURL + endpointSCEP,
		Topic: cfg.Topic, SignMessage: cfg.CertSource == CertFromSignature,
	}
	if cfg.SeparateCheckin {
		prof.CheckInURL = cfg.BaseURL + endpointCheckin
	}
	mux.Handle(endpointEnroll, enroll.Handler(prof, challenges, cfg.EnrollAuthorize))
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/version", nlhttp.NewJSONVersionHandler(cfg.Version))

	// ---- management API ----
	var depSvc *dep.Service
	if cfg.APIKey != "" {
		depStore, err := dep.New(ctx, cfg.PKIDB, cfg.PKITenant, cfg.CAPass)
		if err != nil {
			return nil, fmt.Errorf("dep storage: %w", err)
		}
		if depSvc, err = dep.NewService(ctx, cfg.PKIDB, depStore, cfg.PKITenant, logger.With("service", "dep")); err != nil {
			return nil, fmt.Errorf("dep service: %w", err)
		}
		mux.Handle("/v1/dep/", nlhttp.NewSimpleBasicAuthHandler(depSvc.Handler("/v1/dep"), "fleetcore", cfg.APIKey, "fleetcore"))

		apiAuth := nlhttp.NewMWMux(mux)
		apiAuth.Use(func(h http.Handler) http.Handler {
			return nlhttp.NewSimpleBasicAuthHandler(h, "fleetcore", cfg.APIKey, "fleetcore")
		})
		var popts []nanopush.Option
		if cfg.PushURL != "" {
			popts = append(popts, nanopush.WithPushServerURL(cfg.PushURL))
		}
		ps := pushsvc.New(cfg.Storage, cfg.Storage, nanopush.NewFactory(popts...), logger.With("service", "push"))
		httpapi.HandleAPIv1("/v1", apiAuth, logger, cfg.Storage, ps)

		// ---- JSON command API ----
		var results commands.ResultReader
		if rr, ok := cfg.Storage.(interface {
			CommandResults(ctx context.Context, commandUUID string) ([]mongodb.CommandResult, error)
		}); ok {
			results = resultAdapter{rr}
		}
		ch, err := commands.Handler("/v1/commands", commands.Default(), cfg.Storage, ps, results, logger.With("handler", "commands"))
		if err != nil {
			return nil, fmt.Errorf("command api: %w", err)
		}
		mux.Handle("/v1/commands", nlhttp.NewSimpleBasicAuthHandler(ch, "fleetcore", cfg.APIKey, "fleetcore"))
		mux.Handle("/v1/commands/", nlhttp.NewSimpleBasicAuthHandler(ch, "fleetcore", cfg.APIKey, "fleetcore"))
	}

	return &Server{Handler: trace.NewTraceLoggingHandler(mux, logger.With("handler", "log"), newTraceID), CAPool: pool, Depot: depot, DEP: depSvc, cfg: cfg}, nil
}

// TLSConfig for a listener that terminates TLS here: the given certificate (a public one devices trust), and a request for a client certificate, which is checked by the MDM handlers
// against the device-identity CA (not at the handshake, so browsers, SCEP clients and the enrollment page are not turned away).
func (s *Server) TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}, nil
}

func newTraceID(_ *http.Request) string {
	b := make([]byte, 8)
	f, err := os.Open("/dev/urandom")
	if err == nil {
		defer f.Close()
		_, _ = f.Read(b)
	}
	return fmt.Sprintf("%x", b)
}

// Run starts the background work (the DEP syncers) and returns when ctx ends.
func (s *Server) Run(ctx context.Context) error {
	if s.DEP == nil {
		<-ctx.Done()
		return nil
	}
	return s.DEP.Run(ctx)
}

// resultAdapter lets the MongoDB storage's results feed the command API without either importing the other.
type resultAdapter struct {
	s interface {
		CommandResults(ctx context.Context, commandUUID string) ([]mongodb.CommandResult, error)
	}
}

func (a resultAdapter) CommandResults(ctx context.Context, uuid string) ([]commands.Result, error) {
	rows, err := a.s.CommandResults(ctx, uuid)
	if err != nil {
		return nil, err
	}
	out := make([]commands.Result, len(rows))
	for i, r := range rows {
		out[i] = commands.Result{ID: r.ID, Status: r.Status, QueuedAt: r.QueuedAt, ResultAt: r.ResultAt, Result: r.Result}
	}
	return out, nil
}
