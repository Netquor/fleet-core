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
	nanoapi "github.com/micromdm/nanomdm/api"
	"github.com/micromdm/nanomdm/certverify"
	"github.com/micromdm/nanomdm/cryptoutil"
	"github.com/micromdm/nanomdm/fleetcore/applicability"
	"github.com/micromdm/nanomdm/fleetcore/blueprints"
	"github.com/micromdm/nanomdm/fleetcore/commands"
	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/dep"
	"github.com/micromdm/nanomdm/fleetcore/enroll"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/pki"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
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

	// NoFeeds stops the server from reaching out to Apple (the device-management schemas on GitHub, the OS releases feed). The built-in snapshot is used.
	NoFeeds bool

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
	// Blueprints keeps devices matching their blueprints; Run starts it.
	Blueprints *blueprints.Engine
	releases   *osreleases.Refresher
	schemaFeed *schemas.Refresher
	cfg        Config
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
	ddmStore, err := ddm.NewStore(ctx, cfg.PKIDB, cfg.PKITenant)
	if err != nil {
		return nil, fmt.Errorf("declarative management: %w", err)
	}
	ddmSvc := &ddm.Service{Store: ddmStore}
	nano := nanomdm.New(cfg.Storage,
		nanomdm.WithDeclarativeManagement(ddmSvc),
		nanomdm.WithUserAuthenticate(nanomdm.NewUAService(cfg.Storage, false)),
		nanomdm.WithGetToken(nanomdm.NewTokenMux()),
		nanomdm.WithLogger(logger.With("service", "nanomdm")))
	var popts []nanopush.Option
	if cfg.PushURL != "" {
		popts = append(popts, nanopush.WithPushServerURL(cfg.PushURL))
	}
	ps := pushsvc.New(cfg.Storage, cfg.Storage, nanopush.NewFactory(popts...), logger.With("service", "push"))

	// ---- blueprints: desired state, kept true by a reconciler that learns of devices from check-ins ----
	bpStore, err := blueprints.NewStore(ctx, cfg.PKIDB, cfg.PKITenant)
	if err != nil {
		return nil, fmt.Errorf("blueprints: %w", err)
	}
	profileRules, err := applicability.NewRegistry(ctx, cfg.PKIDB, cfg.PKITenant)
	if err != nil {
		return nil, fmt.Errorf("applicability: %w", err)
	}
	catalog := &osreleases.Catalog{}
	relFeed := &osreleases.Refresher{Catalog: catalog, DB: cfg.PKIDB, Logf: func(f string, a ...any) { logger.Info("msg", fmt.Sprintf(f, a...)) }}
	if err := relFeed.Load(ctx); err != nil {
		return nil, fmt.Errorf("os releases: %w", err)
	}
	schemaFeed := &schemas.Refresher{Ref: "release", DB: cfg.PKIDB, Logf: func(f string, a ...any) { logger.Info("msg", fmt.Sprintf(f, a...)) }}
	if err := schemaFeed.Load(ctx); err != nil {
		return nil, fmt.Errorf("schemas: %w", err)
	}
	pe, err := nanoapi.NewPushEnqueuer(cfg.Storage, ps, nanoapi.WithLogger(logger.With("service", "blueprints")))
	if err != nil {
		return nil, err
	}
	engine := blueprints.New(bpStore, pushEnqueuer{pe}, profileRules, catalog, logger.With("service", "blueprints"), blueprints.Config{})
	engine.DDM = ddmStore
	engine.BaseURL = cfg.BaseURL
	engine.Organization = cfg.Organization
	ddmSvc.OnStatus = engine.OnStatus
	// A new Apple release or schema changes what is out of date and what applies: look at every device again.
	relFeed.OnChange = func([]osreleases.Release) {
		_ = bpStore.Touch(context.Background(), blueprints.Rule{})
		engine.Invalidate()
	}
	schemas.OnChange(func(*schemas.Set) { _ = bpStore.Touch(context.Background(), blueprints.Rule{}) })

	observer := &blueprints.Observer{Store: bpStore, Logger: logger.With("service", "observer")}
	svcs := []service.CheckinAndCommandService{nano, observer}
	if cfg.WebhookURL != "" {
		whOpts := []webhook.Option{webhook.WithTokenUpdateTalley(cfg.Storage), webhook.WithEventID(trace.GetTraceID)}
		if cfg.WebhookHMACKey != "" {
			whOpts = append(whOpts, webhook.WithHMACSecret([]byte(cfg.WebhookHMACKey)))
		}
		svcs = append(svcs, webhook.New(cfg.WebhookURL, whOpts...))
	}
	var mdmService service.CheckinAndCommandService = multi.New(logger.With("service", "multi"), svcs...)
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

	// Profiles that reach a device as legacy-profile declarations are downloaded here, with the device's identity like any MDM request.
	mdmAuth.Handle("/ddm/profile/", httpmdm.CertWithEnrollmentIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ddmStore.Profile(r.Context(), httpmdm.GetEnrollmentID(r.Context()), strings.TrimPrefix(r.URL.Path, "/ddm/profile/"))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if body == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		_, _ = w.Write(body)
	}), certauth.HashCert, cfg.Storage, true, logger.With("handler", "ddm-profile")))

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

		// ---- blueprints, groups, devices, platform applicability, schemas, OS releases ----
		bpAPI := &blueprints.API{Engine: engine, Applicability: profileRules, OSReleases: relFeed, SchemaRefresher: schemaFeed}
		bpHandler := nlhttp.NewSimpleBasicAuthHandler(http.StripPrefix("/v1", bpAPI.Handler()), "fleetcore", cfg.APIKey, "fleetcore")
		for _, p := range []string{"/v1/blueprints", "/v1/blueprints/", "/v1/groups", "/v1/groups/", "/v1/devices/", "/v1/applicability", "/v1/applicability/", "/v1/schemas", "/v1/schemas/", "/v1/os-releases", "/v1/os-releases/", "/v1/ddm/"} {
			mux.Handle(p, bpHandler)
		}
	}

	return &Server{Handler: trace.NewTraceLoggingHandler(mux, logger.With("handler", "log"), newTraceID), CAPool: pool, Depot: depot, DEP: depSvc, Blueprints: engine, releases: relFeed, schemaFeed: schemaFeed, cfg: cfg}, nil
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

// Run starts the background work (the blueprint reconciler, the DEP syncers, the feeds from Apple) and returns when ctx ends.
func (s *Server) Run(ctx context.Context) error {
	go s.Blueprints.Run(ctx)
	if !s.cfg.NoFeeds {
		go s.releases.Run(ctx, time.Hour)
		go s.schemaFeed.Run(ctx, 24*time.Hour)
	}
	if s.DEP == nil {
		<-ctx.Done()
		return nil
	}
	return s.DEP.Run(ctx)
}

// pushEnqueuer queues commands for the blueprint engine and wakes the devices. A push that cannot be delivered (the device is offline) is not a failure: the command waits in the queue.
type pushEnqueuer struct{ pe *nanoapi.PushEnqueuer }

func (p pushEnqueuer) Enqueue(ctx context.Context, ids []string, body []byte) error {
	res, _, err := p.pe.RawCommandEnqueueWithPush(ctx, body, ids, false)
	if res != nil {
		if res.EnqueueError != nil {
			return res.EnqueueError
		}
		for _, st := range res.Status {
			if st.EnqueueError != nil {
				return st.EnqueueError
			}
		}
		return nil
	}
	return err
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
