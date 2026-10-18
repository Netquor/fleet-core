// Package server puts a whole MDM server in one process: the NanoMDM protocol service, a SCEP certificate authority, enrollment profiles, TLS, and the management API, all on one
// HTTP handler and one storage. It is what cmd/fleetcore runs; tests run it in-process.
package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	kitlog "github.com/go-kit/kit/log"
	"github.com/micromdm/nanodep/godep"
	nlhttp "github.com/micromdm/nanolib/http"
	"github.com/micromdm/nanolib/http/trace"
	"github.com/micromdm/nanolib/log"
	nanoapi "github.com/micromdm/nanomdm/api"
	"github.com/micromdm/nanomdm/certverify"
	"github.com/micromdm/nanomdm/cryptoutil"
	"github.com/micromdm/nanomdm/fleetcore/acme"
	"github.com/micromdm/nanomdm/fleetcore/admin"
	"github.com/micromdm/nanomdm/fleetcore/applicability"
	"github.com/micromdm/nanomdm/fleetcore/blueprints"
	"github.com/micromdm/nanomdm/fleetcore/byod"
	"github.com/micromdm/nanomdm/fleetcore/commands"
	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/dep"
	"github.com/micromdm/nanomdm/fleetcore/enroll"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/pki"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"github.com/micromdm/nanomdm/fleetcore/seal"
	"github.com/micromdm/nanomdm/fleetcore/userauth"
	"github.com/micromdm/nanomdm/fleetcore/vault"
	"github.com/micromdm/nanomdm/fleetcore/vpp"
	"github.com/micromdm/nanomdm/fleetcore/workflows"
	httpapi "github.com/micromdm/nanomdm/http/api"
	httpmdm "github.com/micromdm/nanomdm/http/mdm"
	"github.com/micromdm/nanomdm/mdm"
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
	// Migration mounts /v1/migration (management API): it takes the Authenticate, TokenUpdate and SetBootstrapToken check-ins of enrollments from another NanoMDM-family server (see
	// cmd/nano2nano) and creates the enrollments here without a certificate check, so devices keep their enrollment when their MDM address moves.
	Migration bool
	// MigrateCAs (PEM) are the old server's device-identity CAs. While migrating, identity certificates they issued are accepted as well as this server's own; the devices get this
	// server's certificate when they re-enroll their identity. Remove it once the fleet has moved.
	MigrateCAs []byte
	// AllowRetroactive lets a device that enrolled before certificates were checked be associated with one on its next check-in.
	AllowRetroactive bool

	// APIKey enables the management API under /v1 (HTTP basic auth: the password is the key; the user name is ignored); empty disables it unless AdminCA is set.
	APIKey string
	// APIKeys are further keys, each named: a call made with one is logged and audited as that name (basic auth password = the key). Give each person or system its own, so revoking one
	// does not disturb the others and the audit trail says who acted.
	APIKeys map[string]string
	// AdminCA, if set, makes the management API require a client certificate that chains to it (mutual TLS: the strongest way for an operator or a control plane to reach a tenant's
	// server, with no shared secret). With APIKey as well, both are required. The server must terminate TLS itself for this (the certificate is read from the connection).
	AdminCA *x509.CertPool
	// PushURL overrides the APNs server (tests).
	PushURL string
	// WebhookURL receives every MDM event; WebhookHMACKey signs them.
	WebhookURL     string
	WebhookHMACKey string
	// SeparateCheckin serves check-ins at /checkin and commands at /mdm.
	SeparateCheckin bool
	// EnrollAuthorize, if set, decides who may download an enrollment profile (a code, an invite, a session).
	EnrollAuthorize func(*http.Request) error

	// Sealer seals secrets at rest with this tenant's key (seal.Keyring.For(tenant), or seal.ForTenantKeys when the server holds only its tenant's key). Without one, secrets are stored as
	// given: development only. Give the same sealer to the MongoDB storage (mongodb.WithSealer), which the server does not create.
	Sealer seal.Interface
	// BYOD turns on account-driven User Enrollment (personal devices signed in with a Managed Apple Account). Nil: off.
	BYOD *BYODConfig
	// ADERoots are the trust anchors for the device certificates that sign an Automated Device Enrollment request; nil uses Apple's.
	ADERoots *x509.CertPool
	// VPPBaseURL and AppStoreLookupURL override Apple's Apps and Books and App Store catalog endpoints (tests).
	VPPBaseURL, AppStoreLookupURL string
	// UserAuth turns on the UserAuthenticate handshake for network and mobile users (macOS bound to a directory, Shared iPad). Nil: users are declined (or the zero-length challenge).
	UserAuth *UserAuthConfig
	// ACME turns on the ACME server with device attestation (/acme). Nil: off.
	ACME *ACMEConfig
	// MAIDDEPName is the DEP name whose key signs Managed Apple Account tokens; empty uses the only DEP name there is.
	MAIDDEPName string
	// NoFeeds stops the server from reaching out to Apple (the device-management schemas on GitHub, the OS releases feed). The built-in snapshot is used.
	NoFeeds bool

	Logger log.Logger
	Debug  bool
	// Version is shown at /version.
	Version string
}

// UserAuthConfig sets up the UserAuthenticate handshake.
type UserAuthConfig struct {
	// Realm is named in the challenge and in every stored digest hash.
	Realm string
	// Directory holds digest hashes (HA1) of the people the server accepts; Verifier asks a bridge that holds the passwords. At least one.
	Directory userauth.Directory
	Verifier  userauth.Verifier
	// RequireToken refuses user-channel requests from a user who never completed the handshake. Without it only users who have a token are held to it.
	RequireToken bool
}

// enforced puts the AuthToken check in front of the user channel's requests.
type enforced struct {
	service.CheckinAndCommandService
	e *userauth.Enforcer
}

func (x enforced) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	if err := x.e.Check(r, m.AuthToken); err != nil {
		return err
	}
	return x.CheckinAndCommandService.TokenUpdate(r, m)
}

func (x enforced) CommandAndReportResults(r *mdm.Request, m *mdm.CommandResults) (*mdm.Command, error) {
	if err := x.e.Check(r, m.AuthToken); err != nil {
		return nil, err
	}
	return x.CheckinAndCommandService.CommandAndReportResults(r, m)
}

// ACMEConfig sets up device identities by ACME with hardware attestation.
type ACMEConfig struct {
	// ForEnrollment makes the enrollment profiles ask for the identity by ACME instead of SCEP (devices need iOS 16, macOS 13.1 or later).
	ForEnrollment bool
	// AllowUnassigned lets any genuine Apple device get a certificate; by default only devices Apple assigned to this server (Automated Device Enrollment) may.
	AllowUnassigned bool
	// Roots are the trust anchors for attestations; nil uses Apple's.
	Roots *x509.CertPool
}

// BYODConfig sets up account-driven User Enrollment.
type BYODConfig struct {
	Auth byod.Authenticator
	// LoginURL is the identity provider's sign-in page for devices that have no token yet.
	LoginURL string
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
	sealer     seal.Interface
	bpStore    *blueprints.Store
	ddmStore   *ddm.Store
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
		cfg.CertSource = CertFromTLS
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
	if len(cfg.MigrateCAs) > 0 {
		if !pool.AppendCertsFromPEM(cfg.MigrateCAs) {
			return nil, errors.New("no certificate in the migration CA file")
		}
		caPEM = append(caPEM, cfg.MigrateCAs...)
	}
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
	// Secrets are sealed with the tenant's key when a keyring is configured.
	sealer := cfg.Sealer
	if sealer != nil {
		ddmStore.Sealer = sealer
	}
	ddmSvc := &ddm.Service{Store: ddmStore}
	tokenMux := nanomdm.NewTokenMux()
	var uaService service.UserAuthenticate = nanomdm.NewUAService(cfg.Storage, false)
	var uaEnforcer *userauth.Enforcer
	if ua := cfg.UserAuth; ua != nil {
		uaStore, err := userauth.NewStore(ctx, cfg.PKIDB, cfg.PKITenant)
		if err != nil {
			return nil, err
		}
		uaService = &userauth.Service{Store: uaStore, Realm: ua.Realm, Directory: ua.Directory, Verifier: ua.Verifier, Messages: cfg.Storage, Fallback: uaService}
		uaEnforcer = &userauth.Enforcer{Store: uaStore, Require: ua.RequireToken}
	}
	nano := nanomdm.New(cfg.Storage,
		nanomdm.WithDeclarativeManagement(ddmSvc),
		nanomdm.WithUserAuthenticate(uaService),
		nanomdm.WithGetToken(tokenMux),
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
	bpStore.Sealer = sealer
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
	vaultStore, err := vault.NewStore(ctx, cfg.PKIDB, cfg.PKITenant)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	if sealer != nil {
		vaultStore.Sealer = sealer
	}
	wf, err := workflows.New(ctx, cfg.PKIDB, cfg.PKITenant, bpStore, pushEnqueuer{pe}, vaultStore, logger.With("service", "workflows"))
	if err != nil {
		return nil, fmt.Errorf("workflows: %w", err)
	}
	if sealer != nil {
		wf.Sealer = sealer
	}
	vppStore, err := vpp.NewStore(ctx, cfg.PKIDB, cfg.PKITenant)
	if err != nil {
		return nil, fmt.Errorf("vpp: %w", err)
	}
	if sealer != nil {
		vppStore.Sealer = sealer
	}
	licensing := &vpp.Licensing{Store: vppStore, BaseURL: cfg.VPPBaseURL}
	engine.Apps = licensing
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

	var byodStore *byod.Store
	if cfg.BYOD != nil {
		if byodStore, err = byod.NewStore(ctx, cfg.PKIDB, cfg.PKITenant); err != nil {
			return nil, fmt.Errorf("byod: %w", err)
		}
	}
	observer := &blueprints.Observer{Store: bpStore, DDM: ddmStore, Logger: logger.With("service", "observer")}
	observer.OnResult = append(observer.OnResult, wf.HandleResult)
	if byodStore != nil {
		observer.BYOD = byodStore
	}
	var primary service.CheckinAndCommandService = nano
	if uaEnforcer != nil {
		primary = enforced{nano, uaEnforcer}
	}
	svcs := []service.CheckinAndCommandService{primary, observer}
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
	migrationService := mdmService
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

	// What declarations point devices at (a legacy profile, an asset's data) is downloaded here, with the device's identity like any MDM request.
	download := httpmdm.CertWithEnrollmentIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blob, err := ddmStore.GetBlob(r.Context(), httpmdm.GetEnrollmentID(r.Context()), r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if blob == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", blob.ContentType)
		_, _ = w.Write(blob.Body)
	}), certauth.HashCert, cfg.Storage, true, logger.With("handler", "ddm-download"))
	mdmAuth.Handle("/ddm/profile/", download)
	mdmAuth.Handle("/ddm/asset/", download)

	// ---- SCEP and enrollment ----
	mux.Handle(endpointSCEP, scepHandler)
	prof := enroll.Options{
		Organization: cfg.Organization, Identifier: cfg.ProfileIdentifier, ServerURL: cfg.BaseURL + endpointMDM, SCEPURL: cfg.BaseURL + endpointSCEP,
		Topic: cfg.Topic, SignMessage: cfg.CertSource == CertFromSignature,
	}
	if cfg.SeparateCheckin {
		prof.CheckInURL = cfg.BaseURL + endpointCheckin
	}
	var acmeAssigned func(ctx context.Context, serial string) (string, bool, error)
	if cfg.ACME != nil {
		acmeStore, err := acme.NewStore(ctx, cfg.PKIDB, cfg.PKITenant)
		if err != nil {
			return nil, fmt.Errorf("acme: %w", err)
		}
		srv := &acme.Server{Store: acmeStore, BaseURL: cfg.BaseURL, Roots: cfg.ACME.Roots, Issuer: &acme.CAIssuer{Depot: depot, Pass: cfg.CAPass, Organization: cfg.Organization, Days: cfg.SCEPValidityDays}}
		srv.Authorize = func(ctx context.Context, id acme.Identifier) error {
			if cfg.ACME.AllowUnassigned {
				return nil
			}
			if id.Type != "permanent-identifier" || acmeAssigned == nil {
				return errors.New("only devices Apple assigned to this server may get a certificate")
			}
			if _, ok, err := acmeAssigned(ctx, id.Value); err != nil || !ok {
				return errors.New("not assigned")
			}
			return nil
		}
		mux.Handle("/acme/", srv.Handler())
		if cfg.ACME.ForEnrollment {
			prof.ACMEDirectoryURL = cfg.BaseURL + "/acme/directory"
		}
	}
	mux.Handle(endpointEnroll, enroll.Handler(prof, challenges, cfg.EnrollAuthorize))
	if cfg.BYOD != nil {
		// Account-driven User Enrollment: the endpoint wants the person's token from the identity provider; the discovery document points devices at it.
		mux.Handle("/enroll/byod", byod.Handler(byod.Config{Auth: cfg.BYOD.Auth, LoginURL: cfg.BYOD.LoginURL, Profile: prof, Challenges: challenges, Store: byodStore}))
		mux.Handle("/.well-known/com.apple.remotemanagement", byod.WellKnown(cfg.BaseURL+"/enroll/byod"))
	}
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/version", nlhttp.NewJSONVersionHandler(cfg.Version))

	// adminAuth guards the management API: a client certificate from the admin CA and/or the API key, and every call is logged with who made it.
	adminAuth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			who := ""
			if cfg.AdminCA != nil {
				if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
					http.Error(w, "a client certificate is required", http.StatusUnauthorized)
					return
				}
				leaf := r.TLS.PeerCertificates[0]
				inter := x509.NewCertPool()
				for _, c := range r.TLS.PeerCertificates[1:] {
					inter.AddCert(c)
				}
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: cfg.AdminCA, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
					http.Error(w, "the client certificate is not accepted", http.StatusUnauthorized)
					return
				}
				who = leaf.Subject.String()
			}
			if cfg.APIKey != "" || len(cfg.APIKeys) > 0 {
				_, pass, ok := r.BasicAuth()
				name := ""
				if ok {
					// every key is compared, so the time taken does not say which one was close
					if cfg.APIKey != "" && subtle.ConstantTimeCompare([]byte(pass), []byte(cfg.APIKey)) == 1 {
						name = "api key"
					}
					for n, k := range cfg.APIKeys {
						if subtle.ConstantTimeCompare([]byte(pass), []byte(k)) == 1 {
							name = "key " + n
						}
					}
				}
				if name == "" {
					w.Header().Set("WWW-Authenticate", `Basic realm="fleetcore"`)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				if who == "" {
					who = name
				}
			}
			if actor := r.Header.Get("X-Actor"); actor != "" && who != "" { // a control plane names the person it acts for
				who += " (" + actor + ")"
			}
			logger.Info("msg", "admin api", "who", who, "method", r.Method, "path", r.URL.Path)
			next.ServeHTTP(w, r.WithContext(admin.With(r.Context(), who)))
		})
	}

	// ---- management API ----
	var depSvc *dep.Service
	if cfg.APIKey != "" || len(cfg.APIKeys) > 0 || cfg.AdminCA != nil {
		depStore, err := dep.New(ctx, cfg.PKIDB, cfg.PKITenant, cfg.CAPass)
		if err != nil {
			return nil, fmt.Errorf("dep storage: %w", err)
		}
		depStore.Sealer = sealer
		if depSvc, err = dep.NewService(ctx, cfg.PKIDB, depStore, cfg.PKITenant, logger.With("service", "dep")); err != nil {
			return nil, fmt.Errorf("dep service: %w", err)
		}
		acmeAssigned = depSvc.Lookup
		depSvc.EnrollURL = cfg.BaseURL + "/enroll/ade"
		depSvc.OnDevices = func(ctx context.Context, name string, isFetch bool, resp *godep.FetchDeviceResponseJson) {
			supervised, _ := depSvc.ProfileFacts(ctx, name)
			for _, d := range resp.Devices {
				dd := blueprints.DEPDevice{Serial: d.SerialNumber, Model: d.Model, DEPName: name, Supervised: supervised}
				if d.Os != nil {
					dd.OS = string(*d.Os)
				}
				if d.DeviceAssignedDate != nil {
					dd.AssignedAt = *d.DeviceAssignedDate
				}
				removed := d.OpType != nil && *d.OpType == godep.DeviceJsonOpTypeDeleted
				engine.DEPDeviceEvent(ctx, dd, removed)
				if !removed {
					engine.PreLicense(ctx, dd) // the apps it will get are licensed to its serial number before it enrolls
				}
			}
		}
		// A device Apple assigned to this server asks for its enrollment profile here, with no code or sign-in.
		mux.Handle("/enroll/ade", (&dep.ADE{Roots: cfg.ADERoots, Service: depSvc, Profile: prof, Challenges: challenges}).Handler())
		tokenMux.Handle("com.apple.maid", depSvc.GetToken(cfg.MAIDDEPName))
		mux.Handle("/v1/dep/", adminAuth(depSvc.Handler("/v1/dep")))

		apiAuth := nlhttp.NewMWMux(mux)
		apiAuth.Use(func(h http.Handler) http.Handler { return adminAuth(h) })
		httpapi.HandleAPIv1("/v1", apiAuth, logger, cfg.Storage, ps)

		if cfg.Migration {
			migrate := httpmdm.CheckinHandler(migrationService, logger.With("handler", "migration"))
			mux.Handle("/v1/migration", adminAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut && r.Method != http.MethodPost {
					w.Header().Set("Allow", "PUT, POST")
					http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
					return
				}
				migrate.ServeHTTP(w, r)
			})))
		}

		// ---- JSON command API ----
		var results commands.ResultReader
		if rr, ok := cfg.Storage.(interface {
			CommandResults(ctx context.Context, commandUUID string) ([]mongodb.CommandResult, error)
		}); ok {
			results = resultAdapter{rr}
		}
		var cl commands.Lister
		if l, ok := cfg.Storage.(lister); ok {
			cl = commandLister{l}
			lh := adminAuth(http.StripPrefix("/v1", listingHandler(l)))
			for _, p := range []string{"/v1/enrollments", "/v1/enrollments/", "/v1/queue"} {
				mux.Handle(p, lh)
			}
		}
		ch, err := commands.Handler("/v1/commands", commands.Default(), cfg.Storage, ps, results, cl, logger.With("handler", "commands"))
		if err != nil {
			return nil, fmt.Errorf("command api: %w", err)
		}
		mux.Handle("/v1/commands", adminAuth(ch))
		mux.Handle("/v1/commands/", adminAuth(ch))

		// ---- blueprints, groups, devices, platform applicability, schemas, OS releases ----
		bpAPI := &blueprints.API{Engine: engine, Applicability: profileRules, OSReleases: relFeed, SchemaRefresher: schemaFeed}
		var bootstrap workflows.BootstrapReader
		if b, ok := cfg.Storage.(workflows.BootstrapReader); ok {
			bootstrap = b
		}
		bpAPI.ResolveApp = func(ctx context.Context, adam string) (string, error) {
			info, err := vpp.Lookup(ctx, nil, cfg.AppStoreLookupURL, adam, "")
			if err != nil {
				return "", err
			}
			return info.BundleID, nil
		}
		vppHandler := adminAuth(http.StripPrefix("/v1", licensing.Handler()))
		mux.Handle("/v1/vpp/", vppHandler)
		wfAPI := &workflows.API{S: wf, Bootstrap: bootstrap}
		bpHandler := adminAuth(http.StripPrefix("/v1", wfAPI.Handler(bpAPI.Handler())))
		for _, p := range []string{"/v1/blueprints", "/v1/blueprints/", "/v1/groups", "/v1/groups/", "/v1/devices", "/v1/devices/", "/v1/applicability", "/v1/applicability/", "/v1/schemas", "/v1/schemas/", "/v1/os-releases", "/v1/os-releases/", "/v1/ddm/"} {
			mux.Handle(p, bpHandler)
		}
	}

	return &Server{Handler: trace.NewTraceLoggingHandler(mux, logger.With("handler", "log"), newTraceID), CAPool: pool, Depot: depot, DEP: depSvc, Blueprints: engine, sealer: sealer, bpStore: bpStore, ddmStore: ddmStore, releases: relFeed, schemaFeed: schemaFeed, cfg: cfg}, nil
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

// Rekey seals every stored secret with the current master key: values written before sealing was configured, and those under an older key after a rotation. It reports how many
// documents each store changed. It is safe to run again, and while the server runs.
func (s *Server) Rekey(ctx context.Context) (map[string]int, error) {
	if s.sealer == nil {
		return nil, errors.New("no master key is configured: nothing to seal with")
	}
	out := map[string]int{}
	var err error
	if out["blueprints"], err = s.bpStore.RewrapBlueprints(ctx); err != nil {
		return out, fmt.Errorf("blueprints: %w", err)
	}
	if out["declarations"], err = s.ddmStore.Rewrap(ctx); err != nil {
		return out, fmt.Errorf("declarations: %w", err)
	}
	if s.DEP != nil {
		if out["dep"], err = s.DEP.Store.Rewrap(ctx); err != nil {
			return out, fmt.Errorf("dep: %w", err)
		}
	}
	if r, ok := s.cfg.Storage.(interface {
		Rewrap(context.Context) (int, error)
	}); ok {
		if out["mdm"], err = r.Rewrap(ctx); err != nil {
			return out, fmt.Errorf("mdm storage: %w", err)
		}
	}
	return out, nil
}
