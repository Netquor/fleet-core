// fleetcore is a whole MDM server in one binary: MDM protocol, SCEP certificate authority, enrollment profiles, TLS and the management API, on MongoDB.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/micromdm/nanolib/log/stdlogfmt"
	"github.com/micromdm/nanomdm/fleetcore/byod"
	"github.com/micromdm/nanomdm/fleetcore/provision"
	"github.com/micromdm/nanomdm/fleetcore/relay"
	"github.com/micromdm/nanomdm/fleetcore/seal"
	"github.com/micromdm/nanomdm/fleetcore/server"
	"github.com/micromdm/nanomdm/fleetcore/userauth"
	"github.com/micromdm/nanomdm/storage/mongodb"
	"github.com/nats-io/nats.go"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/acme/autocert"
)

var version = "dev"

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	if adminCommand(os.Args[1:]) {
		return
	}
	var (
		listen     = flag.String("listen", env("FLEETCORE_LISTEN", ":9000"), "address to listen on")
		base       = flag.String("url", env("FLEETCORE_URL", ""), "public base URL devices use, for example https://mdm.example.com")
		org        = flag.String("org", env("FLEETCORE_ORG", "MDM"), "organization name for the CA and the profile")
		topic      = flag.String("topic", env("FLEETCORE_TOPIC", ""), "APNs topic of the push certificate (com.apple.mgmt.External.<uuid>)")
		uri        = flag.String("mongo", env("FLEETCORE_MONGO_URI", "mongodb://127.0.0.1:27017/?replicaSet=rs0"), "MongoDB URI")
		mongoCert  = flag.String("mongo-cert", env("FLEETCORE_MONGO_CERT", ""), "client certificate and key (PEM) this server authenticates to MongoDB with (MONGODB-X509, no password)")
		adminCA    = flag.String("admin-ca", env("FLEETCORE_ADMIN_CA", ""), "CA certificate (PEM) whose client certificates may use the management API (mutual TLS); needs TLS terminated by this server")
		byodIssuer = flag.String("byod-issuer", env("FLEETCORE_BYOD_ISSUER", ""), "OpenID Connect issuer whose tokens may start a User Enrollment (BYOD); turns account-driven enrollment on")
		byodJWKS   = flag.String("byod-jwks", env("FLEETCORE_BYOD_JWKS", ""), "URL of the issuer's signing keys (JWKS)")
		byodAud    = flag.String("byod-audience", env("FLEETCORE_BYOD_AUDIENCE", ""), "audience the tokens must carry")
		byodClaim  = flag.String("byod-claim", env("FLEETCORE_BYOD_CLAIM", "email"), "token claim that holds the person's Managed Apple Account")
		byodLogin  = flag.String("byod-login-url", env("FLEETCORE_BYOD_LOGIN_URL", ""), "identity provider sign-in page for devices that have no token yet")
		maidDEP    = flag.String("maid-dep", env("FLEETCORE_MAID_DEP", ""), "DEP name whose key signs Managed Apple Account tokens (default: the only one)")
		uaRealm    = flag.String("ua-realm", env("FLEETCORE_UA_REALM", ""), "realm of the UserAuthenticate digest challenge for network and mobile users; turns that handshake on")
		uaUsers    = flag.String("ua-users", env("FLEETCORE_UA_USERS", ""), "file of user:realm:ha1 lines (see: fleetcore ua-hash) the people are checked against")
		uaVerify   = flag.String("ua-verify-url", env("FLEETCORE_UA_VERIFY_URL", ""), "bridge to your directory that checks a digest it holds the password for")
		uaSecret   = flag.String("ua-verify-secret", env("FLEETCORE_UA_VERIFY_SECRET", ""), "bearer secret for the bridge")
		uaRequire  = flag.Bool("ua-require-token", os.Getenv("FLEETCORE_UA_REQUIRE_TOKEN") != "", "refuse user-channel requests from a user who has not completed the handshake")
		relayNATS  = flag.String("relay-nats", env("FLEETCORE_RELAY_NATS", ""), "NATS URL to publish events to (enrollments, commands, application state, blueprints, DEP assignments)")
		relayPfx   = flag.String("relay-nats-prefix", env("FLEETCORE_RELAY_NATS_PREFIX", "fleetcore.events"), "subject prefix of the events: <prefix>.<type>.<key>")
		relayJS    = flag.Bool("relay-jetstream", os.Getenv("FLEETCORE_RELAY_JETSTREAM") != "", "publish through JetStream with an acknowledgement (the stream must exist)")
		relayHook  = flag.String("relay-webhook", env("FLEETCORE_RELAY_WEBHOOK", ""), "URL to post events to, signed with -relay-webhook-secret")
		relaySec   = flag.String("relay-webhook-secret", env("FLEETCORE_RELAY_WEBHOOK_SECRET", ""), "HMAC secret that signs the webhook body")
		migration  = flag.Bool("migration", os.Getenv("FLEETCORE_MIGRATION") != "", "accept enrollments from another NanoMDM-family server at /v1/migration (see nano2nano)")
		migrateCA  = flag.String("migrate-ca", env("FLEETCORE_MIGRATE_CA", ""), "PEM file with the old server's device-identity CA(s); certificates they issued are accepted while devices move")
		acmeOn     = flag.Bool("acme", os.Getenv("FLEETCORE_ACME") != "", "serve ACME with Apple device attestation at /acme (hardware-bound device identities)")
		acmeEnroll = flag.Bool("acme-for-enrollment", os.Getenv("FLEETCORE_ACME_FOR_ENROLLMENT") != "", "enrollment profiles ask for the identity by ACME instead of SCEP (iOS 16, macOS 13.1 or later)")
		acmeOpen   = flag.Bool("acme-allow-unassigned", os.Getenv("FLEETCORE_ACME_ALLOW_UNASSIGNED") != "", "any genuine Apple device may get a certificate, not only those assigned by Apple Business Manager")
		mongoCA    = flag.String("mongo-ca", env("FLEETCORE_MONGO_CA", ""), "CA certificate that signed the MongoDB servers' certificates")
		dbName     = flag.String("db", env("FLEETCORE_DB", "fleetcore"), "database name")
		tenant     = flag.String("tenant", env("FLEETCORE_TENANT", ""), "tenant id (shared-collections mode); empty: the database belongs to one tenant")
		caPass     = flag.String("ca-pass", env("FLEETCORE_CA_PASS", ""), "passphrase that encrypts the CA key at rest")
		apiKey     = flag.String("api-key", env("FLEETCORE_API_KEY", ""), "management API key (HTTP basic auth, user fleetcore); empty disables the API")
		source     = flag.String("cert-source", env("FLEETCORE_CERT_SOURCE", "tls"), "where the device certificate comes from: tls, signature or header")
		header     = flag.String("cert-header", env("FLEETCORE_CERT_HEADER", ""), "header carrying the certificate when cert-source=header")
		tlsCert    = flag.String("tls-cert", env("FLEETCORE_TLS_CERT", ""), "TLS certificate file")
		tlsKey     = flag.String("tls-key", env("FLEETCORE_TLS_KEY", ""), "TLS key file")
		acme       = flag.String("autocert", env("FLEETCORE_AUTOCERT", ""), "host name to get a Let's Encrypt certificate for (serves :443 and :80)")
		acmeDir    = flag.String("autocert-dir", env("FLEETCORE_AUTOCERT_DIR", "autocert-cache"), "directory that keeps autocert certificates")
		masterKey  = flag.String("master-key", env("FLEETCORE_MASTER_KEY", ""), "master keys that seal secrets at rest: base64, 32 bytes each, comma separated, the current one first (old ones stay to open older data)")
		masterFile = flag.String("master-key-file", env("FLEETCORE_MASTER_KEY_FILE", ""), "file holding the master keys (same format); use instead of -master-key")
		tenantKeys = flag.String("tenant-keys", env("FLEETCORE_TENANT_KEYS", ""), "this tenant's own keys, <id>:<base64>, current first (from 'fleetcore tenant-key'): the server then never holds the master key")
		rekey      = flag.Bool("rekey", false, "seal every stored secret with the current master key, print what changed and exit")
		noFeeds    = flag.Bool("no-feeds", os.Getenv("FLEETCORE_NO_FEEDS") != "", "do not contact Apple's feeds (device-management schemas on GitHub, OS releases); use the built-in snapshot")
		debug      = flag.Bool("debug", false, "log more")
		showVer    = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}
	if *base == "" {
		fmt.Fprintln(os.Stderr, "fleetcore: -url (or FLEETCORE_URL) is required")
		os.Exit(2)
	}
	logger := stdlogfmt.New(stdlogfmt.WithDebugFlag(*debug))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sealer, err := tenantSealer(*tenantKeys, *masterKey, *masterFile, *caPass, *tenant)
	if err != nil {
		fatal(logger, err)
	}
	if sealer == nil {
		logger.Info("msg", "no key: secrets are stored unencrypted. Set FLEETCORE_TENANT_KEYS (or FLEETCORE_MASTER_KEY) outside development")
	}
	clientOpts := options.Client().ApplyURI(*uri)
	if *mongoCert != "" {
		if clientOpts, err = provision.X509Options(*uri, *mongoCert, *mongoCA); err != nil {
			fatal(logger, err)
		}
	}
	mc, err := mongo.Connect(clientOpts)
	if err != nil {
		fatal(logger, err)
	}
	defer mc.Disconnect(context.Background())
	opts := []mongodb.Option{mongodb.WithClient(mc), mongodb.WithDatabase(*dbName)}
	if sealer != nil {
		opts = append(opts, mongodb.WithSealer(sealer))
	}
	if *tenant != "" {
		opts = append(opts, mongodb.WithTenant(*tenant))
	}
	store, err := mongodb.New(ctx, opts...)
	if err != nil {
		fatal(logger, err)
	}
	var adminPool *x509.CertPool
	if *adminCA != "" {
		if *tlsCert == "" && *acme == "" {
			fatal(logger, errors.New("-admin-ca needs this server to terminate TLS (-tls-cert and -tls-key, or -autocert): the client certificate is read from the connection"))
		}
		pem, err := os.ReadFile(*adminCA)
		if err != nil {
			fatal(logger, err)
		}
		adminPool = x509.NewCertPool()
		if !adminPool.AppendCertsFromPEM(pem) {
			fatal(logger, errors.New("no certificate in the -admin-ca file"))
		}
	}
	var acmeCfg *server.ACMEConfig
	if *acmeOn || *acmeEnroll {
		acmeCfg = &server.ACMEConfig{ForEnrollment: *acmeEnroll, AllowUnassigned: *acmeOpen}
	}
	var relaySink relay.Multi
	if *relayNATS != "" {
		nc, err := nats.Connect(*relayNATS, nats.Name("fleetcore-relay"), nats.MaxReconnects(-1))
		if err != nil {
			fatal(logger, fmt.Errorf("-relay-nats: %w", err))
		}
		defer nc.Close()
		relaySink = append(relaySink, &relay.NATS{Conn: nc, Prefix: *relayPfx, Stream: *relayJS})
	}
	if *relayHook != "" {
		relaySink = append(relaySink, &relay.Webhook{URL: *relayHook, Secret: []byte(*relaySec)})
	}
	var migrateCAs []byte
	if *migrateCA != "" {
		var err error
		if migrateCAs, err = os.ReadFile(*migrateCA); err != nil {
			fatal(logger, err)
		}
	}
	var uaCfg *server.UserAuthConfig
	if *uaRealm != "" {
		uaCfg = &server.UserAuthConfig{Realm: *uaRealm, RequireToken: *uaRequire}
		if *uaUsers != "" {
			d, err := userauth.LoadFileDirectory(*uaUsers)
			if err != nil {
				fatal(logger, err)
			}
			uaCfg.Directory = d
		}
		if *uaVerify != "" {
			uaCfg.Verifier = &userauth.HTTPVerifier{URL: *uaVerify, Secret: *uaSecret}
		}
		if uaCfg.Directory == nil && uaCfg.Verifier == nil {
			fatal(logger, errors.New("-ua-realm needs -ua-users or -ua-verify-url"))
		}
	}
	var byodCfg *server.BYODConfig
	if *byodIssuer != "" {
		if *byodJWKS == "" || *byodAud == "" {
			fatal(logger, errors.New("-byod-issuer needs -byod-jwks and -byod-audience"))
		}
		byodCfg = &server.BYODConfig{Auth: &byod.OIDC{Issuer: *byodIssuer, JWKSURL: *byodJWKS, Audience: *byodAud, Claim: *byodClaim}, LoginURL: *byodLogin}
	}
	srv, err := server.New(ctx, server.Config{
		BaseURL: *base, Organization: *org, Topic: *topic, Storage: store, PKIDB: mc.Database(*dbName), PKITenant: *tenant,
		CAPass: *caPass, CertSource: server.CertSource(*source), CertHeader: *header, APIKey: *apiKey, Logger: logger, Debug: *debug, Version: version, NoFeeds: *noFeeds, Sealer: sealer, AdminCA: adminPool, BYOD: byodCfg, MAIDDEPName: *maidDEP, ACME: acmeCfg, UserAuth: uaCfg, Migration: *migration, MigrateCAs: migrateCAs,
	})
	if err != nil {
		fatal(logger, err)
	}

	if len(relaySink) > 0 && !*rekey {
		rl := &relay.Relay{DB: mc.Database(*dbName), Tenant: *tenant, Out: relaySink, Logger: logger.With("service", "relay")}
		go func() { _ = rl.Run(ctx) }()
	}
	if *rekey {
		res, err := srv.Rekey(ctx)
		for k, v := range res {
			fmt.Printf("%-14s %d changed\n", k, v)
		}
		if err != nil {
			fatal(logger, err)
		}
		return
	}
	go func() {
		if err := srv.Run(ctx); err != nil {
			logger.Info("msg", "background work stopped", "err", err)
		}
	}()
	hs := &http.Server{Addr: *listen, Handler: srv.Handler, ReadHeaderTimeout: 15 * time.Second}
	var serve func() error
	switch {
	case *acme != "":
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(*acme), Cache: autocert.DirCache(*acmeDir)}
		cfg := m.TLSConfig()
		if *source == "tls" {
			cfg.ClientAuth = tls.RequestClientCert
		}
		hs.Addr, hs.TLSConfig = ":443", cfg
		go http.ListenAndServe(":80", m.HTTPHandler(nil))
		serve = func() error { return hs.ListenAndServeTLS("", "") }
	case *tlsCert != "" && *tlsKey != "":
		cfg, err := srv.TLSConfig(*tlsCert, *tlsKey)
		if err != nil {
			fatal(logger, err)
		}
		hs.TLSConfig = cfg
		serve = func() error { return hs.ListenAndServeTLS("", "") }
	default:
		if *source == "tls" {
			fatal(logger, errors.New("cert-source=tls needs TLS here: give -tls-cert and -tls-key, or -autocert, or put a proxy in front and use cert-source=signature"))
		}
		serve = hs.ListenAndServe
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(c)
	}()
	logger.Info("msg", "fleetcore listening", "addr", hs.Addr, "url", *base, "version", version, "cert_source", strings.ToLower(*source))
	if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(logger, err)
	}
}

func fatal(l interface{ Info(...interface{}) }, err error) {
	l.Info("msg", "fatal", "err", err)
	os.Exit(1)
}

// tenantSealer builds the sealer for this tenant: from the tenant's own keys (preferred: the server never sees the master key), from master keys, or from the CA passphrase when that is all
// there is. nil means no encryption (development).
func tenantSealer(tenantKeys, masterKeys, masterFile, passphrase, tenant string) (seal.Interface, error) {
	if tenantKeys != "" {
		return seal.ForTenantKeys(tenant, seal.ParseTenantKeys(tenantKeys)...)
	}
	if masterFile != "" {
		b, err := os.ReadFile(masterFile)
		if err != nil {
			return nil, err
		}
		masterKeys = string(b)
	}
	switch {
	case masterKeys != "":
		ks, err := seal.ParseKeys(masterKeys)
		if err != nil {
			return nil, err
		}
		ring, err := seal.NewKeyring(ks...)
		if err != nil {
			return nil, err
		}
		return ring.For(tenant), nil
	case passphrase != "":
		ring, err := seal.FromPassphrase(passphrase)
		if err != nil {
			return nil, err
		}
		return ring.For(tenant), nil
	}
	return nil, nil
}
