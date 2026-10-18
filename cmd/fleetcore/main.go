// fleetcore is a whole MDM server in one binary: MDM protocol, SCEP certificate authority, enrollment profiles, TLS and the management API, on MongoDB.
package main

import (
	"context"
	"crypto/tls"
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
	"github.com/micromdm/nanomdm/fleetcore/server"
	"github.com/micromdm/nanomdm/storage/mongodb"
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
	var (
		listen  = flag.String("listen", env("FLEETCORE_LISTEN", ":9000"), "address to listen on")
		base    = flag.String("url", env("FLEETCORE_URL", ""), "public base URL devices use, for example https://mdm.example.com")
		org     = flag.String("org", env("FLEETCORE_ORG", "Fleet"), "organization name for the CA and the profile")
		topic   = flag.String("topic", env("FLEETCORE_TOPIC", ""), "APNs topic of the push certificate (com.apple.mgmt.External.<uuid>)")
		uri     = flag.String("mongo", env("FLEETCORE_MONGO_URI", "mongodb://127.0.0.1:27017/?replicaSet=rs0"), "MongoDB URI")
		dbName  = flag.String("db", env("FLEETCORE_DB", "fleetcore"), "database name")
		tenant  = flag.String("tenant", env("FLEETCORE_TENANT", ""), "tenant id (shared-collections mode); empty: the database belongs to one tenant")
		caPass  = flag.String("ca-pass", env("FLEETCORE_CA_PASS", ""), "passphrase that encrypts the CA key at rest")
		apiKey  = flag.String("api-key", env("FLEETCORE_API_KEY", ""), "management API key (HTTP basic auth, user fleetcore); empty disables the API")
		source  = flag.String("cert-source", env("FLEETCORE_CERT_SOURCE", "tls"), "where the device certificate comes from: tls, signature or header")
		header  = flag.String("cert-header", env("FLEETCORE_CERT_HEADER", ""), "header carrying the certificate when cert-source=header")
		tlsCert = flag.String("tls-cert", env("FLEETCORE_TLS_CERT", ""), "TLS certificate file")
		tlsKey  = flag.String("tls-key", env("FLEETCORE_TLS_KEY", ""), "TLS key file")
		acme    = flag.String("autocert", env("FLEETCORE_AUTOCERT", ""), "host name to get a Let's Encrypt certificate for (serves :443 and :80)")
		acmeDir = flag.String("autocert-dir", env("FLEETCORE_AUTOCERT_DIR", "autocert-cache"), "directory that keeps autocert certificates")
		debug   = flag.Bool("debug", false, "log more")
		showVer = flag.Bool("version", false, "print the version and exit")
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

	mc, err := mongo.Connect(options.Client().ApplyURI(*uri))
	if err != nil {
		fatal(logger, err)
	}
	defer mc.Disconnect(context.Background())
	opts := []mongodb.Option{mongodb.WithClient(mc), mongodb.WithDatabase(*dbName)}
	if *tenant != "" {
		opts = append(opts, mongodb.WithTenant(*tenant))
	}
	store, err := mongodb.New(ctx, opts...)
	if err != nil {
		fatal(logger, err)
	}
	srv, err := server.New(ctx, server.Config{
		BaseURL: *base, Organization: *org, Topic: *topic, Storage: store, PKIDB: mc.Database(*dbName), PKITenant: *tenant,
		CAPass: *caPass, CertSource: server.CertSource(*source), CertHeader: *header, APIKey: *apiKey, Logger: logger, Debug: *debug, Version: version,
	})
	if err != nil {
		fatal(logger, err)
	}

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
