package provision

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type pki struct {
	dir  string
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	next int64
}

func newPKI(t *testing.T, dir string) *pki {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Cluster CA", Organization: []string{"test"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &pki{dir: dir, ca: ca, key: key, next: 2}
	writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", der)
	return p
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// issue writes name.pem holding the certificate and its key, and returns the subject as MongoDB names it (RFC 2253).
func (p *pki) issue(t *testing.T, cn string, server bool) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// MongoDB refuses a client whose subject shares its organization with the cluster's own certificates (it would pass for a cluster member).
	org := "tenants"
	if server {
		org = "cluster"
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.next), Subject: pkix.Name{CommonName: cn, Organization: []string{org}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	p.next++
	if server {
		tmpl.DNSNames, tmpl.IPAddresses = []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, key.Public(), p.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	body = append(body, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})...)
	if err := os.WriteFile(filepath.Join(p.dir, cn+".pem"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c.Subject.String()
}

func startMongod(t *testing.T, dir, serverPEM, caPEM string, port int) {
	kf := make([]byte, 600)
	_, _ = rand.Read(kf)
	keyFile := filepath.Join(dir, "keyfile")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(kf)), 0o400); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "db")
	_ = os.MkdirAll(db, 0o755)
	cmd := exec.Command("mongod", "--dbpath", db, "--port", fmt.Sprint(port), "--bind_ip", "127.0.0.1", "--replSet", "rs0", "--keyFile", keyFile,
		"--tlsMode", "requireTLS", "--tlsCertificateKeyFile", serverPEM, "--tlsCAFile", caPEM, "--tlsAllowConnectionsWithoutCertificates", "--tlsClusterCAFile", caPEM, "--logpath", filepath.Join(dir, "mongod.log"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("mongod did not start")
}

// A tenant's server authenticates to the cluster with its certificate, over TLS: it can do what it needs in its own database, cannot touch another tenant's, cannot administer, and
// a connection without the certificate (or without TLS) gets nothing.
//
//	FLEETCORE_X509_TEST=1 go test ./fleetcore/provision        (needs mongod on the path)
func TestTenantServerAuthenticatesWithItsCertificate(t *testing.T) {
	if os.Getenv("FLEETCORE_X509_TEST") == "" {
		t.Skip("FLEETCORE_X509_TEST not set")
	}
	if _, err := exec.LookPath("mongod"); err != nil {
		t.Skip("mongod is not installed")
	}
	dir := t.TempDir()
	p := newPKI(t, dir)
	p.issue(t, "localhost-server", true)
	ca := filepath.Join(dir, "ca.pem")
	const port = 27318
	startMongod(t, dir, filepath.Join(dir, "localhost-server.pem"), ca, port)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	base := fmt.Sprintf("mongodb://127.0.0.1:%d/?tls=true&tlsCAFile=%s", port, ca)

	// 1. First start: initiate the replica set and create the administrator (the localhost exception allows exactly this).
	boot, err := mongo.Connect(options.Client().ApplyURI(base + "&directConnection=true"))
	if err != nil {
		t.Fatal(err)
	}
	if err := boot.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetInitiate", Value: bson.D{{Key: "_id", Value: "rs0"}, {Key: "members", Value: bson.A{bson.D{{Key: "_id", Value: 0}, {Key: "host", Value: fmt.Sprintf("127.0.0.1:%d", port)}}}}}}}).Err(); err != nil {
		t.Fatalf("initiate: %v", err)
	}
	for i := 0; i < 100; i++ {
		var r bson.M
		if boot.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&r) == nil && r["isWritablePrimary"] == true {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err := boot.Database("admin").RunCommand(ctx, bson.D{{Key: "createUser", Value: "root"}, {Key: "pwd", Value: "rootpw"}, {Key: "roles", Value: bson.A{"root"}}}).Err(); err != nil {
		t.Fatalf("create root: %v", err)
	}
	boot.Disconnect(ctx)
	root, err := mongo.Connect(options.Client().ApplyURI(base + "&replicaSet=rs0&directConnection=true").SetAuth(options.Credential{Username: "root", Password: "rootpw", AuthSource: "admin"}))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Disconnect(ctx)

	// 2. The operator gives each tenant server its identity.
	acmeDN := p.issue(t, "acme-mdm", false)
	globexDN := p.issue(t, "globex-mdm", false)
	reportDN := p.issue(t, "acme-report", false)
	for _, u := range []User{{Subject: acmeDN, Database: "fleetcore_acme"}, {Subject: globexDN, Database: "fleetcore_globex"}, {Subject: reportDN, Database: "fleetcore_acme", ReadOnly: true}} {
		if err := Create(ctx, root, u); err != nil {
			t.Fatalf("provisioning %s: %v", u.Subject, err)
		}
	}
	// Running it again changes nothing (and does not fail).
	if err := Create(ctx, root, User{Subject: acmeDN, Database: "fleetcore_acme"}); err != nil {
		t.Fatalf("second provisioning: %v", err)
	}
	users, err := Users(ctx, root)
	if err != nil || len(users[acmeDN]) != 1 || users[acmeDN][0] != "fleetcore:fleetcore_acme" {
		t.Fatalf("users: %v %v", users, err)
	}

	connect := func(name string) *mongo.Client {
		o, err := X509Options(base+"&replicaSet=rs0&directConnection=true", filepath.Join(dir, name+".pem"), ca)
		if err != nil {
			t.Fatal(err)
		}
		c, err := mongo.Connect(o)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Disconnect(context.Background()) })
		return c
	}
	acme, globex, report := connect("acme-mdm"), connect("globex-mdm"), connect("acme-report")

	// 3. What a tenant server does in its own database works, including what the MDM storage needs (indexes, transactions).
	store, err := mongodb.New(ctx, mongodb.WithClient(acme), mongodb.WithDatabase("fleetcore_acme"))
	if err != nil {
		t.Fatalf("the tenant's own storage could not start: %v", err)
	}
	cmd, err := mdm.DecodeCommand([]byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CommandUUID</key><string>U1</string><key>Command</key><dict><key>RequestType</key><string>DeviceInformation</string></dict></dict></plist>`))
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd // a command needs an enrollment to be queued for; the transaction itself is what matters here
	if _, err := store.EnqueueCommand(ctx, []string{"dev1"}, cmd); err != nil {
		t.Fatalf("a transaction in the tenant's own database: %v", err)
	}

	// 4. It cannot reach another tenant's database, nor administer the cluster.
	denied := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s was allowed", what)
			return
		}
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "unauthorized") && !strings.Contains(low, "not authorized") && !strings.Contains(low, "requires authentication") && !strings.Contains(low, "auth error") {
			t.Errorf("%s failed, but not as a refusal: %v", what, err)
		}
	}
	denied("reading another tenant's database", acme.Database("fleetcore_globex").Collection("commands").FindOne(ctx, bson.D{}).Err())
	denied("writing another tenant's database", func() error {
		_, err := acme.Database("fleetcore_globex").Collection("commands").InsertOne(ctx, bson.D{{Key: "x", Value: 1}})
		return err
	}())
	denied("reading the other direction", globex.Database("fleetcore_acme").Collection("commands").FindOne(ctx, bson.D{}).Err())
	denied("dropping its own database", acme.Database("fleetcore_acme").Drop(ctx))
	denied("creating a user", acme.Database("$external").RunCommand(ctx, bson.D{{Key: "createUser", Value: "CN=evil"}, {Key: "roles", Value: bson.A{"root"}}}).Err())
	// listDatabases answers each identity with the databases it may use, no more: the other tenant's name is not even revealed.
	var dbs struct {
		Databases []struct {
			Name string `bson:"name"`
		} `bson:"databases"`
	}
	if err := acme.Database("admin").RunCommand(ctx, bson.D{{Key: "listDatabases", Value: 1}, {Key: "nameOnly", Value: true}, {Key: "authorizedDatabases", Value: true}}).Decode(&dbs); err != nil {
		t.Fatalf("listing databases: %v", err)
	}
	for _, d := range dbs.Databases {
		if d.Name != "fleetcore_acme" {
			t.Errorf("the tenant can see a database called %q", d.Name)
		}
	}

	// 5. A read-only identity reads and cannot write.
	if err := report.Database("fleetcore_acme").Collection("commands").FindOne(ctx, bson.D{}).Err(); err != nil && err != mongo.ErrNoDocuments {
		t.Errorf("the read-only identity could not read: %v", err)
	}
	_, werr := report.Database("fleetcore_acme").Collection("commands").InsertOne(ctx, bson.D{{Key: "x", Value: 1}})
	denied("the read-only identity writing", werr)

	// 6. Without the certificate, or without TLS, nothing.
	anon, err := mongo.Connect(options.Client().ApplyURI(base + "&replicaSet=rs0&directConnection=true"))
	if err != nil {
		t.Fatal(err)
	}
	defer anon.Disconnect(ctx)
	denied("an unauthenticated read", anon.Database("fleetcore_acme").Collection("commands").FindOne(ctx, bson.D{}).Err())
	plain, err := mongo.Connect(options.Client().ApplyURI(fmt.Sprintf("mongodb://127.0.0.1:%d/?directConnection=true&serverSelectionTimeoutMS=1500", port)))
	if err == nil {
		defer plain.Disconnect(ctx)
		if plain.Ping(ctx, nil) == nil {
			t.Error("a connection without TLS worked")
		}
	}
	// a certificate from another CA is refused at the handshake
	other := newPKI(t, t.TempDir())
	other.issue(t, "intruder", false)
	o, _ := X509Options(base+"&replicaSet=rs0&directConnection=true&serverSelectionTimeoutMS=2000", filepath.Join(other.dir, "intruder.pem"), ca)
	if ic, err := mongo.Connect(o); err == nil {
		defer ic.Disconnect(ctx)
		if err := ic.Database("fleetcore_acme").Collection("commands").FindOne(ctx, bson.D{}).Err(); err == nil || err == mongo.ErrNoDocuments {
			t.Error("a certificate from another CA was accepted")
		}
	}
	_ = tls.VersionTLS12
	// 7. Taking the user away takes the access away.
	if err := Remove(ctx, root, acmeDN); err != nil {
		t.Fatal(err)
	}
	gone := connect("acme-mdm")
	denied("a removed user reading", gone.Database("fleetcore_acme").Collection("commands").FindOne(ctx, bson.D{}).Err())
}
