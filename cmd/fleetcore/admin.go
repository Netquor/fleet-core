package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/provision"
	"github.com/micromdm/nanomdm/fleetcore/seal"
	"github.com/micromdm/nanomdm/fleetcore/userauth"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// adminCommand runs the operator subcommands: keygen, tenant-key, mongo-user. It returns false when the arguments are the server's own flags.
func adminCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "keygen":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fatalf("%v", err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(b))
	case "ua-hash":
		fs := flag.NewFlagSet("ua-hash", flag.ExitOnError)
		user := fs.String("user", "", "the person's short name")
		realm := fs.String("realm", "", "the realm (-ua-realm)")
		fs.Usage = func() {
			fmt.Fprintln(os.Stderr, "Usage: fleetcore ua-hash -user NAME -realm REALM\n\nReads the password from standard input and prints a user:realm:ha1 line for the -ua-users file. The password is not stored.")
		}
		_ = fs.Parse(args[1:])
		if *user == "" || *realm == "" {
			fs.Usage()
			os.Exit(2)
		}
		pw, _ := io.ReadAll(os.Stdin)
		fmt.Printf("%s:%s:%s\n", *user, *realm, userauth.HA1(*user, *realm, strings.TrimRight(string(pw), "\r\n")))
	case "tenant-key":
		fs := flag.NewFlagSet("tenant-key", flag.ExitOnError)
		tenant := fs.String("tenant", "", "the tenant id")
		master := fs.String("master-key", env("FLEETCORE_MASTER_KEY", ""), "master keys (base64, comma separated, current first)")
		file := fs.String("master-key-file", env("FLEETCORE_MASTER_KEY_FILE", ""), "file with the master keys")
		fs.Usage = func() {
			fmt.Fprintln(os.Stderr, "Usage: fleetcore tenant-key -tenant ID [-master-key KEYS | -master-key-file FILE]\n\nPrints the tenant's key (one per master key, current first) for the tenant's server to use as\nFLEETCORE_TENANT_KEYS. Run it where the master key lives, never on the tenant's server.")
		}
		_ = fs.Parse(args[1:])
		if *file != "" {
			b, err := os.ReadFile(*file)
			if err != nil {
				fatalf("%v", err)
			}
			*master = string(b)
		}
		keys, err := seal.ParseKeys(*master)
		if err != nil || len(keys) == 0 {
			fatalf("a master key is required (-master-key or -master-key-file)")
		}
		ring, err := seal.NewKeyring(keys...)
		if err != nil {
			fatalf("%v", err)
		}
		for _, k := range ring.TenantKeys(*tenant) {
			fmt.Println(k)
		}
	case "mongo-user":
		fs := flag.NewFlagSet("mongo-user", flag.ExitOnError)
		uri := fs.String("uri", env("FLEETCORE_ADMIN_MONGO_URI", ""), "MongoDB URI of an administrator (with credentials, or use -cert)")
		cert := fs.String("cert", "", "administrator's client certificate and key (PEM) for MONGODB-X509")
		ca := fs.String("ca", "", "CA certificate that signed the cluster's certificate")
		subject := fs.String("subject", "", "the tenant server's certificate subject, for example CN=acme-mdm-1,O=Example")
		db := fs.String("db", "", "the database the server may use")
		readOnly := fs.Bool("read-only", false, "read-only access")
		remove := fs.Bool("remove", false, "remove the user instead")
		script := fs.Bool("script", false, "print the mongosh commands and do nothing")
		fs.Usage = func() {
			fmt.Fprintln(os.Stderr, "Usage: fleetcore mongo-user -subject DN -db NAME [-uri URI [-cert FILE -ca FILE]] [-read-only] [-remove] [-script]\n\nGives a tenant's server a database identity: its client certificate, allowed to use one database.")
			fs.PrintDefaults()
		}
		_ = fs.Parse(args[1:])
		u := provision.User{Subject: *subject, Database: *db, ReadOnly: *readOnly}
		if *script {
			fmt.Print(provision.Script(u))
			return true
		}
		if *uri == "" {
			fatalf("-uri is required (or -script to print the commands)")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var client *mongo.Client
		var err error
		if *cert != "" {
			var o *options.ClientOptions
			if o, err = provision.X509Options(*uri, *cert, *ca); err == nil {
				client, err = mongo.Connect(o)
			}
		} else {
			client, err = mongo.Connect(options.Client().ApplyURI(*uri))
		}
		if err != nil {
			fatalf("%v", err)
		}
		defer client.Disconnect(context.Background())
		if *remove {
			err = provision.Remove(ctx, client, *subject)
		} else {
			err = provision.Create(ctx, client, u)
		}
		if err != nil {
			fatalf("%v", err)
		}
		fmt.Println("ok")
	default:
		return false
	}
	return true
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "fleetcore: "+f+"\n", a...)
	os.Exit(1)
}
