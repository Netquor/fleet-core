// Package provision sets up what a tenant's server needs from the MongoDB cluster: a database user that is a client certificate (no password to leak, or to rotate by hand), allowed to do
// what the server does in its own database and nothing else, and not to touch any other tenant's database.
//
// What MongoDB can and cannot enforce: access is granted per database, never per document. A server that shares a database with other tenants (the dense layout, with the tenant on every
// document) is kept to its own tenant by the software and by its own encryption key, and can in principle read the other tenants' unencrypted metadata; the database itself keeps it out of
// every other database. A tenant that needs the cluster to enforce the boundary gets a database of its own and a user restricted to it.
package provision

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Actions is everything the server does in its database. It cannot drop a collection or the database, create users, or reach another database.
var Actions = []string{"find", "insert", "update", "remove", "createIndex", "listIndexes", "listCollections", "createCollection", "collStats", "dbStats", "changeStream"}

// ReadOnlyActions is for a reporting or backup identity.
var ReadOnlyActions = []string{"find", "listIndexes", "listCollections", "collStats", "dbStats", "changeStream"}

// RoleName is the name of the role that grants access to one database.
func RoleName(database string, readOnly bool) string {
	if readOnly {
		return "fleetcore-ro:" + database
	}
	return "fleetcore:" + database
}

// User is a database identity: a client certificate subject and the one database it may use.
type User struct {
	// Subject is the certificate's subject in the form MongoDB matches (RFC 2253, for example "CN=acme-mdm-1,O=Example").
	Subject  string
	Database string
	ReadOnly bool
}

func (u User) validate() error {
	if u.Subject == "" || !strings.Contains(u.Subject, "=") {
		return errors.New("the subject is the certificate's, like CN=acme-mdm-1,O=Example")
	}
	if u.Database == "" || u.Database == "admin" || u.Database == "local" || u.Database == "config" || strings.ContainsAny(u.Database, "/\\. \"$") {
		return errors.New("the database must be a name of the tenant's own, not a system database")
	}
	return nil
}

// Create makes the role and the certificate user on the cluster (the client must be connected as an administrator), or brings an existing user to this role.
func Create(ctx context.Context, c *mongo.Client, u User) error {
	if err := u.validate(); err != nil {
		return err
	}
	admin := c.Database("admin")
	actions := Actions
	if u.ReadOnly {
		actions = ReadOnlyActions
	}
	privileges := bson.A{bson.D{{Key: "resource", Value: bson.D{{Key: "db", Value: u.Database}, {Key: "collection", Value: ""}}}, {Key: "actions", Value: stringsToA(actions)}}}
	role := RoleName(u.Database, u.ReadOnly)
	err := admin.RunCommand(ctx, bson.D{{Key: "createRole", Value: role}, {Key: "privileges", Value: privileges}, {Key: "roles", Value: bson.A{}}}).Err()
	if isExists(err) {
		err = admin.RunCommand(ctx, bson.D{{Key: "updateRole", Value: role}, {Key: "privileges", Value: privileges}, {Key: "roles", Value: bson.A{}}}).Err()
	}
	if err != nil {
		return fmt.Errorf("role %s: %w", role, err)
	}
	ext := c.Database("$external")
	roles := bson.A{bson.D{{Key: "role", Value: role}, {Key: "db", Value: "admin"}}}
	err = ext.RunCommand(ctx, bson.D{{Key: "createUser", Value: u.Subject}, {Key: "roles", Value: roles}}).Err()
	if isExists(err) {
		err = ext.RunCommand(ctx, bson.D{{Key: "updateUser", Value: u.Subject}, {Key: "roles", Value: roles}}).Err()
	}
	if err != nil {
		return fmt.Errorf("user %s: %w", u.Subject, err)
	}
	return nil
}

// Remove takes the certificate user away (the role stays for other users of the database).
func Remove(ctx context.Context, c *mongo.Client, subject string) error {
	return c.Database("$external").RunCommand(ctx, bson.D{{Key: "dropUser", Value: subject}}).Err()
}

// Script is the same setup as mongosh commands, for an operator who runs them by hand.
func Script(u User) string {
	actions := Actions
	if u.ReadOnly {
		actions = ReadOnlyActions
	}
	role := RoleName(u.Database, u.ReadOnly)
	quoted := make([]string, len(actions))
	for i, a := range actions {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	return fmt.Sprintf(`use admin
db.createRole({role: %q, privileges: [{resource: {db: %q, collection: ""}, actions: [%s]}], roles: []})
use $external
db.createUser({user: %q, roles: [{role: %q, db: "admin"}]})
`, role, u.Database, strings.Join(quoted, ", "), u.Subject, role)
}

func isExists(err error) bool {
	if err == nil {
		return false
	}
	var ce mongo.CommandError
	if errors.As(err, &ce) {
		return ce.Code == 51002 || ce.Code == 51003 || ce.Code == 11000 || strings.Contains(strings.ToLower(ce.Message), "already exists")
	}
	return strings.Contains(strings.ToLower(err.Error()), "already exists")
}

func stringsToA(s []string) bson.A {
	out := make(bson.A, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// Users lists the certificate users and their roles (for an operator's overview).
func Users(ctx context.Context, c *mongo.Client) (map[string][]string, error) {
	var res struct {
		Users []struct {
			User  string `bson:"user"`
			Roles []struct {
				Role string `bson:"role"`
			} `bson:"roles"`
		} `bson:"users"`
	}
	if err := c.Database("$external").RunCommand(ctx, bson.D{{Key: "usersInfo", Value: 1}}).Decode(&res); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, u := range res.Users {
		for _, r := range u.Roles {
			out[u.User] = append(out[u.User], r.Role)
		}
		sort.Strings(out[u.User])
	}
	return out, nil
}

// X509Options returns client options for a server that authenticates to MongoDB with its certificate: TLS, a CA that signed the cluster's certificate, and MONGODB-X509 (the user
// is the certificate's subject).
func X509Options(uri, certKeyFile, caFile string) (*options.ClientOptions, error) {
	cert, err := tls.LoadX509KeyPair(certKeyFile, certKeyFile)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("no certificate in the CA file")
		}
		cfg.RootCAs = pool
	}
	return options.Client().ApplyURI(uri).SetTLSConfig(cfg).SetAuth(options.Credential{AuthMechanism: "MONGODB-X509", AuthSource: "$external"}), nil
}
