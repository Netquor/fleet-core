// Package mongodb stores and retrieves MDM data in MongoDB.
//
// It follows the SQL backends closely (the same tables become collections, the same primary keys become _id or unique indexes) so that behavior matches.
// Multi-document changes (enqueueing a command for many enrollments, deleting a command once nothing refers to it) use transactions, which MongoDB only
// offers on a replica set (or a sharded cluster): a standalone mongod will not do.
package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/micromdm/nanomdm/cryptoutil"
	"github.com/micromdm/nanomdm/mdm"

	"github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanolib/log/ctxlog"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Collection names. They match the SQL table names.
const (
	cDevices      = "devices"
	cUsers        = "users"
	cEnrollments  = "enrollments"
	cCommands     = "commands"
	cQueue        = "enrollment_queue"
	cPushCerts    = "push_certs"
	cCertAuth     = "cert_auth_associations"
	defaultDBName = "nanomdm"
)

var ErrNoCert = errors.New("no certificate in MDM Request")

// MongoDBStorage is the MongoDB storage backend.
type MongoDBStorage struct {
	logger log.Logger
	client *mongo.Client
	db     *mongo.Database
	rm     bool
	owned  bool   // whether Close should disconnect the client
	tid    string // the tenant, when tenants share collections (empty: this database is the tenant's alone)
}

// pk is the _id of a document that is keyed by an id: the id itself, or the tenant and the id when tenants share collections.
func (s *MongoDBStorage) pk(id string) string {
	if s.tid == "" {
		return id
	}
	return s.tid + "\x1f" + id
}

// scope puts the tenant in front of a filter, when tenants share collections. Every query on a collection that holds more than one tenant goes through it (or through pk), so a store bound to one tenant cannot see another's data.
func (s *MongoDBStorage) scope(f bson.D) bson.D {
	if s.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, f...)
}

// stamp adds the tenant to a document being written, when tenants share collections.
func (s *MongoDBStorage) stamp(d bson.D) bson.D {
	if s.tid == "" {
		return d
	}
	return append(d, bson.E{Key: "t", Value: s.tid})
}

// stampSet is stamp for the fields of an aggregation-pipeline $set (the tenant is a literal there).
func (s *MongoDBStorage) stampSet(d bson.D) bson.D {
	if s.tid == "" {
		return d
	}
	return append(d, bson.E{Key: "t", Value: lit(s.tid)})
}

// onInsert is what a new document keyed by an id starts with: its id (also kept apart from _id, which carries the tenant when they share), its creation time, and the tenant.
func (s *MongoDBStorage) onInsert(id string, t time.Time) bson.D {
	return s.stamp(bson.D{{Key: "id", Value: id}, {Key: "created_at", Value: t}})
}

type config struct {
	tenant string
	uri    string
	dbName string
	client *mongo.Client
	logger log.Logger
	rm     bool
	noIdx  bool
}

// Option configures New.
type Option func(*config)

// WithLogger sets the logger.
func WithLogger(logger log.Logger) Option { return func(c *config) { c.logger = logger } }

// WithURI sets the MongoDB connection string (mongodb:// or mongodb+srv://). The database defaults to the one in the URI path, else "nanomdm".
func WithURI(uri string) Option { return func(c *config) { c.uri = uri } }

// WithDatabase names the database, overriding the URI's.
func WithDatabase(name string) Option { return func(c *config) { c.dbName = name } }

// WithTenant binds the store to one tenant that shares its collections with others: every document carries the tenant, every query is scoped to it, and indexes lead with it.
// Without it the whole database belongs to one tenant (a database per tenant). The tenant cannot be changed after the store is made.
func WithTenant(id string) Option { return func(c *config) { c.tenant = id } }

// WithClient uses an existing client (which the caller keeps ownership of).
func WithClient(client *mongo.Client) Option { return func(c *config) { c.client = client } }

// WithDeleteCommands deletes a command (and its queue entry and result) once an enrollment has acknowledged it, other than NotNow.
func WithDeleteCommands() Option { return func(c *config) { c.rm = true } }

// WithoutIndexes skips creating indexes at startup (for deployments where an admin manages them).
func WithoutIndexes() Option { return func(c *config) { c.noIdx = true } }

// New connects, checks the connection and makes sure the indexes exist.
func New(ctx context.Context, opts ...Option) (*MongoDBStorage, error) {
	cfg := &config{logger: log.NopLogger}
	for _, opt := range opts {
		opt(cfg)
	}
	s := &MongoDBStorage{logger: cfg.logger, rm: cfg.rm, tid: cfg.tenant}
	name := cfg.dbName
	if cfg.client == nil {
		if cfg.uri == "" {
			return nil, errors.New("mongodb: no URI")
		}
		co := options.Client().ApplyURI(cfg.uri)
		client, err := mongo.Connect(co)
		if err != nil {
			return nil, err
		}
		cfg.client, s.owned = client, true
		if name == "" {
			if cs, err := parseDB(cfg.uri); err == nil {
				name = cs
			}
		}
	}
	if name == "" {
		name = defaultDBName
	}
	s.client, s.db = cfg.client, cfg.client.Database(name)
	if err := s.client.Ping(ctx, nil); err != nil {
		if s.owned {
			_ = s.client.Disconnect(ctx)
		}
		return nil, err
	}
	if !cfg.noIdx {
		if err := s.EnsureIndexes(ctx); err != nil {
			return nil, fmt.Errorf("mongodb indexes: %w", err)
		}
	}
	return s, nil
}

// Close disconnects a client that New made.
func (s *MongoDBStorage) Close(ctx context.Context) error {
	if s.owned {
		return s.client.Disconnect(ctx)
	}
	return nil
}

// EnsureIndexes creates what the queries and the uniqueness rules need. It is safe to run again.
func (s *MongoDBStorage) EnsureIndexes(ctx context.Context) error {
	idx := func(coll string, models ...mongo.IndexModel) error {
		_, err := s.db.Collection(coll).Indexes().CreateMany(ctx, models)
		return err
	}
	key := func(kv ...any) bson.D {
		d := bson.D{}
		if s.tid != "" {
			d = append(d, bson.E{Key: "t", Value: 1}) // tenants share collections: every index leads with the tenant
		}
		for i := 0; i+1 < len(kv); i += 2 {
			d = append(d, bson.E{Key: kv[i].(string), Value: kv[i+1]})
		}
		return d
	}
	unique := options.Index().SetUnique(true)
	for _, f := range []func() error{
		func() error { return idx(cDevices, mongo.IndexModel{Keys: key("serial_number", 1)}) },
		func() error { return idx(cUsers, mongo.IndexModel{Keys: key("device_id", 1)}) },
		func() error {
			// user_id is unique among enrollments that have one (a device channel enrollment has none).
			return idx(cEnrollments,
				mongo.IndexModel{Keys: key("device_id", 1)},
				mongo.IndexModel{Keys: key("type", 1)},
				mongo.IndexModel{Keys: key("user_id", 1), Options: options.Index().SetUnique(true).SetPartialFilterExpression(bson.D{{Key: "user_id", Value: bson.D{{Key: "$type", Value: "string"}}}})})
		},
		func() error {
			return idx(cQueue,
				mongo.IndexModel{Keys: key("id", 1, "command_uuid", 1), Options: unique},
				mongo.IndexModel{Keys: key("id", 1, "active", 1, "status", 1, "priority", -1, "created_at", 1)},
				mongo.IndexModel{Keys: key("command_uuid", 1)})
		},
		func() error {
			return idx(cCertAuth,
				mongo.IndexModel{Keys: key("id", 1, "sha256", 1), Options: unique},
				mongo.IndexModel{Keys: key("sha256", 1)})
		},
	} {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

// nullEmpty stores nil (a BSON null) for an empty string, like the SQL backends' NULL.
func nullEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

var now = func() time.Time { return time.Now().UTC() }

func parseDB(uri string) (string, error) {
	cs, err := parseConnString(uri)
	if err != nil {
		return "", err
	}
	return cs, nil
}

// StoreAuthenticate stores the Authenticate check-in message from an enrollment.
func (s *MongoDBStorage) StoreAuthenticate(r *mdm.Request, msg *mdm.Authenticate) error {
	var pemCert []byte
	if r.Certificate != nil {
		pemCert = cryptoutil.PEMCertificate(r.Certificate.Raw)
	}
	t := now()
	_, err := s.db.Collection(cDevices).UpdateOne(r.Context(),
		bson.D{{Key: "_id", Value: s.pk(r.ID)}},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "identity_cert", Value: nullEmpty(string(pemCert))},
				{Key: "serial_number", Value: nullEmpty(msg.SerialNumber)},
				{Key: "bootstrap_token_b64", Value: nil},
				{Key: "bootstrap_token_at", Value: nil},
				{Key: "authenticate", Value: string(msg.Raw)},
				{Key: "authenticate_doc", Value: plistDoc(msg.Raw)},
				{Key: "authenticate_at", Value: t},
				{Key: "updated_at", Value: t},
			}},
			{Key: "$setOnInsert", Value: s.onInsert(r.ID, t)},
		},
		options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoDBStorage) storeDeviceTokenUpdate(r *mdm.Request, msg *mdm.TokenUpdate) error {
	t := now()
	set := bson.D{{Key: "token_update", Value: string(msg.Raw)}, {Key: "token_update_doc", Value: plistDoc(msg.Raw)}, {Key: "token_update_at", Value: t}, {Key: "updated_at", Value: t}}
	// separately store the Unlock Token per MDM spec
	if len(msg.UnlockToken) > 0 {
		set = append(set, bson.E{Key: "unlock_token", Value: msg.UnlockToken}, bson.E{Key: "unlock_token_at", Value: t})
	}
	_, err := s.db.Collection(cDevices).UpdateOne(r.Context(), bson.D{{Key: "_id", Value: s.pk(r.ID)}}, bson.D{{Key: "$set", Value: set}})
	return err
}

func (s *MongoDBStorage) storeUserTokenUpdate(r *mdm.Request, msg *mdm.TokenUpdate) error {
	// there shouldn't be an Unlock Token on the user channel, but complain if there is to warn an admin
	if len(msg.UnlockToken) > 0 {
		ctxlog.Logger(r.Context(), s.logger).Info("msg", "Unlock Token on user channel not stored")
	}
	t := now()
	_, err := s.db.Collection(cUsers).UpdateOne(r.Context(),
		bson.D{{Key: "_id", Value: s.pk(r.ID)}},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "device_id", Value: r.ParentID},
				{Key: "user_short_name", Value: nullEmpty(msg.UserShortName)},
				{Key: "user_long_name", Value: nullEmpty(msg.UserLongName)},
				{Key: "token_update", Value: string(msg.Raw)},
				{Key: "token_update_doc", Value: plistDoc(msg.Raw)},
				{Key: "token_update_at", Value: t},
				{Key: "updated_at", Value: t},
			}},
			{Key: "$setOnInsert", Value: s.onInsert(r.ID, t)},
		},
		options.UpdateOne().SetUpsert(true))
	return err
}

// StoreTokenUpdate stores the TokenUpdate check-in message. The first one is a successful enrollment.
func (s *MongoDBStorage) StoreTokenUpdate(r *mdm.Request, msg *mdm.TokenUpdate) error {
	var err error
	var deviceID, userID string
	resolved := (&msg.Enrollment).Resolved()
	if err = resolved.Validate(); err != nil {
		return err
	}
	if resolved.IsUserChannel {
		deviceID, userID = r.ParentID, r.ID
		err = s.storeUserTokenUpdate(r, msg)
	} else {
		deviceID = r.ID
		err = s.storeDeviceTokenUpdate(r, msg)
	}
	if err != nil {
		return err
	}
	// One pipeline update does what the SQL "ON CONFLICT DO UPDATE" does: a new enrollment starts at tally 1 and each TokenUpdate adds one.
	_, err = s.db.Collection(cEnrollments).UpdateOne(r.Context(),
		bson.D{{Key: "_id", Value: s.pk(r.ID)}},
		mongo.Pipeline{{{Key: "$set", Value: s.stampSet(bson.D{
			{Key: "id", Value: lit(r.ID)},
			{Key: "device_id", Value: lit(deviceID)},
			{Key: "user_id", Value: lit(nullEmpty(userID))},
			{Key: "type", Value: lit(r.Type.String())},
			{Key: "topic", Value: lit(msg.Topic)},
			{Key: "push_magic", Value: lit(msg.PushMagic)},
			{Key: "token_hex", Value: lit(msg.Token.String())},
			{Key: "enabled", Value: true},
			{Key: "last_seen_at", Value: "$$NOW"},
			{Key: "updated_at", Value: "$$NOW"},
			{Key: "created_at", Value: bson.D{{Key: "$ifNull", Value: bson.A{"$created_at", "$$NOW"}}}},
			{Key: "token_update_tally", Value: bson.D{{Key: "$add", Value: bson.A{bson.D{{Key: "$ifNull", Value: bson.A{"$token_update_tally", 0}}}, 1}}}},
		})}}},
		options.UpdateOne().SetUpsert(true))
	return err
}

// RetrieveTokenUpdateTally retrieves the TokenUpdate tally for id (0 with no error when there is none).
func (s *MongoDBStorage) RetrieveTokenUpdateTally(ctx context.Context, id string) (int, error) {
	var doc struct {
		Tally int `bson:"token_update_tally"`
	}
	err := s.db.Collection(cEnrollments).FindOne(ctx, bson.D{{Key: "_id", Value: s.pk(id)}}, options.FindOne().SetProjection(bson.D{{Key: "token_update_tally", Value: 1}})).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return 0, nil
	}
	return doc.Tally, err
}

// StoreUserAuthenticate stores a UserAuthenticate check-in message.
func (s *MongoDBStorage) StoreUserAuthenticate(r *mdm.Request, msg *mdm.UserAuthenticate) error {
	col, colAt := "user_authenticate", "user_authenticate_at"
	// if the DigestResponse is empty then this is the first (of two) UserAuthenticate messages depending on our response
	if msg.DigestResponse != "" {
		col, colAt = "user_authenticate_digest", "user_authenticate_digest_at"
	}
	t := now()
	_, err := s.db.Collection(cUsers).UpdateOne(r.Context(),
		bson.D{{Key: "_id", Value: s.pk(r.ID)}},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "device_id", Value: r.ParentID},
				{Key: "user_short_name", Value: nullEmpty(msg.UserShortName)},
				{Key: "user_long_name", Value: nullEmpty(msg.UserLongName)},
				{Key: col, Value: string(msg.Raw)},
				{Key: colAt, Value: t},
				{Key: "updated_at", Value: t},
			}},
			{Key: "$setOnInsert", Value: s.onInsert(r.ID, t)},
		},
		options.UpdateOne().SetUpsert(true))
	if err != nil {
		return err
	}
	return s.updateLastSeen(r)
}

// Disable the MDM enrollment (an Authenticate or CheckOut): the device channel and, with it, any user channels.
func (s *MongoDBStorage) Disable(r *mdm.Request) error {
	if r.ParentID != "" {
		return errors.New("can only disable a device channel")
	}
	t := now()
	_, err := s.db.Collection(cEnrollments).UpdateMany(r.Context(),
		s.scope(bson.D{{Key: "device_id", Value: r.ID}, {Key: "enabled", Value: true}}),
		bson.D{{Key: "$set", Value: bson.D{{Key: "enabled", Value: false}, {Key: "token_update_tally", Value: 0}, {Key: "last_seen_at", Value: t}, {Key: "updated_at", Value: t}}}})
	return err
}

func (s *MongoDBStorage) updateLastSeen(r *mdm.Request) error {
	t := now()
	_, err := s.db.Collection(cEnrollments).UpdateOne(r.Context(), bson.D{{Key: "_id", Value: s.pk(r.ID)}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "last_seen_at", Value: t}, {Key: "updated_at", Value: t}}}})
	if err != nil {
		return fmt.Errorf("updating last seen: %w", err)
	}
	return nil
}

// DeleteTenant removes everything of this store's tenant from the shared collections (a tenant leaving). Only a store bound with WithTenant can do it; when a database is the tenant's alone, drop the database.
// It deletes in each collection by tenant, in batches the server handles one after another; nothing of any other tenant is touched.
func (s *MongoDBStorage) DeleteTenant(ctx context.Context) (deleted int64, err error) {
	if s.tid == "" {
		return 0, errors.New("DeleteTenant needs a tenant: drop the database when it belongs to one tenant")
	}
	for _, c := range []string{cQueue, cCommands, cEnrollments, cUsers, cDevices, cCertAuth, cPushCerts} {
		res, err := s.db.Collection(c).DeleteMany(ctx, bson.D{{Key: "t", Value: s.tid}})
		if err != nil {
			return deleted, fmt.Errorf("deleting %s: %w", c, err)
		}
		deleted += res.DeletedCount
	}
	return deleted, nil
}
