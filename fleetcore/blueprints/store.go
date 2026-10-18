package blueprints

import (
	"context"
	"errors"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	cDevices    = "bp_devices"
	cGroups     = "bp_groups"
	cBlueprints = "bp_blueprints"
	cRevisions  = "bp_revisions"
	cApplied    = "bp_applied"
)

// ErrNotFound is returned for a blueprint, group or device that does not exist.
var ErrNotFound = errors.New("not found")

// Store keeps blueprints, groups, the device inventory and what was applied, in MongoDB. With a tenant, tenants share the collections and every document carries it,
// as in the other fleetcore collections.
type Store struct {
	db  *mongo.Database
	tid string
	// Now is the clock (tests set it).
	Now func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// NewStore returns the store and makes its indexes. tenant may be empty (the database belongs to one tenant).
func NewStore(ctx context.Context, db *mongo.Database, tenant string) (*Store, error) {
	s := &Store{db: db, tid: tenant}
	lead := func(k bson.D) bson.D {
		if tenant == "" {
			return k
		}
		return append(bson.D{{Key: "t", Value: 1}}, k...)
	}
	for coll, idx := range map[string][]mongo.IndexModel{
		// The work queue: devices due for reconciliation.
		cDevices: {
			{Keys: lead(bson.D{{Key: "active", Value: 1}, {Key: "reconcile_at", Value: 1}})},
			{Keys: lead(bson.D{{Key: "platform", Value: 1}})},
			{Keys: lead(bson.D{{Key: "tags", Value: 1}})},
			{Keys: lead(bson.D{{Key: "groups", Value: 1}})},
			{Keys: lead(bson.D{{Key: "serial", Value: 1}})},
		},
		cGroups:     {{Keys: lead(bson.D{{Key: "name", Value: 1}}), Options: options.Index().SetUnique(true)}},
		cBlueprints: {{Keys: lead(bson.D{{Key: "name", Value: 1}}), Options: options.Index().SetUnique(true)}},
		cRevisions:  {{Keys: lead(bson.D{{Key: "blueprint", Value: 1}, {Key: "revision", Value: -1}}), Options: options.Index().SetUnique(true)}},
		cApplied: {
			{Keys: lead(bson.D{{Key: "device", Value: 1}})},
			{Keys: lead(bson.D{{Key: "blueprint", Value: 1}, {Key: "state", Value: 1}})},
			{Keys: lead(bson.D{{Key: "command_uuid", Value: 1}})},
		},
	} {
		if _, err := db.Collection(coll).Indexes().CreateMany(ctx, idx); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) key(parts ...string) string {
	k := ""
	for i, p := range parts {
		if i > 0 {
			k += "\x1f"
		}
		k += p
	}
	if s.tid == "" {
		return k
	}
	return s.tid + "\x1f" + k
}

func (s *Store) scope(f bson.D) bson.D {
	if s.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, f...)
}

func (s *Store) stamp(d bson.D) bson.D {
	if s.tid == "" {
		return d
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, d...)
}

// ---- devices ----

// DeviceUpdate is what a check-in learns about a device; empty fields leave what is known.
type DeviceUpdate struct {
	ID, UDID, Serial, Name, Platform, Model, OSVersion, EnrollType string
}

// UpsertDevice records a device seen at check-in, marks it active and due for reconciliation now.
func (s *Store) UpsertDevice(ctx context.Context, u DeviceUpdate, now time.Time) error {
	set := bson.D{{Key: "id", Value: u.ID}, {Key: "active", Value: true}, {Key: "last_seen", Value: now}, {Key: "reconcile_at", Value: now}}
	for k, v := range map[string]string{"udid": u.UDID, "serial": u.Serial, "name": u.Name, "platform": u.Platform, "model": u.Model, "os_version": u.OSVersion, "enroll_type": u.EnrollType} {
		if v != "" {
			set = append(set, bson.E{Key: k, Value: v})
		}
	}
	if n, ok := versionNum(u.OSVersion); ok {
		set = append(set, bson.E{Key: "os_num", Value: n})
	}
	_, err := s.db.Collection(cDevices).UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key(u.ID)}},
		bson.D{{Key: "$set", Value: s.stamp(set)}, {Key: "$setOnInsert", Value: bson.D{{Key: "enrolled_at", Value: now}}}},
		options.UpdateOne().SetUpsert(true))
	return err
}

// Deactivate marks a device that checked out; it leaves the work queue.
func (s *Store) Deactivate(ctx context.Context, id string) error {
	_, err := s.db.Collection(cDevices).UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}}, bson.D{{Key: "$set", Value: bson.D{{Key: "active", Value: false}}}})
	return err
}

// GetDevice returns one device.
func (s *Store) GetDevice(ctx context.Context, id string) (*Device, error) {
	var d Device
	err := s.db.Collection(cDevices).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNotFound
	}
	return &d, err
}

// SetDeviceFields changes fields of a device (tags, groups, DEP name...); with touch it also becomes due now.
func (s *Store) SetDeviceFields(ctx context.Context, id string, fields bson.D, touch bool) error {
	if touch {
		fields = append(fields, bson.E{Key: "reconcile_at", Value: s.now()})
	}
	res, err := s.db.Collection(cDevices).UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}}, bson.D{{Key: "$set", Value: fields}})
	if err == nil && res.MatchedCount == 0 {
		return ErrNotFound
	}
	return err
}

// QueryDevices returns devices matching an expanded rule, by ID, starting after a cursor (the last ID of the previous page).
func (s *Store) QueryDevices(ctx context.Context, r Rule, after string, limit int) ([]Device, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	f := s.scope(bson.D{{Key: "$and", Value: bson.A{r.Filter(), bson.D{{Key: "id", Value: bson.D{{Key: "$gt", Value: after}}}}}}})
	cur, err := s.db.Collection(cDevices).Find(ctx, f, options.Find().SetSort(bson.D{{Key: "id", Value: 1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	var out []Device
	return out, cur.All(ctx, &out)
}

// CountDevices counts active devices matching an expanded rule.
func (s *Store) CountDevices(ctx context.Context, r Rule) (int64, error) {
	return s.db.Collection(cDevices).CountDocuments(ctx, s.scope(bson.D{{Key: "active", Value: true}, {Key: "$and", Value: bson.A{r.Filter()}}}))
}

// Touch makes every active device matching any of the rules due now (a blueprint changed).
func (s *Store) Touch(ctx context.Context, rules ...Rule) error {
	if len(rules) == 0 {
		return nil
	}
	alts := make(bson.A, len(rules))
	for i, r := range rules {
		alts[i] = r.Filter()
	}
	_, err := s.db.Collection(cDevices).UpdateMany(ctx,
		s.scope(bson.D{{Key: "active", Value: true}, {Key: "$or", Value: alts}}),
		bson.D{{Key: "$set", Value: bson.D{{Key: "reconcile_at", Value: s.now()}}}})
	return err
}

// Claim leases one active device that is due, so that any number of workers (in any number of processes) share the queue without a coordinator.
// The lease protects it while it is worked on; a worker that dies loses it when the lease runs out.
func (s *Store) Claim(ctx context.Context, now time.Time, lease time.Duration) (*Device, error) {
	var d Device
	err := s.db.Collection(cDevices).FindOneAndUpdate(ctx,
		s.scope(bson.D{{Key: "active", Value: true}, {Key: "reconcile_at", Value: bson.D{{Key: "$lte", Value: now}}},
			{Key: "$or", Value: bson.A{bson.D{{Key: "lease_until", Value: bson.D{{Key: "$exists", Value: false}}}}, bson.D{{Key: "lease_until", Value: bson.D{{Key: "$lt", Value: now}}}}}}}),
		bson.D{{Key: "$set", Value: bson.D{{Key: "lease_until", Value: now.Add(lease)}}}},
		options.FindOneAndUpdate().SetSort(bson.D{{Key: "reconcile_at", Value: 1}}).SetReturnDocument(options.After)).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &d, err
}

// Release ends a lease and sets when the device is next due. A touch that happened during the work (reconcile_at moved to now) is kept, so no change is lost.
func (s *Store) Release(ctx context.Context, id string, claimedAt, next time.Time) error {
	// Only move reconcile_at if nothing asked for an earlier run while the lease was held.
	_, err := s.db.Collection(cDevices).UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}, {Key: "reconcile_at", Value: bson.D{{Key: "$lte", Value: claimedAt}}}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "reconcile_at", Value: next}}}, {Key: "$unset", Value: bson.D{{Key: "lease_until", Value: ""}}}})
	if err != nil {
		return err
	}
	_, err = s.db.Collection(cDevices).UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}}, bson.D{{Key: "$unset", Value: bson.D{{Key: "lease_until", Value: ""}}}})
	return err
}

// ---- groups ----

func (s *Store) PutGroup(ctx context.Context, g Group) error {
	if g.Rule != nil {
		if err := g.Rule.Validate(); err != nil {
			return err
		}
	}
	_, err := s.db.Collection(cGroups).ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(g.ID)}}, s.stampDoc(g), options.Replace().SetUpsert(true))
	if err == nil {
		// Members of a changed group may need a different blueprint.
		_ = s.touchAll(ctx)
	}
	return err
}

func (s *Store) touchAll(ctx context.Context) error {
	_, err := s.db.Collection(cDevices).UpdateMany(ctx, s.scope(bson.D{{Key: "active", Value: true}}), bson.D{{Key: "$set", Value: bson.D{{Key: "reconcile_at", Value: s.now()}}}})
	return err
}

func (s *Store) stampDoc(v any) bson.D {
	b, _ := bson.Marshal(v)
	var d bson.D
	_ = bson.Unmarshal(b, &d)
	return s.stamp(d)
}

func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	cur, err := s.db.Collection(cGroups).Find(ctx, s.scope(bson.D{}), options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return nil, err
	}
	var out []Group
	return out, cur.All(ctx, &out)
}

func (s *Store) GetGroup(ctx context.Context, id string) (*Group, error) {
	var g Group
	err := s.db.Collection(cGroups).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}}).Decode(&g)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNotFound
	}
	return &g, err
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	res, err := s.db.Collection(cGroups).DeleteOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}})
	if err == nil && res.DeletedCount == 0 {
		return ErrNotFound
	}
	if err == nil {
		_ = s.touchAll(ctx)
	}
	return err
}

// ---- blueprints ----

func (s *Store) ListBlueprints(ctx context.Context, onlyEnabled bool) ([]Blueprint, error) {
	f := bson.D{}
	if onlyEnabled {
		f = bson.D{{Key: "enabled", Value: true}}
	}
	cur, err := s.db.Collection(cBlueprints).Find(ctx, s.scope(f))
	if err != nil {
		return nil, err
	}
	var out []Blueprint
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (s *Store) GetBlueprint(ctx context.Context, id string) (*Blueprint, error) {
	var b Blueprint
	err := s.db.Collection(cBlueprints).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}}).Decode(&b)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNotFound
	}
	return &b, err
}

// SaveBlueprint stores a new revision. The previous revision stays in the history. The scopes of both old and new revisions are touched so that devices that enter and devices that leave are both reconciled.
func (s *Store) SaveBlueprint(ctx context.Context, b Blueprint, by string, env Env) (*Blueprint, error) {
	now := s.now()
	old, err := s.GetBlueprint(ctx, b.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	b.Revision, b.UpdatedAt, b.UpdatedBy = 1, now, by
	b.RolloutAt = now
	var oldScope *Rule
	if old != nil {
		b.Revision = old.Revision + 1
		oldScope = &old.Scope
		if sameItems(old.Items, b.Items) {
			b.RolloutAt = old.RolloutAt
		}
	}
	if _, err := s.db.Collection(cBlueprints).ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(b.ID)}}, s.stampDoc(b), options.Replace().SetUpsert(true)); err != nil {
		return nil, err
	}
	rev := s.stampDoc(struct {
		Blueprint string    `bson:"blueprint"`
		Revision  int       `bson:"revision"`
		At        time.Time `bson:"at"`
		Doc       Blueprint `bson:"doc"`
	}{b.ID, b.Revision, now, b})
	if _, err := s.db.Collection(cRevisions).InsertOne(ctx, rev); err != nil {
		return nil, err
	}
	rules := []Rule{}
	if e, err := b.Scope.Expand(env); err == nil {
		rules = append(rules, e)
	}
	if oldScope != nil {
		if e, err := oldScope.Expand(env); err == nil {
			rules = append(rules, e)
		}
	}
	if err := s.Touch(ctx, rules...); err != nil {
		return nil, err
	}
	return &b, nil
}

func sameItems(a, b []Item) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Hash() != b[i].Hash() {
			return false
		}
	}
	return true
}

// DeleteBlueprint removes it; devices that had it are reconciled (profiles come off unless it said to keep them).
func (s *Store) DeleteBlueprint(ctx context.Context, id string, env Env) error {
	old, err := s.GetBlueprint(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.db.Collection(cBlueprints).DeleteOne(ctx, bson.D{{Key: "_id", Value: s.key(id)}}); err != nil {
		return err
	}
	// Remember what it put on devices: the engine removes what no blueprint wants any more.
	if _, err := s.db.Collection(cApplied).UpdateMany(ctx, s.scope(bson.D{{Key: "blueprint", Value: id}}), bson.D{{Key: "$set", Value: bson.D{{Key: "orphan_keep", Value: old.KeepOnLeave}}}}); err != nil {
		return err
	}
	devs, err := s.db.Collection(cApplied).Distinct(ctx, "device", s.scope(bson.D{{Key: "blueprint", Value: id}})).Raw()
	if err == nil {
		var ids []string
		if vals, e := devs.Values(); e == nil {
			for _, v := range vals {
				if str, ok := v.StringValueOK(); ok {
					ids = append(ids, str)
				}
			}
		}
		if len(ids) > 0 {
			keys := make(bson.A, len(ids))
			for i, d := range ids {
				keys[i] = s.key(d)
			}
			_, _ = s.db.Collection(cDevices).UpdateMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: keys}}}}, bson.D{{Key: "$set", Value: bson.D{{Key: "reconcile_at", Value: s.now()}}}})
		}
	}
	return nil
}

// Revisions returns a blueprint's history, newest first.
func (s *Store) Revisions(ctx context.Context, id string, limit int) ([]Blueprint, error) {
	if limit <= 0 {
		limit = 50
	}
	cur, err := s.db.Collection(cRevisions).Find(ctx, s.scope(bson.D{{Key: "blueprint", Value: id}}), options.Find().SetSort(bson.D{{Key: "revision", Value: -1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Doc Blueprint `bson:"doc"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]Blueprint, len(rows))
	for i, r := range rows {
		out[i] = r.Doc
	}
	return out, nil
}

// ---- applications ----

func (s *Store) appKey(device, blueprint, item string) string { return s.key(device, blueprint, item) }

func (s *Store) Applications(ctx context.Context, device string) ([]Application, error) {
	cur, err := s.db.Collection(cApplied).Find(ctx, s.scope(bson.D{{Key: "device", Value: device}}))
	if err != nil {
		return nil, err
	}
	var out []Application
	return out, cur.All(ctx, &out)
}

func (s *Store) PutApplication(ctx context.Context, a Application) error {
	a.UpdatedAt = s.now()
	_, err := s.db.Collection(cApplied).ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.appKey(a.Device, a.Blueprint, a.Item)}}, s.stampDoc(a), options.Replace().SetUpsert(true))
	return err
}

func (s *Store) DeleteApplication(ctx context.Context, device, blueprint, item string) error {
	_, err := s.db.Collection(cApplied).DeleteOne(ctx, bson.D{{Key: "_id", Value: s.appKey(device, blueprint, item)}})
	return err
}

// ApplicationByCommand finds the application a command UUID belongs to.
func (s *Store) ApplicationByCommand(ctx context.Context, uuid string) (*Application, error) {
	var a Application
	err := s.db.Collection(cApplied).FindOne(ctx, s.scope(bson.D{{Key: "command_uuid", Value: uuid}})).Decode(&a)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &a, err
}

// Status counts a blueprint's applications by state.
func (s *Store) Status(ctx context.Context, blueprint string) (map[string]int64, error) {
	cur, err := s.db.Collection(cApplied).Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: s.scope(bson.D{{Key: "blueprint", Value: blueprint}})}},
		{{Key: "$group", Value: bson.D{{Key: "_id", Value: "$state"}, {Key: "n", Value: bson.D{{Key: "$sum", Value: 1}}}}}},
	})
	if err != nil {
		return nil, err
	}
	var rows []struct {
		State string `bson:"_id"`
		N     int64  `bson:"n"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, r := range rows {
		out[r.State] = r.N
	}
	return out, nil
}

// DeliveryCounts counts applications by kind, delivery and state: how much of the fleet's configuration is on declarative management and how much is still on profiles.
func (s *Store) DeliveryCounts(ctx context.Context) ([]map[string]any, error) {
	cur, err := s.db.Collection(cApplied).Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: s.scope(bson.D{})}},
		{{Key: "$group", Value: bson.D{{Key: "_id", Value: bson.D{{Key: "kind", Value: "$kind"}, {Key: "delivery", Value: "$delivery"}, {Key: "state", Value: "$state"}}}, {Key: "n", Value: bson.D{{Key: "$sum", Value: 1}}}}}},
	})
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID struct {
			Kind     string `bson:"kind"`
			Delivery string `bson:"delivery"`
			State    string `bson:"state"`
		} `bson:"_id"`
		N int64 `bson:"n"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		d := r.ID.Delivery
		if d == "" {
			d = "profile"
		}
		out = append(out, map[string]any{"kind": r.ID.Kind, "delivery": d, "state": r.ID.State, "count": r.N})
	}
	return out, nil
}
