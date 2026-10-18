// Package applicability decides what part of a configuration profile a platform can use. The profile that reaches a device has the payloads and settings that platform does not support left out,
// so one profile can be written once and scoped to a mixed fleet (the same job the Fleet console does when it builds a profile).
//
// Two sources are combined:
//
//   - Apple's schemas (fleetcore/schemas): which payload types and which keys exist on which operating system. They follow Apple's releases, so new payloads and keys are understood the day Apple publishes them.
//   - Overrides: data, not code, for what Apple's schemas cannot know, such as a third-party payload type or preference domain (com.google.Chrome is macOS only). They are rows in MongoDB, editable through the API.
//
// A payload type nobody knows is kept: the device ignores what it does not understand, and guessing wrong would silently drop a customer's setting.
package applicability

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"github.com/micromdm/plist"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

//go:embed defaults.json
var defaultsJSON []byte

// Override says on which platforms a payload type or preference domain applies. Match is exact, or a prefix when it ends in *.
type Override struct {
	ID        string   `bson:"id" json:"id"`
	Match     string   `bson:"match" json:"match"`
	Platforms []string `bson:"platforms" json:"platforms"`
	Note      string   `bson:"note,omitempty" json:"note,omitempty"`
}

func (o Override) matches(name string) bool {
	if strings.HasSuffix(o.Match, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(o.Match, "*"))
	}
	return o.Match == name
}

func (o Override) allows(platform string) bool {
	for _, p := range o.Platforms {
		if p == platform || (p == "iOS" && platform == "iPadOS") {
			return true
		}
	}
	return false
}

// Registry holds the overrides and filters profiles with them and the current Apple schemas.
type Registry struct {
	mu    sync.RWMutex
	rules []Override
	coll  *mongo.Collection
	tid   string
}

// NewRegistry loads the overrides from MongoDB (db may be nil: in memory). The first time, the defaults shipped in the binary are saved.
func NewRegistry(ctx context.Context, db *mongo.Database, tenant string) (*Registry, error) {
	r := &Registry{tid: tenant}
	if db == nil {
		var d []Override
		_ = json.Unmarshal(defaultsJSON, &d)
		r.rules = d
		return r, nil
	}
	r.coll = db.Collection("applicability")
	n, err := r.coll.CountDocuments(ctx, r.scope(bson.D{}))
	if err != nil {
		return nil, err
	}
	if n == 0 {
		var d []Override
		_ = json.Unmarshal(defaultsJSON, &d)
		for _, o := range d {
			if err := r.save(ctx, o); err != nil {
				return nil, err
			}
		}
	}
	return r, r.reload(ctx)
}

func (r *Registry) scope(f bson.D) bson.D {
	if r.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: r.tid}}, f...)
}

func (r *Registry) key(id string) string {
	if r.tid == "" {
		return id
	}
	return r.tid + "\x1f" + id
}

func (r *Registry) save(ctx context.Context, o Override) error {
	doc := bson.D{{Key: "id", Value: o.ID}, {Key: "match", Value: o.Match}, {Key: "platforms", Value: o.Platforms}, {Key: "note", Value: o.Note}}
	if r.tid != "" {
		doc = append(bson.D{{Key: "t", Value: r.tid}}, doc...)
	}
	_, err := r.coll.ReplaceOne(ctx, bson.D{{Key: "_id", Value: r.key(o.ID)}}, doc, options.Replace().SetUpsert(true))
	return err
}

func (r *Registry) reload(ctx context.Context) error {
	cur, err := r.coll.Find(ctx, r.scope(bson.D{}), options.Find().SetSort(bson.D{{Key: "match", Value: 1}}))
	if err != nil {
		return err
	}
	var rows []Override
	if err := cur.All(ctx, &rows); err != nil {
		return err
	}
	r.mu.Lock()
	r.rules = rows
	r.mu.Unlock()
	return nil
}

// List returns the overrides.
func (r *Registry) List() []Override {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := append([]Override(nil), r.rules...)
	sort.Slice(out, func(i, j int) bool { return out[i].Match < out[j].Match })
	return out
}

// Put adds or replaces an override.
func (r *Registry) Put(ctx context.Context, o Override) error {
	if o.ID == "" || o.Match == "" || len(o.Platforms) == 0 {
		return errors.New("an override needs an id, a match and at least one platform")
	}
	for _, p := range o.Platforms {
		switch p {
		case "macOS", "iOS", "iPadOS", "tvOS", "visionOS", "watchOS":
		default:
			return fmt.Errorf("unknown platform %q", p)
		}
	}
	if r.coll != nil {
		if err := r.save(ctx, o); err != nil {
			return err
		}
		return r.reload(ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.rules {
		if r.rules[i].ID == o.ID {
			r.rules[i] = o
			return nil
		}
	}
	r.rules = append(r.rules, o)
	return nil
}

// Delete removes an override.
func (r *Registry) Delete(ctx context.Context, id string) error {
	if r.coll != nil {
		if _, err := r.coll.DeleteOne(ctx, bson.D{{Key: "_id", Value: r.key(id)}}); err != nil {
			return err
		}
		return r.reload(ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.rules {
		if r.rules[i].ID == id {
			r.rules = append(r.rules[:i], r.rules[i+1:]...)
		}
	}
	return nil
}

func (r *Registry) override(name string) *Override {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := range r.rules {
		if r.rules[i].matches(name) {
			return &r.rules[i]
		}
	}
	return nil
}

// LeftOut is something removed from a profile for a platform.
type LeftOut struct {
	Payload string `json:"payload"`
	Key     string `json:"key,omitempty"`
	Reason  string `json:"reason"`
}

// Result is a profile adapted to a platform.
type Result struct {
	// Profile is the profile to send; nil when nothing in it applies (NotApplicable).
	Profile       []byte    `json:"-"`
	NotApplicable bool      `json:"not_applicable,omitempty"`
	LeftOut       []LeftOut `json:"left_out,omitempty"`
}

// baseKeys are the keys every payload has; they are never judged.
var baseKeys = map[string]bool{"PayloadType": true, "PayloadVersion": true, "PayloadIdentifier": true, "PayloadUUID": true, "PayloadDisplayName": true, "PayloadDescription": true, "PayloadOrganization": true, "PayloadEnabled": true}

// Apply adapts a .mobileconfig (XML plist) to a platform (macOS, iOS, iPadOS, tvOS, visionOS, watchOS) and, if known, its OS version (payloads and keys Apple removed by then are left out).
// An empty platform returns the profile unchanged.
func (r *Registry) Apply(profile []byte, platform, osVersion string) (Result, error) {
	if platform == "" {
		return Result{Profile: profile}, nil
	}
	var root map[string]any
	if err := plist.Unmarshal(profile, &root); err != nil {
		return Result{}, fmt.Errorf("the profile is not a valid property list: %w", err)
	}
	content, _ := root["PayloadContent"].([]any)
	if len(content) == 0 {
		return Result{Profile: profile}, nil
	}
	set := schemas.Current()
	os := schemas.SchemaOS(platform)
	var res Result
	kept := make([]any, 0, len(content))
	for _, item := range content {
		p, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}
		typ, _ := p["PayloadType"].(string)
		// 1. an override for the payload type
		if o := r.override(typ); o != nil {
			if !o.allows(platform) {
				res.LeftOut = append(res.LeftOut, LeftOut{Payload: typ, Reason: "override " + o.ID + ": not for " + platform})
				continue
			}
		} else if def, ok := set.Profile(typ); ok {
			// 2. Apple's schema for the payload type
			if info, listed := def.OS[os]; listed && info.UnsupportedOn(osVersion) {
				res.LeftOut = append(res.LeftOut, LeftOut{Payload: typ, Reason: typ + " does not exist on " + platform + " " + osVersion})
				continue
			}
			res.LeftOut = append(res.LeftOut, dropKeys(p, typ, def.Keys, os, platform, osVersion)...)
		}
		// 3. preference domains inside a managed-preferences payload
		if typ == "com.apple.ManagedClient.preferences" {
			if domains, ok := p["PayloadContent"].(map[string]any); ok {
				for domain := range domains {
					if o := r.override(domain); o != nil && !o.allows(platform) {
						delete(domains, domain)
						res.LeftOut = append(res.LeftOut, LeftOut{Payload: typ, Key: domain, Reason: "override " + o.ID + ": not for " + platform})
					}
				}
				if len(domains) == 0 {
					continue
				}
			}
		}
		kept = append(kept, p)
	}
	if len(kept) == 0 {
		res.NotApplicable = true
		return res, nil
	}
	if len(res.LeftOut) == 0 {
		res.Profile = profile
		return res, nil
	}
	root["PayloadContent"] = kept
	out, err := plist.MarshalIndent(root, "  ")
	if err != nil {
		return Result{}, err
	}
	res.Profile = out
	return res, nil
}

// dropKeys removes keys the platform does not support from a payload (descending into dictionaries the schema describes).
func dropKeys(p map[string]any, payload string, keys []schemas.Key, os, platform, osVersion string) []LeftOut {
	var out []LeftOut
	byName := make(map[string]*schemas.Key, len(keys))
	for i := range keys {
		byName[keys[i].Key] = &keys[i]
	}
	var walk func(m map[string]any, ks map[string]*schemas.Key, path string)
	walk = func(m map[string]any, ks map[string]*schemas.Key, path string) {
		for name, v := range m {
			if path == "" && baseKeys[name] {
				continue
			}
			k, ok := ks[name]
			if !ok {
				continue
			}
			full := name
			if path != "" {
				full = path + "." + name
			}
			if info, listed := k.OS[os]; listed && info.UnsupportedOn(osVersion) {
				delete(m, name)
				out = append(out, LeftOut{Payload: payload, Key: full, Reason: name + " does not exist on " + platform})
				continue
			}
			if sub, ok := v.(map[string]any); ok && k.Type == "dictionary" && len(k.Keys) > 0 && !k.Recursive {
				inner := make(map[string]*schemas.Key, len(k.Keys))
				for i := range k.Keys {
					inner[k.Keys[i].Key] = &k.Keys[i]
				}
				walk(sub, inner, full)
			}
		}
	}
	walk(p, byName, "")
	return out
}
