package ddm

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"sort"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const cProfiles = "ddm_profiles"

// PutProfile stores a configuration profile the device will download for a legacy-profile declaration. It is kept per device under a key derived from its content.
func (s *Store) PutProfile(ctx context.Context, device, key string, body []byte) error {
	doc := s.stamp(bson.D{{Key: "device", Value: device}, {Key: "key", Value: key}, {Key: "body", Value: body}})
	_, err := s.db.Collection(cProfiles).ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(device, key)}}, doc, options.Replace().SetUpsert(true))
	return err
}

// Profile returns a stored profile of a device; nil if there is none.
func (s *Store) Profile(ctx context.Context, device, key string) ([]byte, error) {
	var doc struct {
		Body []byte `bson:"body"`
	}
	err := s.db.Collection(cProfiles).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(device, key)}}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return doc.Body, err
}

// PruneProfiles deletes a device's stored profiles that are not in keep.
func (s *Store) PruneProfiles(ctx context.Context, device string, keep []string) error {
	if keep == nil {
		keep = []string{}
	}
	_, err := s.db.Collection(cProfiles).DeleteMany(ctx, s.scope(bson.D{{Key: "device", Value: device}, {Key: "key", Value: bson.D{{Key: "$nin", Value: keep}}}}))
	return err
}

//go:embed equivalents.json
var equivalentsJSON []byte

// Equivalents maps a configuration profile payload type to the declarative configuration (or asset) types that do the same job natively. A payload type that is not here has no native
// declaration yet; a profile that uses it is delivered as a legacy-profile declaration, which is Apple's route for exactly that.
func Equivalents() map[string][]string {
	m := map[string][]string{}
	_ = json.Unmarshal(equivalentsJSON, &m)
	return m
}

// EquivalentTypes returns the sorted list of profile payload types that have a native declaration.
func EquivalentTypes() []string {
	m := Equivalents()
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
