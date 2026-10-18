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

// Blob is data a device downloads: a profile for a legacy-profile declaration, or the data behind an asset declaration.
type Blob struct {
	Body        []byte
	ContentType string
}

// PutBlob stores data the device will download, per device, under a key derived from its content.
func (s *Store) PutBlob(ctx context.Context, device, key, contentType string, body []byte) error {
	doc := s.stamp(bson.D{{Key: "device", Value: device}, {Key: "key", Value: key}, {Key: "body", Value: body}, {Key: "content_type", Value: contentType}})
	_, err := s.db.Collection(cProfiles).ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(device, key)}}, doc, options.Replace().SetUpsert(true))
	return err
}

// GetBlob returns stored data of a device; nil if there is none.
func (s *Store) GetBlob(ctx context.Context, device, key string) (*Blob, error) {
	var doc struct {
		Body        []byte `bson:"body"`
		ContentType string `bson:"content_type"`
	}
	err := s.db.Collection(cProfiles).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(device, key)}}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Blob{doc.Body, doc.ContentType}, nil
}

// PutProfile stores a configuration profile the device will download for a legacy-profile declaration.
func (s *Store) PutProfile(ctx context.Context, device, key string, body []byte) error {
	return s.PutBlob(ctx, device, key, "application/x-apple-aspen-config", body)
}

// Profile returns a stored profile of a device; nil if there is none.
func (s *Store) Profile(ctx context.Context, device, key string) ([]byte, error) {
	b, err := s.GetBlob(ctx, device, key)
	if b == nil {
		return nil, err
	}
	return b.Body, err
}

// PruneProfiles deletes a device's stored downloads that are not in keep.
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
