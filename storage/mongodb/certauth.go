package mongodb

import (
	"context"
	"errors"
	"strings"

	"github.com/micromdm/nanomdm/mdm"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func (s *MongoDBStorage) exists(ctx context.Context, filter bson.D) (bool, error) {
	n, err := s.db.Collection(cCertAuth).CountDocuments(ctx, filter, options.Count().SetLimit(1))
	return n > 0, err
}

// EnrollmentHasCertHash reports whether the enrollment has any certificate hash associated.
func (s *MongoDBStorage) EnrollmentHasCertHash(r *mdm.Request, _ string) (bool, error) {
	return s.exists(r.Context(), bson.D{{Key: "id", Value: r.ID}})
}

// HasCertHash reports whether any enrollment has the certificate hash associated.
func (s *MongoDBStorage) HasCertHash(r *mdm.Request, hash string) (bool, error) {
	return s.exists(r.Context(), bson.D{{Key: "sha256", Value: strings.ToLower(hash)}})
}

// IsCertHashAssociated reports whether the hash is associated with this enrollment.
func (s *MongoDBStorage) IsCertHashAssociated(r *mdm.Request, hash string) (bool, error) {
	return s.exists(r.Context(), bson.D{{Key: "id", Value: r.ID}, {Key: "sha256", Value: strings.ToLower(hash)}})
}

// AssociateCertHash associates the hash with the enrollment; doing it again only touches updated_at.
func (s *MongoDBStorage) AssociateCertHash(r *mdm.Request, hash string) error {
	t := now()
	_, err := s.db.Collection(cCertAuth).UpdateOne(r.Context(),
		bson.D{{Key: "id", Value: r.ID}, {Key: "sha256", Value: strings.ToLower(hash)}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "updated_at", Value: t}}}, {Key: "$setOnInsert", Value: bson.D{{Key: "created_at", Value: t}}}},
		options.UpdateOne().SetUpsert(true))
	return err
}

// EnrollmentFromHash returns an enrollment id that has the hash associated ("" when none).
func (s *MongoDBStorage) EnrollmentFromHash(ctx context.Context, hash string) (string, error) {
	var d struct {
		ID string `bson:"id"`
	}
	err := s.db.Collection(cCertAuth).FindOne(ctx, bson.D{{Key: "sha256", Value: hash}}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil
	}
	return d.ID, err
}
