package mongodb

import (
	"errors"

	"github.com/micromdm/nanomdm/mdm"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// StoreBootstrapToken stores the device's bootstrap token.
func (s *MongoDBStorage) StoreBootstrapToken(r *mdm.Request, msg *mdm.SetBootstrapToken) error {
	t := now()
	_, err := s.db.Collection(cDevices).UpdateOne(r.Context(), bson.D{{Key: "_id", Value: r.ID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "bootstrap_token_b64", Value: nullEmpty(msg.BootstrapToken.BootstrapToken.String())}, {Key: "bootstrap_token_at", Value: t}, {Key: "updated_at", Value: t}}}})
	if err != nil {
		return err
	}
	return s.updateLastSeen(r)
}

// RetrieveBootstrapToken returns the device's bootstrap token (nil, nil when there is none).
func (s *MongoDBStorage) RetrieveBootstrapToken(r *mdm.Request, _ *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	var d struct {
		Token *string `bson:"bootstrap_token_b64"`
	}
	err := s.db.Collection(cDevices).FindOne(r.Context(), bson.D{{Key: "_id", Value: r.ID}}, options.FindOne().SetProjection(bson.D{{Key: "bootstrap_token_b64", Value: 1}})).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) || (err == nil && d.Token == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bs := new(mdm.BootstrapToken)
	if err = bs.SetTokenString(*d.Token); err == nil {
		err = s.updateLastSeen(r)
	}
	return bs, err
}
