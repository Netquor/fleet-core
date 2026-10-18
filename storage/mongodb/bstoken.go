package mongodb

import (
	"context"
	"errors"

	"github.com/micromdm/nanomdm/mdm"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// StoreBootstrapToken stores the device's bootstrap token.
func (s *MongoDBStorage) StoreBootstrapToken(r *mdm.Request, msg *mdm.SetBootstrapToken) error {
	t := now()
	var token any = nullEmpty(msg.BootstrapToken.BootstrapToken.String())
	if tok := msg.BootstrapToken.BootstrapToken.String(); tok != "" && s.sealer != nil {
		enc, err := s.seal("mdm.bootstrap", []byte(tok))
		if err != nil {
			return err
		}
		token = enc
	}
	_, err := s.db.Collection(cDevices).UpdateOne(r.Context(), bson.D{{Key: "_id", Value: s.pk(r.ID)}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "bootstrap_token_b64", Value: token}, {Key: "bootstrap_token_at", Value: t}, {Key: "updated_at", Value: t}}}})
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
	err := s.db.Collection(cDevices).FindOne(r.Context(), bson.D{{Key: "_id", Value: s.pk(r.ID)}}, options.FindOne().SetProjection(bson.D{{Key: "bootstrap_token_b64", Value: 1}})).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) || (err == nil && d.Token == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bs := new(mdm.BootstrapToken)
	tok, err := s.open("mdm.bootstrap", *d.Token)
	if err != nil {
		return nil, err
	}
	if err = bs.SetTokenString(string(tok)); err == nil {
		err = s.updateLastSeen(r)
	}
	return bs, err
}

// BootstrapTokenString returns the device's bootstrap token as it is stored for the device (base64); ok is false when there is none.
func (s *MongoDBStorage) BootstrapTokenString(ctx context.Context, id string) (string, bool, error) {
	var d struct {
		Token *string `bson:"bootstrap_token_b64"`
	}
	err := s.db.Collection(cDevices).FindOne(ctx, bson.D{{Key: "_id", Value: s.pk(id)}}, options.FindOne().SetProjection(bson.D{{Key: "bootstrap_token_b64", Value: 1}})).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) || (err == nil && d.Token == nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	tok, err := s.open("mdm.bootstrap", *d.Token)
	return string(tok), err == nil, err
}
