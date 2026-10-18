package mongodb

import (
	"context"
	"strconv"

	"github.com/micromdm/nanomdm/cryptoutil"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// RetrievePushCert returns the push certificate and key for the topic, and its stale token.
func (s *MongoDBStorage) RetrievePushCert(ctx context.Context, topic string) ([]byte, []byte, string, error) {
	var d struct {
		Cert  string `bson:"cert_pem"`
		Key   string `bson:"key_pem"`
		Stale int    `bson:"stale_token"`
	}
	if err := s.db.Collection(cPushCerts).FindOne(ctx, bson.D{{Key: "_id", Value: s.pk(topic)}}).Decode(&d); err != nil {
		return nil, nil, "", err
	}
	key, err := s.open("mdm.pushkey", d.Key)
	if err != nil {
		return nil, nil, "", err
	}
	return []byte(d.Cert), key, strconv.Itoa(d.Stale), nil
}

// IsPushCertStale reports whether the push certificate was replaced since staleToken was handed out.
func (s *MongoDBStorage) IsPushCertStale(ctx context.Context, topic, staleToken string) (bool, error) {
	have, err := strconv.Atoi(staleToken)
	if err != nil {
		return true, err
	}
	var d struct {
		Stale int `bson:"stale_token"`
	}
	err = s.db.Collection(cPushCerts).FindOne(ctx, bson.D{{Key: "_id", Value: s.pk(topic)}}, options.FindOne().SetProjection(bson.D{{Key: "stale_token", Value: 1}})).Decode(&d)
	if err != nil {
		return true, err
	}
	return d.Stale != have, nil
}

// StorePushCert stores (or replaces) a push certificate and key; replacing bumps the stale token so push services reload it.
func (s *MongoDBStorage) StorePushCert(ctx context.Context, pemCert, pemKey []byte) error {
	topic, err := cryptoutil.TopicFromPEMCert(pemCert)
	if err != nil {
		return err
	}
	sealedKey, err := s.seal("mdm.pushkey", pemKey)
	if err != nil {
		return err
	}
	_, err = s.db.Collection(cPushCerts).UpdateOne(ctx, bson.D{{Key: "_id", Value: s.pk(topic)}},
		mongo.Pipeline{{{Key: "$set", Value: s.stampSet(bson.D{
			{Key: "topic", Value: lit(topic)}, {Key: "cert_pem", Value: lit(string(pemCert))}, {Key: "key_pem", Value: lit(sealedKey)},
			{Key: "stale_token", Value: bson.D{{Key: "$cond", Value: bson.A{bson.D{{Key: "$eq", Value: bson.A{bson.D{{Key: "$type", Value: "$stale_token"}}, "missing"}}}, 0, bson.D{{Key: "$add", Value: bson.A{"$stale_token", 1}}}}}}},
			{Key: "created_at", Value: bson.D{{Key: "$ifNull", Value: bson.A{"$created_at", "$$NOW"}}}},
			{Key: "updated_at", Value: "$$NOW"},
		})}}},
		options.UpdateOne().SetUpsert(true))
	return err
}
