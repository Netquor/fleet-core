package mongodb

import (
	"context"
	"errors"

	"github.com/micromdm/nanomdm/mdm"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// RetrievePushInfo retrieves push info for the enrollment ids. It may return fewer results than ids.
func (s *MongoDBStorage) RetrievePushInfo(ctx context.Context, ids []string) (map[string]*mdm.Push, error) {
	if len(ids) < 1 {
		return nil, errors.New("no ids provided")
	}
	pks := make([]string, len(ids))
	for i, id := range ids {
		pks[i] = s.pk(id)
	}
	cur, err := s.db.Collection(cEnrollments).Find(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: pks}}}},
		options.Find().SetProjection(bson.D{{Key: "id", Value: 1}, {Key: "topic", Value: 1}, {Key: "push_magic", Value: 1}, {Key: "token_hex", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	out := make(map[string]*mdm.Push)
	for cur.Next(ctx) {
		var d struct {
			ID    string `bson:"id"`
			Topic string `bson:"topic"`
			Magic string `bson:"push_magic"`
			Token string `bson:"token_hex"`
		}
		if err := cur.Decode(&d); err != nil {
			return nil, err
		}
		push := &mdm.Push{Topic: d.Topic, PushMagic: d.Magic}
		if err := push.SetTokenString(d.Token); err != nil {
			return nil, err
		}
		out[d.ID] = push
	}
	return out, cur.Err()
}
