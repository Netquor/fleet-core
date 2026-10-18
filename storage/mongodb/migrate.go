package mongodb

import (
	"context"

	"github.com/micromdm/nanomdm/mdm"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// RetrieveMigrationCheckins sends each device's last Authenticate and TokenUpdate, and each user's last TokenUpdate, down c.
func (s *MongoDBStorage) RetrieveMigrationCheckins(ctx context.Context, c chan<- interface{}) error {
	send := func(raw string) {
		msg, err := mdm.DecodeCheckin([]byte(raw))
		if err != nil {
			c <- err
		} else {
			c <- msg
		}
	}
	// TODO: if a TokenUpdate does not include the latest UnlockToken then we should synthesize a TokenUpdate to transfer it over.
	devices, err := s.db.Collection(cDevices).Find(ctx, s.scope(bson.D{}), options.Find().SetProjection(bson.D{{Key: "authenticate", Value: 1}, {Key: "token_update", Value: 1}}))
	if err != nil {
		return err
	}
	defer devices.Close(ctx)
	for devices.Next(ctx) {
		var d struct {
			Auth  string `bson:"authenticate"`
			Token string `bson:"token_update"`
		}
		if err := devices.Decode(&d); err != nil {
			return err
		}
		tok, err := s.open("mdm.token_update", d.Token)
		if err != nil {
			return err
		}
		send(d.Auth)
		send(string(tok))
	}
	if err := devices.Err(); err != nil {
		return err
	}
	users, err := s.db.Collection(cUsers).Find(ctx, s.scope(bson.D{}), options.Find().SetProjection(bson.D{{Key: "token_update", Value: 1}}))
	if err != nil {
		return err
	}
	defer users.Close(ctx)
	for users.Next(ctx) {
		var u struct {
			Token string `bson:"token_update"`
		}
		if err := users.Decode(&u); err != nil {
			return err
		}
		tok, err := s.open("mdm.token_update", u.Token)
		if err != nil {
			return err
		}
		send(string(tok))
	}
	return users.Err()
}
