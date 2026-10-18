package bad

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type S struct{ db *mongo.Database }

func (s *S) scope(f bson.D) bson.D { return f }
func (s *S) stamp(d bson.D) bson.D { return d }

// scoped: fine
func (s *S) Good(ctx context.Context) {
	f := s.scope(bson.D{{Key: "a", Value: 1}})
	s.db.Collection("x").Find(ctx, f)
	s.db.Collection("x").InsertOne(ctx, s.stamp(bson.D{}))
}

// no tenant in the filter: a leak
func (s *S) Leaky(ctx context.Context) {
	s.db.Collection("x").Find(ctx, bson.D{{Key: "a", Value: 1}})
}

// an unstamped insert: a document no tenant owns
func (s *S) Unstamped(ctx context.Context) {
	s.db.Collection("x").InsertOne(ctx, bson.D{{Key: "a", Value: 1}})
}

// global by design, and says so
func (s *S) Marked(ctx context.Context) {
	// tenant-ok: public data
	s.db.Collection("global").Find(ctx, bson.D{})
}
