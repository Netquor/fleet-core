package mongodb

import (
	"context"
	"errors"
	"fmt"

	"github.com/micromdm/nanomdm/mdm"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// inTx runs fn in a transaction (MongoDB needs a replica set for this).
func (s *MongoDBStorage) inTx(ctx context.Context, fn func(ctx context.Context) error) error {
	sess, err := s.client.StartSession()
	if err != nil {
		return err
	}
	defer sess.EndSession(ctx)
	_, err = sess.WithTransaction(ctx, func(sc context.Context) (any, error) { return nil, fn(sc) })
	return err
}

// EnqueueCommand queues cmd for every id. The command and its queue entries are written together or not at all.
func (s *MongoDBStorage) EnqueueCommand(ctx context.Context, ids []string, cmd *mdm.Command) (map[string]error, error) {
	if len(ids) < 1 {
		return nil, errors.New("no id(s) supplied to queue command to")
	}
	t := now()
	return nil, s.inTx(ctx, func(ctx context.Context) error {
		if _, err := s.db.Collection(cCommands).InsertOne(ctx, bson.D{
			{Key: "_id", Value: cmd.CommandUUID}, {Key: "command_uuid", Value: cmd.CommandUUID},
			{Key: "request_type", Value: cmd.Command.RequestType}, {Key: "command", Value: string(cmd.Raw)},
			{Key: "created_at", Value: t}, {Key: "updated_at", Value: t},
		}); err != nil {
			return err
		}
		docs := make([]any, len(ids))
		for i, id := range ids {
			docs[i] = bson.D{{Key: "id", Value: id}, {Key: "command_uuid", Value: cmd.CommandUUID}, {Key: "active", Value: true}, {Key: "priority", Value: 0},
				{Key: "created_at", Value: t}, {Key: "updated_at", Value: t}}
		}
		_, err := s.db.Collection(cQueue).InsertMany(ctx, docs)
		return err
	})
}

// deleteCommand removes an enrollment's queue entry and result for a command, and the command itself once nothing else refers to it.
func (s *MongoDBStorage) deleteCommand(ctx context.Context, id, uuid string) error {
	key := bson.D{{Key: "id", Value: id}, {Key: "command_uuid", Value: uuid}}
	if _, err := s.db.Collection(cQueue).DeleteOne(ctx, key); err != nil {
		return err
	}
	// delete the command result (i.e. NotNows) and this queued command
	if _, err := s.db.Collection(cResults).DeleteOne(ctx, key); err != nil {
		return err
	}
	only := bson.D{{Key: "command_uuid", Value: uuid}}
	q, err := s.db.Collection(cQueue).CountDocuments(ctx, only, options.Count().SetLimit(1))
	if err != nil || q > 0 {
		return err
	}
	r, err := s.db.Collection(cResults).CountDocuments(ctx, only, options.Count().SetLimit(1))
	if err != nil || r > 0 {
		return err
	}
	_, err = s.db.Collection(cCommands).DeleteOne(ctx, bson.D{{Key: "_id", Value: uuid}})
	return err
}

// StoreCommandReport stores an enrollment's report of a command (or notes an Idle check-in).
func (s *MongoDBStorage) StoreCommandReport(r *mdm.Request, result *mdm.CommandResults) error {
	if err := s.updateLastSeen(r); err != nil {
		return err
	}
	if result.Status == "Idle" {
		return nil
	}
	if s.rm && result.Status != "NotNow" {
		return s.inTx(r.Context(), func(ctx context.Context) error { return s.deleteCommand(ctx, r.ID, result.CommandUUID) })
	}
	notNow := result.Status == "NotNow"
	// Like the SQL "ON CONFLICT ... DO UPDATE": a new result starts its NotNow tally at 1 (NotNow) or 0, and each later NotNow adds one.
	// not_now_at is set by the first NotNow and kept.
	setNotNowAt := any("$not_now_at")
	tally := bson.D{{Key: "$ifNull", Value: bson.A{"$not_now_tally", 0}}}
	var newTally any = tally
	if notNow {
		setNotNowAt = bson.D{{Key: "$ifNull", Value: bson.A{"$not_now_at", "$$NOW"}}}
		newTally = bson.D{{Key: "$add", Value: bson.A{tally, 1}}}
	} else {
		setNotNowAt = bson.D{{Key: "$ifNull", Value: bson.A{"$not_now_at", nil}}}
	}
	_, err := s.db.Collection(cResults).UpdateOne(r.Context(),
		bson.D{{Key: "id", Value: r.ID}, {Key: "command_uuid", Value: result.CommandUUID}},
		mongo.Pipeline{{{Key: "$set", Value: bson.D{
			{Key: "status", Value: result.Status},
			{Key: "result", Value: string(result.Raw)},
			{Key: "not_now_at", Value: setNotNowAt},
			{Key: "not_now_tally", Value: newTally},
			{Key: "created_at", Value: bson.D{{Key: "$ifNull", Value: bson.A{"$created_at", "$$NOW"}}}},
			{Key: "updated_at", Value: "$$NOW"},
		}}}},
		options.UpdateOne().SetUpsert(true))
	return err
}

// RetrieveNextCommand returns the next command for the enrollment that has no result yet (and, unless skipNotNow, one that has only been told NotNow), by priority then age.
func (s *MongoDBStorage) RetrieveNextCommand(r *mdm.Request, skipNotNow bool) (*mdm.Command, error) {
	statuses := bson.A{nil}
	if !skipNotNow {
		statuses = bson.A{nil, "NotNow"}
	}
	cur, err := s.db.Collection(cQueue).Aggregate(r.Context(), mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "id", Value: r.ID}, {Key: "active", Value: true}}}},
		{{Key: "$sort", Value: bson.D{{Key: "priority", Value: -1}, {Key: "created_at", Value: 1}}}},
		// The result for this enrollment and command, if any: a left join.
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: cResults}, {Key: "let", Value: bson.D{{Key: "u", Value: "$command_uuid"}, {Key: "e", Value: "$id"}}},
			{Key: "pipeline", Value: mongo.Pipeline{{{Key: "$match", Value: bson.D{{Key: "$expr", Value: bson.D{{Key: "$and", Value: bson.A{
				bson.D{{Key: "$eq", Value: bson.A{"$command_uuid", "$$u"}}}, bson.D{{Key: "$eq", Value: bson.A{"$id", "$$e"}}}}}}}}}}, {{Key: "$project", Value: bson.D{{Key: "status", Value: 1}}}}}},
			{Key: "as", Value: "r"},
		}}},
		{{Key: "$set", Value: bson.D{{Key: "status", Value: bson.D{{Key: "$arrayElemAt", Value: bson.A{"$r.status", 0}}}}}}},
		{{Key: "$match", Value: bson.D{{Key: "status", Value: bson.D{{Key: "$in", Value: statuses}}}}}},
		{{Key: "$limit", Value: 1}},
		{{Key: "$lookup", Value: bson.D{{Key: "from", Value: cCommands}, {Key: "localField", Value: "command_uuid"}, {Key: "foreignField", Value: "_id"}, {Key: "as", Value: "c"}}}},
		{{Key: "$unwind", Value: "$c"}},
		{{Key: "$project", Value: bson.D{{Key: "command_uuid", Value: 1}, {Key: "request_type", Value: "$c.request_type"}, {Key: "command", Value: "$c.command"}}}},
	})
	if err != nil {
		return nil, err
	}
	defer cur.Close(r.Context())
	if !cur.Next(r.Context()) {
		return nil, cur.Err()
	}
	var doc struct {
		UUID    string `bson:"command_uuid"`
		Type    string `bson:"request_type"`
		Command string `bson:"command"`
	}
	if err := cur.Decode(&doc); err != nil {
		return nil, err
	}
	command := new(mdm.Command)
	command.CommandUUID, command.Command.RequestType, command.Raw = doc.UUID, doc.Type, []byte(doc.Command)
	return command, nil
}

// ClearQueue deactivates the commands still waiting (no result, or NotNow) for a device channel and all its user channels.
func (s *MongoDBStorage) ClearQueue(r *mdm.Request) error {
	if r.ParentID != "" {
		return errors.New("can only clear a device channel queue")
	}
	ctx := r.Context()
	var enrollments []string
	if err := s.db.Collection(cEnrollments).Distinct(ctx, "_id", bson.D{{Key: "device_id", Value: r.ID}}).Decode(&enrollments); err != nil {
		return fmt.Errorf("enrollment ids: %w", err)
	}
	if len(enrollments) == 0 {
		return nil
	}
	cur, err := s.db.Collection(cQueue).Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "id", Value: bson.D{{Key: "$in", Value: enrollments}}}, {Key: "active", Value: true}}}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: cResults}, {Key: "let", Value: bson.D{{Key: "u", Value: "$command_uuid"}, {Key: "e", Value: "$id"}}},
			{Key: "pipeline", Value: mongo.Pipeline{{{Key: "$match", Value: bson.D{{Key: "$expr", Value: bson.D{{Key: "$and", Value: bson.A{
				bson.D{{Key: "$eq", Value: bson.A{"$command_uuid", "$$u"}}}, bson.D{{Key: "$eq", Value: bson.A{"$id", "$$e"}}}}}}}}}}, {{Key: "$project", Value: bson.D{{Key: "status", Value: 1}}}}}},
			{Key: "as", Value: "r"},
		}}},
		{{Key: "$set", Value: bson.D{{Key: "status", Value: bson.D{{Key: "$arrayElemAt", Value: bson.A{"$r.status", 0}}}}}}},
		{{Key: "$match", Value: bson.D{{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{nil, "NotNow"}}}}}}},
		{{Key: "$project", Value: bson.D{{Key: "_id", Value: 1}}}},
	})
	if err != nil {
		return err
	}
	var queued []struct {
		ID bson.ObjectID `bson:"_id"`
	}
	if err := cur.All(ctx, &queued); err != nil {
		return err
	}
	if len(queued) == 0 {
		return nil
	}
	oids := make([]bson.ObjectID, len(queued))
	for i, q := range queued {
		oids[i] = q.ID
	}
	_, err = s.db.Collection(cQueue).UpdateMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: oids}}}}, bson.D{{Key: "$set", Value: bson.D{{Key: "active", Value: false}, {Key: "updated_at", Value: now()}}}})
	return err
}
