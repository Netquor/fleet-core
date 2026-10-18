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
	rawCmd, err := s.seal("mdm.command", cmd.Raw)
	if err != nil {
		return nil, err
	}
	return nil, s.inTx(ctx, func(ctx context.Context) error {
		if _, err := s.db.Collection(cCommands).InsertOne(ctx, s.stamp(bson.D{
			{Key: "_id", Value: s.pk(cmd.CommandUUID)}, {Key: "command_uuid", Value: cmd.CommandUUID},
			{Key: "request_type", Value: cmd.Command.RequestType}, {Key: "command", Value: rawCmd}, {Key: "command_doc", Value: s.doc(cmd.Raw)},
			{Key: "created_at", Value: t}, {Key: "updated_at", Value: t},
		})); err != nil {
			return err
		}
		docs := make([]any, len(ids))
		for i, id := range ids {
			docs[i] = s.stamp(bson.D{{Key: "id", Value: id}, {Key: "command_uuid", Value: cmd.CommandUUID}, {Key: "active", Value: true}, {Key: "status", Value: nil}, {Key: "priority", Value: 0},
				{Key: "created_at", Value: t}, {Key: "updated_at", Value: t}})
		}
		_, err := s.db.Collection(cQueue).InsertMany(ctx, docs)
		return err
	})
}

// deleteCommand removes an enrollment's queue entry and result for a command, and the command itself once nothing else refers to it.
func (s *MongoDBStorage) deleteCommand(ctx context.Context, id, uuid string) error {
	key := s.scope(bson.D{{Key: "id", Value: id}, {Key: "command_uuid", Value: uuid}})
	if _, err := s.db.Collection(cQueue).DeleteOne(ctx, key); err != nil {
		return err
	}
	only := s.scope(bson.D{{Key: "command_uuid", Value: uuid}})
	q, err := s.db.Collection(cQueue).CountDocuments(ctx, only, options.Count().SetLimit(1))
	if err != nil || q > 0 {
		return err
	}
	_, err = s.db.Collection(cCommands).DeleteOne(ctx, bson.D{{Key: "_id", Value: s.pk(uuid)}})
	return err
}

// StoreCommandReport stores an enrollment's report of a command (or notes an Idle check-in). The result lives in the command's queue entry for that enrollment (they are one to one),
// so an acknowledgement is a single write and finding the next command needs no join. Reporting a command that was never queued for the enrollment is an error, as the SQL backends' foreign keys make it.
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
	// Like the SQL "ON CONFLICT ... DO UPDATE": a NotNow starts (or adds to) the NotNow tally; not_now_at is set by the first NotNow and kept.
	tally := bson.D{{Key: "$ifNull", Value: bson.A{"$not_now_tally", 0}}}
	var newTally any = tally
	notNowAt := any(bson.D{{Key: "$ifNull", Value: bson.A{"$not_now_at", nil}}})
	if result.Status == "NotNow" {
		notNowAt = bson.D{{Key: "$ifNull", Value: bson.A{"$not_now_at", "$$NOW"}}}
		newTally = bson.D{{Key: "$add", Value: bson.A{tally, 1}}}
	}
	rawResult, err := s.seal("mdm.result", result.Raw)
	if err != nil {
		return err
	}
	res, err := s.db.Collection(cQueue).UpdateOne(r.Context(),
		s.scope(bson.D{{Key: "id", Value: r.ID}, {Key: "command_uuid", Value: result.CommandUUID}}),
		mongo.Pipeline{{{Key: "$set", Value: bson.D{
			{Key: "status", Value: lit(result.Status)},
			{Key: "result", Value: lit(rawResult)},
			{Key: "result_doc", Value: lit(s.doc(result.Raw))},
			{Key: "not_now_at", Value: notNowAt},
			{Key: "not_now_tally", Value: newTally},
			{Key: "result_at", Value: "$$NOW"},
			{Key: "updated_at", Value: "$$NOW"},
		}}}})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return fmt.Errorf("no command %s queued for %s", result.CommandUUID, r.ID)
	}
	return nil
}

// RetrieveNextCommand returns the next command for the enrollment that has no result yet (and, unless skipNotNow, one that has only been told NotNow), by priority then age.
func (s *MongoDBStorage) RetrieveNextCommand(r *mdm.Request, skipNotNow bool) (*mdm.Command, error) {
	statuses := bson.A{nil}
	if !skipNotNow {
		statuses = bson.A{nil, "NotNow"}
	}
	var q struct {
		UUID string `bson:"command_uuid"`
	}
	err := s.db.Collection(cQueue).FindOne(r.Context(),
		s.scope(bson.D{{Key: "id", Value: r.ID}, {Key: "active", Value: true}, {Key: "status", Value: bson.D{{Key: "$in", Value: statuses}}}}),
		options.FindOne().SetSort(bson.D{{Key: "priority", Value: -1}, {Key: "created_at", Value: 1}}).SetProjection(bson.D{{Key: "command_uuid", Value: 1}})).Decode(&q)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c struct {
		Type    string `bson:"request_type"`
		Command string `bson:"command"`
	}
	err = s.db.Collection(cCommands).FindOne(r.Context(), bson.D{{Key: "_id", Value: s.pk(q.UUID)}}, options.FindOne().SetProjection(bson.D{{Key: "request_type", Value: 1}, {Key: "command", Value: 1}})).Decode(&c)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil // the command was deleted from under its queue entry
	}
	if err != nil {
		return nil, err
	}
	raw, err := s.open("mdm.command", c.Command)
	if err != nil {
		return nil, err
	}
	command := new(mdm.Command)
	command.CommandUUID, command.Command.RequestType, command.Raw = q.UUID, c.Type, raw
	return command, nil
}

// ClearQueue deactivates the commands still waiting (no result, or NotNow) for a device channel and all its user channels.
func (s *MongoDBStorage) ClearQueue(r *mdm.Request) error {
	if r.ParentID != "" {
		return errors.New("can only clear a device channel queue")
	}
	ctx := r.Context()
	var enrollments []string
	if err := s.db.Collection(cEnrollments).Distinct(ctx, "id", s.scope(bson.D{{Key: "device_id", Value: r.ID}})).Decode(&enrollments); err != nil {
		return fmt.Errorf("enrollment ids: %w", err)
	}
	if len(enrollments) == 0 {
		return nil
	}
	_, err := s.db.Collection(cQueue).UpdateMany(ctx,
		s.scope(bson.D{{Key: "id", Value: bson.D{{Key: "$in", Value: enrollments}}}, {Key: "active", Value: true}, {Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{nil, "NotNow"}}}}}),
		bson.D{{Key: "$set", Value: bson.D{{Key: "active", Value: false}, {Key: "updated_at", Value: now()}}}})
	return err
}
