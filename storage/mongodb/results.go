package mongodb

import (
	"context"
	"encoding/base64"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// CommandResult is one enrollment's state for a command: queued (no status yet), or what the device answered.
type CommandResult struct {
	ID       string     `json:"id"`
	Status   string     `json:"status"`
	QueuedAt time.Time  `json:"queued_at"`
	ResultAt *time.Time `json:"result_at,omitempty"`
	// Result is the device's response as JSON-safe values (data as base64, dates as RFC 3339), nil until it answers.
	Result map[string]any `json:"result,omitempty"`
}

// CommandResults returns the state of a command for every enrollment it was queued for, so a JSON API can show progress and answers without parsing plists.
// A command removed after completion (WithDeleteCommands) has no results left to show.
func (s *MongoDBStorage) CommandResults(ctx context.Context, commandUUID string) ([]CommandResult, error) {
	cur, err := s.db.Collection(cQueue).Find(ctx, s.scope(bson.D{{Key: "command_uuid", Value: commandUUID}}), options.Find().SetLimit(10000))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID        string    `bson:"id"`
		Status    string    `bson:"status"`
		CreatedAt time.Time `bson:"created_at"`
		ResultAt  time.Time `bson:"result_at"`
		ResultDoc bson.M    `bson:"result_doc"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]CommandResult, 0, len(rows))
	for _, r := range rows {
		cr := CommandResult{ID: r.ID, Status: r.Status, QueuedAt: r.CreatedAt}
		if cr.Status == "" {
			cr.Status = "Queued"
		}
		if !r.ResultAt.IsZero() {
			t := r.ResultAt
			cr.ResultAt = &t
		}
		if r.ResultDoc != nil {
			cr.Result, _ = jsonSafe(r.ResultDoc).(map[string]any)
		}
		out = append(out, cr)
	}
	return out, nil
}

func jsonSafe(v any) any {
	switch t := v.(type) {
	case bson.M:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = jsonSafe(e)
		}
		return m
	case bson.D:
		m := make(map[string]any, len(t))
		for _, e := range t {
			m[e.Key] = jsonSafe(e.Value)
		}
		return m
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = jsonSafe(e)
		}
		return m
	case bson.A:
		a := make([]any, len(t))
		for i, e := range t {
			a[i] = jsonSafe(e)
		}
		return a
	case []any:
		a := make([]any, len(t))
		for i, e := range t {
			a[i] = jsonSafe(e)
		}
		return a
	case bson.Binary:
		return base64.StdEncoding.EncodeToString(t.Data)
	case bson.DateTime:
		return t.Time().UTC().Format(time.RFC3339)
	}
	return v
}
