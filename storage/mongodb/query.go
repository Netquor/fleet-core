package mongodb

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Listing is for management APIs: enrollments, the command queue and command history, in pages. A page ends with a cursor that gives the next page; a cursor is opaque, stays valid while
// data is added, and never skips or repeats a row. Nothing here returns a command's contents unless asked.

// Page is how much to return and where to continue.
type Page struct {
	// After is the cursor of the previous page; empty for the first.
	After string
	// Limit is the page size (default 100, at most 1000).
	Limit int
}

func (p Page) limit() int64 {
	switch {
	case p.Limit <= 0:
		return 100
	case p.Limit > 1000:
		return 1000
	}
	return int64(p.Limit)
}

// EnrollmentFilter selects enrollments. Zero values select everything.
type EnrollmentFilter struct {
	DeviceID string
	// Type is the enrollment type: Device, User, User Enrollment (Device), User Enrollment, Shared iPad.
	Type    string
	Enabled *bool
}

// Enrollment is one enrolled channel (a device, a user channel of a device, or a User Enrollment).
type Enrollment struct {
	ID         string    `bson:"id" json:"id"`
	DeviceID   string    `bson:"device_id" json:"device_id"`
	UserID     string    `bson:"user_id" json:"user_id,omitempty"`
	Type       string    `bson:"type" json:"type"`
	Topic      string    `bson:"topic" json:"topic"`
	Enabled    bool      `bson:"enabled" json:"enabled"`
	LastSeenAt time.Time `bson:"last_seen_at" json:"last_seen_at"`
	EnrolledAt time.Time `bson:"created_at" json:"enrolled_at"`
}

var enrollmentProjection = bson.D{{Key: "id", Value: 1}, {Key: "device_id", Value: 1}, {Key: "user_id", Value: 1}, {Key: "type", Value: 1}, {Key: "topic", Value: 1}, {Key: "enabled", Value: 1}, {Key: "last_seen_at", Value: 1}, {Key: "created_at", Value: 1}}

// ListEnrollments returns a page of enrollments ordered by ID, and the cursor of the next page (empty at the end).
func (s *MongoDBStorage) ListEnrollments(ctx context.Context, f EnrollmentFilter, p Page) ([]Enrollment, string, error) {
	filter := bson.D{}
	if f.DeviceID != "" {
		filter = append(filter, bson.E{Key: "device_id", Value: f.DeviceID})
	}
	if f.Type != "" {
		filter = append(filter, bson.E{Key: "type", Value: f.Type})
	}
	if f.Enabled != nil {
		filter = append(filter, bson.E{Key: "enabled", Value: *f.Enabled})
	}
	if p.After != "" {
		after, err := decodeCursor(p.After)
		if err != nil {
			return nil, "", err
		}
		filter = append(filter, bson.E{Key: "id", Value: bson.D{{Key: "$gt", Value: after}}})
	}
	cur, err := s.db.Collection(cEnrollments).Find(ctx, s.scope(filter), options.Find().SetSort(bson.D{{Key: "id", Value: 1}}).SetLimit(p.limit()).SetProjection(enrollmentProjection))
	if err != nil {
		return nil, "", err
	}
	var rows []Enrollment
	if err := cur.All(ctx, &rows); err != nil {
		return nil, "", err
	}
	next := ""
	if int64(len(rows)) == p.limit() {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	return rows, next, nil
}

// GetEnrollment returns one enrollment; nil if there is none.
func (s *MongoDBStorage) GetEnrollment(ctx context.Context, id string) (*Enrollment, error) {
	var e Enrollment
	err := s.db.Collection(cEnrollments).FindOne(ctx, bson.D{{Key: "_id", Value: s.pk(id)}}, options.FindOne().SetProjection(enrollmentProjection)).Decode(&e)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &e, err
}

// QueueFilter selects queue entries (a command for an enrollment).
type QueueFilter struct {
	// ID is the enrollment; empty for all.
	ID          string
	CommandUUID string
	// Status: pending (no answer yet), acknowledged, error, notnow, or empty for every status.
	Status      string
	RequestType string
}

// QueueEntry is one command queued for one enrollment, with how it went.
type QueueEntry struct {
	ID          string     `json:"id"`
	CommandUUID string     `json:"command_uuid"`
	RequestType string     `json:"request_type,omitempty"`
	Status      string     `json:"status"`
	Active      bool       `json:"active"`
	Priority    int        `json:"priority"`
	QueuedAt    time.Time  `json:"queued_at"`
	ResultAt    *time.Time `json:"result_at,omitempty"`
	NotNowTally int        `json:"not_now_tally,omitempty"`
}

func statusFilter(status string) (any, bool) {
	switch strings.ToLower(status) {
	case "":
		return nil, false
	case "pending", "queued":
		return nil, true
	case "acknowledged":
		return "Acknowledged", true
	case "error":
		return bson.D{{Key: "$in", Value: bson.A{"Error", "CommandFormatError"}}}, true
	case "notnow":
		return "NotNow", true
	}
	return "\x00no such status", true
}

// ListQueue returns a page of queue entries in the order they were queued, and the next cursor.
func (s *MongoDBStorage) ListQueue(ctx context.Context, f QueueFilter, p Page) ([]QueueEntry, string, error) {
	filter := bson.D{}
	if f.ID != "" {
		filter = append(filter, bson.E{Key: "id", Value: f.ID})
	}
	if f.CommandUUID != "" {
		filter = append(filter, bson.E{Key: "command_uuid", Value: f.CommandUUID})
	}
	if v, ok := statusFilter(f.Status); ok {
		filter = append(filter, bson.E{Key: "status", Value: v})
	}
	if f.RequestType != "" {
		// the type lives on the command: find the commands of that type, then their queue entries
		uuids, err := s.commandUUIDsOfType(ctx, f.RequestType)
		if err != nil {
			return nil, "", err
		}
		filter = append(filter, bson.E{Key: "command_uuid", Value: bson.D{{Key: "$in", Value: uuids}}})
	}
	if p.After != "" {
		raw, err := decodeCursor(p.After)
		if err != nil {
			return nil, "", err
		}
		oid, err := bson.ObjectIDFromHex(raw)
		if err != nil {
			return nil, "", errors.New("bad cursor")
		}
		filter = append(filter, bson.E{Key: "_id", Value: bson.D{{Key: "$gt", Value: oid}}})
	}
	cur, err := s.db.Collection(cQueue).Find(ctx, s.scope(filter), options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}).SetLimit(p.limit()))
	if err != nil {
		return nil, "", err
	}
	var docs []struct {
		OID       bson.ObjectID `bson:"_id"`
		ID        string        `bson:"id"`
		UUID      string        `bson:"command_uuid"`
		Status    *string       `bson:"status"`
		Active    bool          `bson:"active"`
		Priority  int           `bson:"priority"`
		CreatedAt time.Time     `bson:"created_at"`
		ResultAt  time.Time     `bson:"result_at"`
		Tally     int           `bson:"not_now_tally"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		return nil, "", err
	}
	uuids := make([]string, len(docs))
	for i, d := range docs {
		uuids[i] = d.UUID
	}
	types, err := s.requestTypes(ctx, uuids)
	if err != nil {
		return nil, "", err
	}
	out := make([]QueueEntry, len(docs))
	for i, d := range docs {
		e := QueueEntry{ID: d.ID, CommandUUID: d.UUID, RequestType: types[d.UUID], Status: "Queued", Active: d.Active, Priority: d.Priority, QueuedAt: d.CreatedAt, NotNowTally: d.Tally}
		if d.Status != nil {
			e.Status = *d.Status
		}
		if !d.ResultAt.IsZero() {
			t := d.ResultAt
			e.ResultAt = &t
		}
		out[i] = e
	}
	next := ""
	if int64(len(docs)) == p.limit() {
		next = encodeCursor(docs[len(docs)-1].OID.Hex())
	}
	return out, next, nil
}

func (s *MongoDBStorage) commandUUIDsOfType(ctx context.Context, requestType string) ([]string, error) {
	cur, err := s.db.Collection(cCommands).Find(ctx, s.scope(bson.D{{Key: "request_type", Value: requestType}}), options.Find().SetProjection(bson.D{{Key: "command_uuid", Value: 1}}).SetLimit(50000))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		UUID string `bson:"command_uuid"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.UUID
	}
	return out, nil
}

func (s *MongoDBStorage) requestTypes(ctx context.Context, uuids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(uuids) == 0 {
		return out, nil
	}
	keys := make(bson.A, len(uuids))
	for i, u := range uuids {
		keys[i] = s.pk(u)
	}
	cur, err := s.db.Collection(cCommands).Find(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: keys}}}}, options.Find().SetProjection(bson.D{{Key: "command_uuid", Value: 1}, {Key: "request_type", Value: 1}}))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		UUID string `bson:"command_uuid"`
		Type string `bson:"request_type"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.UUID] = r.Type
	}
	return out, nil
}

// CommandInfo is a command in the history.
type CommandInfo struct {
	CommandUUID string    `json:"command_uuid"`
	RequestType string    `json:"request_type"`
	CreatedAt   time.Time `json:"created_at"`
	// Command is the command as JSON, when asked for.
	Command map[string]any `json:"command,omitempty"`
}

// ListCommands returns a page of commands, newest first. With contents the command is included as JSON (opened, if sealed).
func (s *MongoDBStorage) ListCommands(ctx context.Context, requestType string, contents bool, p Page) ([]CommandInfo, string, error) {
	filter := bson.D{}
	if requestType != "" {
		filter = append(filter, bson.E{Key: "request_type", Value: requestType})
	}
	if p.After != "" {
		raw, err := decodeCursor(p.After)
		if err != nil {
			return nil, "", err
		}
		parts := strings.SplitN(raw, "|", 2)
		if len(parts) != 2 {
			return nil, "", errors.New("bad cursor")
		}
		ts, err := time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			return nil, "", errors.New("bad cursor")
		}
		filter = append(filter, bson.E{Key: "$or", Value: bson.A{
			bson.D{{Key: "created_at", Value: bson.D{{Key: "$lt", Value: ts}}}},
			bson.D{{Key: "created_at", Value: ts}, {Key: "_id", Value: bson.D{{Key: "$lt", Value: parts[1]}}}},
		}})
	}
	proj := bson.D{{Key: "command_uuid", Value: 1}, {Key: "request_type", Value: 1}, {Key: "created_at", Value: 1}}
	if contents {
		proj = append(proj, bson.E{Key: "command", Value: 1})
	}
	cur, err := s.db.Collection(cCommands).Find(ctx, s.scope(filter), options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}).SetLimit(p.limit()).SetProjection(proj))
	if err != nil {
		return nil, "", err
	}
	var rows []struct {
		ID      string    `bson:"_id"`
		UUID    string    `bson:"command_uuid"`
		Type    string    `bson:"request_type"`
		Created time.Time `bson:"created_at"`
		Command string    `bson:"command"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, "", err
	}
	out := make([]CommandInfo, len(rows))
	for i, r := range rows {
		out[i] = CommandInfo{CommandUUID: r.UUID, RequestType: r.Type, CreatedAt: r.Created}
		if contents && r.Command != "" {
			raw, err := s.open("mdm.command", r.Command)
			if err != nil {
				return nil, "", err
			}
			if d, ok := plistDoc(raw).(bson.M); ok {
				out[i].Command, _ = jsonSafe(d).(map[string]any)
			}
		}
	}
	next := ""
	if int64(len(rows)) == p.limit() {
		last := rows[len(rows)-1]
		next = encodeCursor(last.Created.UTC().Format(time.RFC3339Nano) + "|" + last.ID)
	}
	return out, next, nil
}

func encodeCursor(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func decodeCursor(c string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", errors.New("bad cursor")
	}
	return string(b), nil
}
