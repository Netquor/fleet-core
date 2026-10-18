package blueprints

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const cExpected = "bp_expected"

// Expected is what an administrator knows about a device before it enrolls (usually from the MDM it is leaving): the name it should have, the static groups and tags it belongs in.
// They are applied the moment a device with that serial number enrolls, and at once to one that already has.
type Expected struct {
	Serial     string    `bson:"serial" json:"serial"`
	Name       string    `bson:"name,omitempty" json:"name,omitempty"`
	User       string    `bson:"user,omitempty" json:"user,omitempty"` // the person it is assigned to (kept as a note; matching a Managed Apple Account is up to rules on managed_apple_id)
	Groups     []string  `bson:"groups,omitempty" json:"groups,omitempty"`
	Tags       []string  `bson:"tags,omitempty" json:"tags,omitempty"`
	Source     string    `bson:"source,omitempty" json:"source,omitempty"`
	ImportedAt time.Time `bson:"imported_at" json:"imported_at"`
}

// PutExpected records or replaces what is expected of a serial number and applies it to a device already enrolled under it.
func (s *Store) PutExpected(ctx context.Context, e Expected) (alreadyEnrolled bool, err error) {
	e.Serial = strings.ToUpper(strings.TrimSpace(e.Serial))
	e.ImportedAt = s.now()
	if _, err = s.db.Collection(cExpected).ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(e.Serial)}}, s.stampDoc(e), options.Replace().SetUpsert(true)); err != nil {
		return false, err
	}
	set := bson.D{}
	if e.Name != "" {
		set = append(set, bson.E{Key: "name", Value: e.Name})
	}
	upd := bson.D{}
	if len(set) > 0 {
		upd = append(upd, bson.E{Key: "$set", Value: append(set, bson.E{Key: "reconcile_at", Value: s.now()})})
	} else {
		upd = append(upd, bson.E{Key: "$set", Value: bson.D{{Key: "reconcile_at", Value: s.now()}}})
	}
	add := bson.D{}
	if len(e.Groups) > 0 {
		add = append(add, bson.E{Key: "groups", Value: bson.D{{Key: "$each", Value: e.Groups}}})
	}
	if len(e.Tags) > 0 {
		add = append(add, bson.E{Key: "tags", Value: bson.D{{Key: "$each", Value: e.Tags}}})
	}
	if len(add) > 0 {
		upd = append(upd, bson.E{Key: "$addToSet", Value: add})
	}
	res, err := s.db.Collection(cDevices).UpdateMany(ctx, s.scope(bson.D{{Key: "serial", Value: e.Serial}}), upd)
	return err == nil && res.MatchedCount > 0, err
}

// ExpectedFor returns what is expected of a serial; nil if nothing.
func (s *Store) ExpectedFor(ctx context.Context, serial string) (*Expected, error) {
	var e Expected
	err := s.db.Collection(cExpected).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(strings.ToUpper(serial))}}).Decode(&e)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &e, err
}

// ListExpected pages through the imported records by serial.
func (s *Store) ListExpected(ctx context.Context, after string, limit int) ([]Expected, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	cur, err := s.db.Collection(cExpected).Find(ctx, s.scope(bson.D{{Key: "serial", Value: bson.D{{Key: "$gt", Value: after}}}}), options.Find().SetSort(bson.D{{Key: "serial", Value: 1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	var out []Expected
	return out, cur.All(ctx, &out)
}

// DeleteExpected forgets a record.
func (s *Store) DeleteExpected(ctx context.Context, serial string) error {
	_, err := s.db.Collection(cExpected).DeleteOne(ctx, bson.D{{Key: "_id", Value: s.key(strings.ToUpper(serial))}})
	return err
}

// ImportRow is one line of an import that did not go in.
type ImportRow struct {
	Row   int    `json:"row"`
	Error string `json:"error"`
}

// ImportResult says what an import did.
type ImportResult struct {
	Imported        int         `json:"imported"`
	AlreadyEnrolled int         `json:"already_enrolled"`
	GroupsCreated   []string    `json:"groups_created,omitempty"`
	Rejected        []ImportRow `json:"rejected,omitempty"`
}

// Import records the expected devices. A group that does not exist is an error for its row unless createGroups is set, which creates it as a static group (named as given).
func (s *Store) Import(ctx context.Context, rows []Expected, createGroups bool) (*ImportResult, error) {
	res := &ImportResult{}
	groups, err := s.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	known := map[string]*Group{}
	for i := range groups {
		known[groups[i].ID] = &groups[i]
	}
	created := map[string]bool{}
	for i, e := range rows {
		reject := func(msg string) { res.Rejected = append(res.Rejected, ImportRow{Row: i + 1, Error: msg}) }
		e.Serial = strings.ToUpper(strings.TrimSpace(e.Serial))
		if e.Serial == "" {
			reject("a serial number is required")
			continue
		}
		bad := ""
		for _, gid := range e.Groups {
			g := known[gid]
			if g == nil && createGroups && idPattern.MatchString(gid) {
				ng := Group{ID: gid, Name: gid}
				if err := s.PutGroup(ctx, ng); err != nil {
					bad = err.Error()
					break
				}
				known[gid], created[gid] = &ng, true
				continue
			}
			if g == nil {
				bad = fmt.Sprintf("the group %q does not exist (create it, or import with create_groups)", gid)
				break
			}
			if g.Rule != nil {
				bad = fmt.Sprintf("the group %q is dynamic: members are decided by its rule", gid)
				break
			}
		}
		if bad != "" {
			reject(bad)
			continue
		}
		enrolled, err := s.PutExpected(ctx, e)
		if err != nil {
			return nil, err
		}
		res.Imported++
		if enrolled {
			res.AlreadyEnrolled++
		}
	}
	for g := range created {
		res.GroupsCreated = append(res.GroupsCreated, g)
	}
	sort.Strings(res.GroupsCreated)
	return res, nil
}

// columnAliases are header names other products use for the same thing, matched ignoring case and punctuation. They only guess at headers: ParseCSV reports a file with no
// serial column rather than importing it wrongly, and columns= lets a caller name theirs.
var columnAliases = map[string][]string{
	"serial": {"serial", "serialnumber", "serialno", "deviceserial", "serialnumbers"},
	"name":   {"name", "devicename", "computername", "hostname", "assetname", "displayname"},
	"user":   {"user", "username", "assigneduser", "assignedto", "email", "owner", "enduser", "fullname"},
	"groups": {"groups", "group", "smartgroups", "staticgroups", "site", "department", "building"},
	"tags":   {"tags", "tag", "labels", "label", "assettag"},
}

func normHeader(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ParseCSV reads an export from another MDM or an inventory sheet. columns maps a field (serial, name, user, groups, tags) to the header that holds it; without it the headers are
// recognized by common names. Several groups or tags in a cell are separated by a semicolon or a comma inside quotes. source labels the records.
func ParseCSV(r io.Reader, columns map[string]string, source string) ([]Expected, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("the file has no header row: %w", err)
	}
	idx := map[string]int{}
	for field := range columnAliases {
		if want := columns[field]; want != "" {
			for i, h := range head {
				if normHeader(h) == normHeader(want) {
					idx[field] = i + 1
				}
			}
			if idx[field] == 0 {
				return nil, fmt.Errorf("there is no column %q for %s", want, field)
			}
			continue
		}
	found:
		for _, alias := range columnAliases[field] {
			for i, h := range head {
				if normHeader(h) == alias {
					idx[field] = i + 1
					break found
				}
			}
		}
	}
	if idx["serial"] == 0 {
		return nil, errors.New("no serial number column: name it with columns=serial:<header>")
	}
	cell := func(rec []string, field string) string {
		if i := idx[field]; i > 0 && i <= len(rec) {
			return strings.TrimSpace(rec[i-1])
		}
		return ""
	}
	list := func(s string) []string {
		var out []string
		for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == '|' }) {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	var out []Expected
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Expected{Serial: cell(rec, "serial"), Name: cell(rec, "name"), User: cell(rec, "user"), Groups: list(cell(rec, "groups")), Tags: list(cell(rec, "tags")), Source: source})
	}
	return out, nil
}
