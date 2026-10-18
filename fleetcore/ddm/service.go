package ddm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// DeclarationStatus is a device's report on one declaration.
type DeclarationStatus struct {
	Identifier  string   `json:"identifier"`
	ServerToken string   `json:"server-token"`
	Active      bool     `json:"active"`
	Valid       string   `json:"valid"` // unknown, invalid, valid
	Reasons     []Reason `json:"reasons,omitempty"`
}

// Reason is why a declaration is invalid or inactive.
type Reason struct {
	Code        string         `json:"code"`
	Description string         `json:"description,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// Report is a status report from a device.
type Report struct {
	StatusItems map[string]json.RawMessage `json:"StatusItems"`
	Errors      []struct {
		StatusItem string   `json:"StatusItem"`
		Reasons    []Reason `json:"Reasons"`
	} `json:"Errors"`
	FullReport bool `json:"FullReport"`
}

// Declarations extracts the management.declarations status item.
func (r Report) Declarations() []DeclarationStatus {
	raw, ok := r.StatusItems["management.declarations"]
	if !ok {
		return nil
	}
	var d struct {
		Activations    []DeclarationStatus `json:"activations"`
		Configurations []DeclarationStatus `json:"configurations"`
		Assets         []DeclarationStatus `json:"assets"`
		Management     []DeclarationStatus `json:"management"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return nil
	}
	return append(append(append(d.Activations, d.Configurations...), d.Assets...), d.Management...)
}

// String reads a status item that is a string.
func (r Report) String(name string) string {
	var s string
	if raw, ok := r.StatusItems[name]; ok && json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// Service answers the declarative management protocol for the NanoMDM service (service.DeclarativeManagement).
type Service struct {
	Store *Store
	// OnStatus is called with each status report after it is stored (inventory and blueprint state follow from it).
	OnStatus func(ctx context.Context, device string, rep Report)
}

var _ service.DeclarativeManagement = (*Service)(nil)

func httpErr(code int, format string, a ...any) error {
	return service.NewHTTPStatusError(code, fmt.Errorf(format, a...))
}

// DeclarativeManagement handles one request from a device.
func (s *Service) DeclarativeManagement(r *mdm.Request, m *mdm.DeclarativeManagement) ([]byte, error) {
	ctx, id := r.Context(), r.ID
	switch {
	case m.Endpoint == "tokens":
		st, err := s.Store.State(ctx, id)
		if err != nil {
			return nil, err
		}
		ts := st.UpdatedAt
		if ts.IsZero() {
			ts = s.Store.now()
		}
		token := st.Token
		if token == "" {
			token = SetToken(nil)
		}
		return json.Marshal(map[string]any{"SyncTokens": map[string]any{"DeclarationsToken": token, "Timestamp": ts.UTC().Format(time.RFC3339)}})

	case m.Endpoint == "declaration-items":
		ds, err := s.Store.List(ctx, id)
		if err != nil {
			return nil, err
		}
		type item struct {
			Identifier  string `json:"Identifier"`
			ServerToken string `json:"ServerToken"`
		}
		groups := map[string][]item{KindActivation: {}, KindAsset: {}, KindConfiguration: {}, KindManagement: {}}
		for _, d := range ds {
			groups[d.Kind] = append(groups[d.Kind], item{d.Identifier, d.Token()})
		}
		token := SetToken(ds)
		_ = s.Store.Synced(ctx, id, token)
		return json.Marshal(map[string]any{
			"Declarations":      map[string]any{"Activations": groups[KindActivation], "Assets": groups[KindAsset], "Configurations": groups[KindConfiguration], "Management": groups[KindManagement]},
			"DeclarationsToken": token,
		})

	case strings.HasPrefix(m.Endpoint, "declaration/"):
		parts := strings.SplitN(strings.TrimPrefix(m.Endpoint, "declaration/"), "/", 2)
		if len(parts) != 2 {
			return nil, httpErr(http.StatusBadRequest, "malformed declaration endpoint %q", m.Endpoint)
		}
		d, err := s.Store.Get(ctx, id, parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		if d == nil {
			return nil, httpErr(http.StatusNotFound, "no %s declaration %q", parts[0], parts[1])
		}
		return d.Wire()

	case m.Endpoint == "status":
		var rep Report
		if err := json.Unmarshal(m.Data, &rep); err != nil {
			return nil, httpErr(http.StatusBadRequest, "status report: %v", err)
		}
		if err := s.Store.SaveStatus(ctx, id, m.Data, rep); err != nil {
			return nil, err
		}
		if s.OnStatus != nil {
			s.OnStatus(ctx, id, rep)
		}
		return nil, nil
	}
	return nil, httpErr(http.StatusBadRequest, "unknown declarative management endpoint %q", m.Endpoint)
}

// SaveStatus keeps the latest status per declaration and the raw report. A full report replaces what was known; a partial one updates it.
func (s *Store) SaveStatus(ctx context.Context, device string, raw []byte, rep Report) error {
	set := bson.D{{Key: "device", Value: device}, {Key: "at", Value: s.now()}}
	for _, d := range rep.Declarations() {
		set = append(set, bson.E{Key: "decl." + safeKey(d.Identifier), Value: bson.D{{Key: "identifier", Value: d.Identifier}, {Key: "server_token", Value: d.ServerToken}, {Key: "active", Value: d.Active}, {Key: "valid", Value: d.Valid}, {Key: "reasons", Value: reasonText(d.Reasons)}}})
	}
	for name, v := range rep.StatusItems {
		if name == "management.declarations" {
			continue
		}
		var x any
		if json.Unmarshal(v, &x) == nil {
			set = append(set, bson.E{Key: "items." + safeKey(name), Value: x})
		}
	}
	if len(rep.Errors) > 0 {
		var errs []bson.M
		for _, e := range rep.Errors {
			errs = append(errs, bson.M{"item": e.StatusItem, "reasons": reasonText(e.Reasons)})
		}
		set = append(set, bson.E{Key: "errors", Value: errs})
	}
	_, err := s.db.Collection(cStatus).UpdateOne(ctx, bson.D{{Key: "_id", Value: s.key(device)}}, bson.D{{Key: "$set", Value: s.stamp(set)}}, options.UpdateOne().SetUpsert(true))
	return err
}

// safeKey makes a name usable as a field name (MongoDB field names cannot hold dots).
func safeKey(s string) string { return strings.NewReplacer(".", "·", "$", "＄").Replace(s) }

func reasonText(rs []Reason) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.Description != "" {
			parts = append(parts, r.Code+": "+r.Description)
		} else {
			parts = append(parts, r.Code)
		}
	}
	return strings.Join(parts, "; ")
}

// Status returns what a device last reported: its declarations' state and its status items.
func (s *Store) Status(ctx context.Context, device string) (decls map[string]DeclarationState, items map[string]any, at time.Time, err error) {
	var doc struct {
		At    time.Time                   `bson:"at"`
		Decl  map[string]DeclarationState `bson:"decl"`
		Items map[string]any              `bson:"items"`
	}
	err = s.db.Collection(cStatus).FindOne(ctx, bson.D{{Key: "_id", Value: s.key(device)}}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil, time.Time{}, nil
	}
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	decls = make(map[string]DeclarationState, len(doc.Decl))
	for _, v := range doc.Decl {
		decls[v.Identifier] = v
	}
	return decls, doc.Items, doc.At, nil
}

// DeclarationState is the stored form of a declaration's status.
type DeclarationState struct {
	Identifier  string `bson:"identifier" json:"identifier"`
	ServerToken string `bson:"server_token" json:"server_token"`
	Active      bool   `bson:"active" json:"active"`
	Valid       string `bson:"valid" json:"valid"`
	Reasons     string `bson:"reasons" json:"reasons,omitempty"`
}
