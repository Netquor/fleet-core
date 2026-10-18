package blueprints

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"

	"github.com/micromdm/nanomdm/fleetcore/applicability"
	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"github.com/micromdm/plist"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// API is the management API for blueprints, groups, devices, platform applicability, Apple schemas and OS releases. Authentication is the caller's.
type API struct {
	Engine          *Engine
	Applicability   *applicability.Registry
	OSReleases      *osreleases.Refresher
	SchemaRefresher *schemas.Refresher
	// ResolveApp finds the bundle identifier of an App Store app, for items that give only its number. Nil: the item must carry it.
	ResolveApp func(ctx context.Context, adamID string) (bundleID string, err error)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(v); err != nil {
		fail(w, 400, "the body is not valid JSON: "+err.Error())
		return false
	}
	return true
}

func storeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		fail(w, 404, "not found")
		return
	}
	fail(w, 500, err.Error())
}

// Handler returns the routes, relative to a mount point (mount with http.StripPrefix("/v1", ...)).
func (a *API) Handler() http.Handler {
	e := a.Engine
	st := e.Store
	mux := http.NewServeMux()

	// ---- blueprints ----
	mux.HandleFunc("GET /blueprints", func(w http.ResponseWriter, r *http.Request) {
		bps, err := st.ListBlueprints(r.Context(), false)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		for i := range bps {
			for j := range bps[i].Items {
				bps[i].Items[j].Payload = nil // the list stays small; GET one for the profile bodies
			}
		}
		writeJSON(w, 200, map[string]any{"blueprints": bps})
	})
	save := func(w http.ResponseWriter, r *http.Request, id string, create bool) {
		var b Blueprint
		if !decode(w, r, &b) {
			return
		}
		if id != "" {
			b.ID = id
		}
		if a.ResolveApp != nil {
			for i := range b.Items {
				if it := &b.Items[i]; it.Kind == "app" && it.AdamID != "" && it.BundleID == "" {
					bundle, err := a.ResolveApp(r.Context(), it.AdamID)
					if err != nil {
						fail(w, 422, "item "+it.ID+": "+err.Error())
						return
					}
					it.BundleID = bundle
				}
			}
		}
		if err := b.Prepare(); err != nil {
			fail(w, 422, err.Error())
			return
		}
		env, err := e.Env(r.Context())
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		if _, err := b.Scope.Expand(env); err != nil {
			fail(w, 422, "scope: "+err.Error())
			return
		}
		if create {
			if _, err := st.GetBlueprint(r.Context(), b.ID); err == nil {
				fail(w, 409, "a blueprint with that id exists; PUT replaces it")
				return
			}
		}
		by, _, _ := r.BasicAuth()
		out, err := st.SaveBlueprint(r.Context(), b, by, env)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		e.Invalidate()
		code := 200
		if create {
			code = 201
		}
		writeJSON(w, code, out)
	}
	mux.HandleFunc("POST /blueprints", func(w http.ResponseWriter, r *http.Request) { save(w, r, "", true) })
	mux.HandleFunc("PUT /blueprints/{id}", func(w http.ResponseWriter, r *http.Request) { save(w, r, r.PathValue("id"), false) })
	mux.HandleFunc("GET /blueprints/{id}", func(w http.ResponseWriter, r *http.Request) {
		b, err := st.GetBlueprint(r.Context(), r.PathValue("id"))
		if err != nil {
			storeErr(w, err)
			return
		}
		writeJSON(w, 200, b)
	})
	mux.HandleFunc("DELETE /blueprints/{id}", func(w http.ResponseWriter, r *http.Request) {
		env, _ := e.Env(r.Context())
		if err := st.DeleteBlueprint(r.Context(), r.PathValue("id"), env); err != nil {
			storeErr(w, err)
			return
		}
		e.Invalidate()
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /blueprints/{id}/revisions", func(w http.ResponseWriter, r *http.Request) {
		revs, err := st.Revisions(r.Context(), r.PathValue("id"), 50)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		type row struct {
			Revision  int    `json:"revision"`
			UpdatedAt any    `json:"updated_at"`
			UpdatedBy string `json:"updated_by,omitempty"`
			Items     int    `json:"items"`
		}
		out := make([]row, len(revs))
		for i, b := range revs {
			out[i] = row{b.Revision, b.UpdatedAt, b.UpdatedBy, len(b.Items)}
		}
		writeJSON(w, 200, map[string]any{"revisions": out})
	})
	mux.HandleFunc("POST /blueprints/{id}/rollback", func(w http.ResponseWriter, r *http.Request) {
		want, err := strconv.Atoi(r.URL.Query().Get("revision"))
		if err != nil {
			fail(w, 400, "revision=N is required")
			return
		}
		revs, err := st.Revisions(r.Context(), r.PathValue("id"), 1000)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		for _, old := range revs {
			if old.Revision == want {
				env, _ := e.Env(r.Context())
				by, _, _ := r.BasicAuth()
				out, err := st.SaveBlueprint(r.Context(), old, by, env)
				if err != nil {
					fail(w, 500, err.Error())
					return
				}
				e.Invalidate()
				writeJSON(w, 200, out)
				return
			}
		}
		fail(w, 404, "no such revision")
	})
	mux.HandleFunc("GET /blueprints/{id}/preview", func(w http.ResponseWriter, r *http.Request) {
		b, err := st.GetBlueprint(r.Context(), r.PathValue("id"))
		if err != nil {
			storeErr(w, err)
			return
		}
		env, _ := e.Env(r.Context())
		scope, err := b.Scope.Expand(env)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
		total, err := st.CountDevices(r.Context(), scope)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		sample, _ := st.QueryDevices(r.Context(), scope, "", 20)
		// How the staged rollout would reach the devices in scope (up to the first 10,000).
		rings := map[string]int{}
		after, seen := "", 0
		for seen < 10000 {
			page, err := st.QueryDevices(r.Context(), scope, after, 1000)
			if err != nil || len(page) == 0 {
				break
			}
			for _, d := range page {
				if !d.Active {
					continue
				}
				at, ok := eligibleAt(b, d.ID)
				switch {
				case !ok:
					rings["not reached"]++
				case at.Equal(b.RolloutAt):
					rings["immediately"]++
				default:
					rings["after "+at.Sub(b.RolloutAt).String()]++
				}
			}
			seen += len(page)
			after = page[len(page)-1].ID
		}
		writeJSON(w, 200, map[string]any{"devices_in_scope": total, "sample": sample, "rollout": rings})
	})
	mux.HandleFunc("GET /blueprints/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		b, err := st.GetBlueprint(r.Context(), r.PathValue("id"))
		if err != nil {
			storeErr(w, err)
			return
		}
		counts, err := st.Status(r.Context(), b.ID)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"blueprint": b.ID, "revision": b.Revision, "rollout_at": b.RolloutAt, "states": counts})
	})

	// ---- devices Apple assigned to this server, known before they enroll ----
	mux.HandleFunc("GET /dep-devices", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		rows, err := st.ListDEP(r.Context(), r.URL.Query().Get("cursor"), n)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		next := ""
		if len(rows) > 0 && (n <= 0 && len(rows) == 100 || len(rows) == n) {
			next = rows[len(rows)-1].Serial
		}
		writeJSON(w, 200, map[string]any{"devices": rows, "next": next})
	})

	// ---- groups ----
	mux.HandleFunc("GET /groups", func(w http.ResponseWriter, r *http.Request) {
		gs, err := st.ListGroups(r.Context())
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"groups": gs})
	})
	mux.HandleFunc("PUT /groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		var g Group
		if !decode(w, r, &g) {
			return
		}
		g.ID = r.PathValue("id")
		if g.Name == "" {
			g.Name = g.ID
		}
		if err := st.PutGroup(r.Context(), g); err != nil {
			fail(w, 422, err.Error())
			return
		}
		e.Invalidate()
		writeJSON(w, 200, g)
	})
	mux.HandleFunc("DELETE /groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := st.DeleteGroup(r.Context(), r.PathValue("id")); err != nil {
			storeErr(w, err)
			return
		}
		e.Invalidate()
		w.WriteHeader(204)
	})

	// ---- devices ----
	// GET /devices?platform=&model=&serial=&name=&dep_name=&enroll_type=&user=&tag=&group=&os_version_lt=&cursor=&limit=  (every filter given must match)
	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var all []Rule
		for _, f := range []string{"platform", "model", "serial", "name", "dep_name", "enroll_type", "user", "tag", "group"} {
			if v := q.Get(f); v != "" {
				all = append(all, Rule{Field: f, Op: "eq", Value: v})
			}
		}
		if v := q.Get("os_version_lt"); v != "" {
			all = append(all, Rule{Field: "os_version", Op: "lt", Value: v})
		}
		rule := Rule{All: all}
		if err := rule.Validate(); err != nil {
			fail(w, 422, err.Error())
			return
		}
		env, _ := e.Env(r.Context())
		x, err := rule.Expand(env)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
		n, _ := strconv.Atoi(q.Get("limit"))
		if n <= 0 || n > 1000 {
			n = 100
		}
		ds, err := st.QueryDevices(r.Context(), x, q.Get("cursor"), n)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		next := ""
		if len(ds) == n {
			next = ds[len(ds)-1].ID
		}
		writeJSON(w, 200, map[string]any{"devices": ds, "next": next})
	})
	mux.HandleFunc("POST /devices/query", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Rule  Rule   `json:"rule"`
			After string `json:"after"`
			Limit int    `json:"limit"`
		}
		if !decode(w, r, &req) {
			return
		}
		if err := req.Rule.Validate(); err != nil {
			fail(w, 422, err.Error())
			return
		}
		env, _ := e.Env(r.Context())
		x, err := req.Rule.Expand(env)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
		ds, err := st.QueryDevices(r.Context(), x, req.After, req.Limit)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		next := ""
		if l := len(ds); l > 0 && (req.Limit <= 0 && l == 100 || l == req.Limit) {
			next = ds[l-1].ID
		}
		writeJSON(w, 200, map[string]any{"devices": ds, "next": next})
	})
	mux.HandleFunc("GET /devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		d, err := st.GetDevice(r.Context(), r.PathValue("id"))
		if err != nil {
			storeErr(w, err)
			return
		}
		apps, _ := st.Applications(r.Context(), d.ID)
		out := map[string]any{"device": d, "applications": apps}
		if e.Releases != nil {
			if s, ok := e.Releases.Compare(d.Platform, d.OSVersion); ok {
				out["os_status"] = s
			}
		}
		writeJSON(w, 200, out)
	})
	setList := func(field string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Values []string `json:"values"`
			}
			if !decode(w, r, &body) {
				return
			}
			sort.Strings(body.Values)
			if err := st.SetDeviceFields(r.Context(), r.PathValue("id"), bson.D{{Key: field, Value: body.Values}}, true); err != nil {
				storeErr(w, err)
				return
			}
			w.WriteHeader(204)
		}
	}
	mux.HandleFunc("PUT /devices/{id}/tags", setList("tags"))
	mux.HandleFunc("PUT /devices/{id}/groups", setList("groups"))

	// ---- platform applicability ----
	mux.HandleFunc("GET /applicability", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"overrides": a.Applicability.List()})
	})
	mux.HandleFunc("PUT /applicability/{id}", func(w http.ResponseWriter, r *http.Request) {
		var o applicability.Override
		if !decode(w, r, &o) {
			return
		}
		o.ID = r.PathValue("id")
		if err := a.Applicability.Put(r.Context(), o); err != nil {
			fail(w, 422, err.Error())
			return
		}
		e.Store.Touch(r.Context(), Rule{}) // every device is looked at again with the new rule
		writeJSON(w, 200, o)
	})
	mux.HandleFunc("DELETE /applicability/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Applicability.Delete(r.Context(), r.PathValue("id")); err != nil {
			fail(w, 500, err.Error())
			return
		}
		e.Store.Touch(r.Context(), Rule{})
		w.WriteHeader(204)
	})
	// Try a profile against a platform without saving anything.
	mux.HandleFunc("POST /applicability/check", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Profile   []byte `json:"profile"`
			Platform  string `json:"platform"`
			OSVersion string `json:"os_version"`
		}
		if !decode(w, r, &req) {
			return
		}
		res, err := a.Applicability.Apply(req.Profile, req.Platform, req.OSVersion)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"not_applicable": res.NotApplicable, "left_out": res.LeftOut, "profile": res.Profile})
	})

	// ---- Apple schemas ----
	mux.HandleFunc("GET /schemas", func(w http.ResponseWriter, r *http.Request) {
		s := schemas.Current()
		writeJSON(w, 200, map[string]any{"ref": s.Ref, "fetched_at": s.FetchedAt, "commands": len(s.Commands), "profile_payloads": len(s.Profiles)})
	})
	mux.HandleFunc("POST /schemas/refresh", func(w http.ResponseWriter, r *http.Request) {
		if a.SchemaRefresher == nil {
			fail(w, 501, "schema refresh is not configured")
			return
		}
		s, changed, err := a.SchemaRefresher.Check(r.Context())
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		e.Store.Touch(r.Context(), Rule{})
		writeJSON(w, 200, map[string]any{"changed": changed, "ref": s.Ref, "commands": len(s.Commands), "profile_payloads": len(s.Profiles)})
	})
	mux.HandleFunc("GET /schemas/profiles", func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			PayloadType string                    `json:"payload_type"`
			Title       string                    `json:"title"`
			OS          map[string]schemas.OSInfo `json:"os,omitempty"`
		}
		var rows []row
		for _, p := range schemas.Current().Profiles {
			rows = append(rows, row{p.PayloadType, p.Title, p.OS})
		}
		writeJSON(w, 200, map[string]any{"profiles": rows})
	})
	mux.HandleFunc("GET /schemas/profiles/{type}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := schemas.Current().Profile(r.PathValue("type"))
		if !ok {
			fail(w, 404, "no such payload type")
			return
		}
		writeJSON(w, 200, p)
	})

	// ---- declarative device management ----
	// How far the fleet is on declarative management, and what is left on profiles: where a native declaration exists and where Apple has deprecated a profile payload.
	mux.HandleFunc("GET /ddm/coverage", func(w http.ResponseWriter, r *http.Request) {
		bps, err := st.ListBlueprints(r.Context(), false)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		equiv := ddm.Equivalents()
		set := schemas.Current()
		type payloadRow struct {
			Type         string            `json:"type"`
			NativeTypes  []string          `json:"native_declarations,omitempty"`
			DeprecatedIn map[string]string `json:"deprecated_in,omitempty"`
			RemovedIn    map[string]string `json:"removed_in,omitempty"`
		}
		type itemRow struct {
			Blueprint string       `json:"blueprint"`
			Item      string       `json:"item"`
			Kind      string       `json:"kind"`
			Delivery  string       `json:"delivery,omitempty"`
			Payloads  []payloadRow `json:"payloads,omitempty"`
		}
		var items []itemRow
		for _, b := range bps {
			for _, it := range b.Items {
				row := itemRow{Blueprint: b.ID, Item: it.ID, Kind: it.Kind, Delivery: it.Delivery}
				if it.Kind == "profile" {
					for _, typ := range profilePayloadTypes(it.Payload) {
						pr := payloadRow{Type: typ, NativeTypes: equiv[typ]}
						if def, ok := set.Profile(typ); ok {
							for os, info := range def.OS {
								if info.Deprecated != "" && info.Deprecated != "n/a" {
									if pr.DeprecatedIn == nil {
										pr.DeprecatedIn = map[string]string{}
									}
									pr.DeprecatedIn[os] = info.Deprecated
								}
								if info.Removed != "" && info.Removed != "n/a" {
									if pr.RemovedIn == nil {
										pr.RemovedIn = map[string]string{}
									}
									pr.RemovedIn[os] = info.Removed
								}
							}
						}
						row.Payloads = append(row.Payloads, pr)
					}
				}
				items = append(items, row)
			}
		}
		counts, err := st.DeliveryCounts(r.Context())
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "applications_by_delivery": counts, "profile_payloads_with_native_declarations": len(equiv)})
	})
	// Express a profile as native declarations where Apple has an equivalent. Nothing is saved; the result says what could not be translated.
	mux.HandleFunc("POST /ddm/translate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Profile     []byte `json:"profile"`
			Declaration string `json:"declaration"`
		}
		if !decode(w, r, &req) {
			return
		}
		var p struct {
			PayloadContent []map[string]any
		}
		if err := plist.Unmarshal(req.Profile, &p); err != nil {
			fail(w, 422, "the profile is not a valid property list: "+err.Error())
			return
		}
		type outRow struct {
			PayloadType string `json:"payload_type"`
			*ddm.Translation
			Note string `json:"note,omitempty"`
		}
		var out []outRow
		for _, c := range p.PayloadContent {
			typ, _ := c["PayloadType"].(string)
			tr, ok := ddm.Translate(typ, c, req.Declaration, schemas.Current())
			if !ok {
				out = append(out, outRow{PayloadType: typ, Note: "no native declaration for this payload type: keep it as a profile (it is delivered as a legacy-profile declaration where the device allows)"})
				continue
			}
			out = append(out, outRow{PayloadType: typ, Translation: tr})
		}
		writeJSON(w, 200, map[string]any{"payloads": out})
	})
	// From which OS version declarative management, and its software update features, are available, per platform; and every declaration type for one platform.
	mux.HandleFunc("GET /ddm/support", func(w http.ResponseWriter, r *http.Request) {
		set := schemas.Current()
		if p := r.URL.Query().Get("platform"); p != "" {
			writeJSON(w, 200, map[string]any{"platform": p, "schema": set.Ref, "declarations": ddm.SupportFor(set, p)})
			return
		}
		writeJSON(w, 200, map[string]any{"schema": set.Ref, "platforms": ddm.Support(set)})
	})
	mux.HandleFunc("GET /ddm/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		if e.DDM == nil {
			fail(w, 501, "declarative management is not enabled")
			return
		}
		id := r.PathValue("id")
		decls, err := e.DDM.List(r.Context(), id)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		state, _ := e.DDM.State(r.Context(), id)
		status, items, at, _ := e.DDM.Status(r.Context(), id)
		type row struct {
			Identifier string `json:"identifier"`
			Kind       string `json:"kind"`
			Type       string `json:"type"`
			Token      string `json:"server_token"`
			Source     string `json:"source"`
			Payload    any    `json:"payload,omitempty"`
		}
		rows := make([]row, len(decls))
		for i, d := range decls {
			rows[i] = row{d.Identifier, d.Kind, d.Type, d.Token(), d.Source, d.Payload}
		}
		writeJSON(w, 200, map[string]any{"declarations": rows, "sync": state, "status": status, "status_items": items, "status_at": at})
	})

	// ---- Apple OS releases ----
	mux.HandleFunc("GET /os-releases", func(w http.ResponseWriter, r *http.Request) {
		all := e.Releases.All()
		if p := r.URL.Query().Get("platform"); p != "" {
			f := all[:0:0]
			for _, x := range all {
				if x.Platform == p {
					f = append(f, x)
				}
			}
			all = f
		}
		writeJSON(w, 200, map[string]any{"releases": all, "updated_at": e.Releases.UpdatedAt()})
	})
	mux.HandleFunc("GET /os-releases/latest", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{}
		for _, p := range releasePlatforms {
			if rel, ok := e.Releases.Latest(p); ok {
				byMajor := map[string]string{}
				for _, m := range e.Releases.Majors(p) {
					if x, ok := e.Releases.LatestInMajor(p, m); ok {
						byMajor[strconv.Itoa(m)] = x.Version
					}
				}
				out[p] = map[string]any{"latest": rel, "by_major": byMajor}
			}
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("POST /os-releases/refresh", func(w http.ResponseWriter, r *http.Request) {
		if a.OSReleases == nil {
			fail(w, 501, "the releases feed is not configured")
			return
		}
		n, err := a.OSReleases.Check(r.Context())
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"new_releases": n})
	})
	return mux
}

var _ = context.Background

// profilePayloadTypes lists the payload types inside a configuration profile.
func profilePayloadTypes(profile []byte) []string {
	var p struct {
		PayloadContent []struct{ PayloadType string }
	}
	if plist.Unmarshal(profile, &p) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range p.PayloadContent {
		if c.PayloadType != "" && !seen[c.PayloadType] {
			seen[c.PayloadType] = true
			out = append(out, c.PayloadType)
		}
	}
	return out
}
