package blueprints

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"

	"github.com/micromdm/nanomdm/fleetcore/applicability"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// API is the management API for blueprints, groups, devices, platform applicability, Apple schemas and OS releases. Authentication is the caller's.
type API struct {
	Engine          *Engine
	Applicability   *applicability.Registry
	OSReleases      *osreleases.Refresher
	SchemaRefresher *schemas.Refresher
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
