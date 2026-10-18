package vpp

import (
	"encoding/json"
	"net/http"
)

func write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Handler is the Apps and Books API. Mount it with http.StripPrefix("/v1").
//
//	GET    /vpp/tokens                    stored tokens (never their contents)
//	PUT    /vpp/tokens/{name}             {"token": "<the file from Apple Business Manager>"}: checked with Apple, then kept sealed
//	DELETE /vpp/tokens/{name}
//	GET    /vpp/{name}/assets?adam_id=    owned apps and license counts
//	GET    /vpp/{name}/assignments?serial=&adam_id=
//	POST   /vpp/{name}/assign             {"adam_ids": [...], "serials": [...]}   POST /unassign takes them back
func (l *Licensing) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /vpp/tokens", func(w http.ResponseWriter, r *http.Request) {
		ts, err := l.Store.Tokens(r.Context())
		if err != nil {
			write(w, 500, map[string]any{"error": err.Error()})
			return
		}
		write(w, 200, map[string]any{"tokens": ts})
	})
	mux.HandleFunc("PUT /vpp/tokens/{name}", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			write(w, 400, map[string]any{"error": "the body is not valid JSON"})
			return
		}
		info, err := l.Store.PutToken(r.Context(), r.PathValue("name"), req.Token, &Client{BaseURL: l.BaseURL, HTTP: l.HTTP})
		if err != nil {
			write(w, 422, map[string]any{"error": err.Error()})
			return
		}
		write(w, 200, info)
	})
	mux.HandleFunc("DELETE /vpp/tokens/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := l.Store.DeleteToken(r.Context(), r.PathValue("name")); err != nil {
			write(w, 500, map[string]any{"error": err.Error()})
			return
		}
		w.WriteHeader(204)
	})
	withClient := func(f func(w http.ResponseWriter, r *http.Request, c *Client)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c, err := l.client(r.Context(), r.PathValue("name"))
			if err != nil {
				write(w, 404, map[string]any{"error": err.Error()})
				return
			}
			f(w, r, c)
		}
	}
	mux.HandleFunc("GET /vpp/{name}/assets", withClient(func(w http.ResponseWriter, r *http.Request, c *Client) {
		as, err := c.Assets(r.Context(), r.URL.Query().Get("adam_id"))
		if err != nil {
			write(w, 502, map[string]any{"error": err.Error()})
			return
		}
		write(w, 200, map[string]any{"assets": as})
	}))
	mux.HandleFunc("GET /vpp/{name}/assignments", withClient(func(w http.ResponseWriter, r *http.Request, c *Client) {
		as, err := c.Assignments(r.Context(), r.URL.Query().Get("serial"), r.URL.Query().Get("adam_id"))
		if err != nil {
			write(w, 502, map[string]any{"error": err.Error()})
			return
		}
		write(w, 200, map[string]any{"assignments": as})
	}))
	change := func(assign bool) http.HandlerFunc {
		return withClient(func(w http.ResponseWriter, r *http.Request, c *Client) {
			var req struct {
				AdamIDs []string `json:"adam_ids"`
				Serials []string `json:"serials"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || len(req.AdamIDs) == 0 || len(req.Serials) == 0 {
				write(w, 400, map[string]any{"error": "adam_ids and serials are required"})
				return
			}
			var ev *Event
			var err error
			if assign {
				ev, err = c.Associate(r.Context(), req.AdamIDs, req.Serials)
			} else {
				ev, err = c.Disassociate(r.Context(), req.AdamIDs, req.Serials)
			}
			if err != nil {
				write(w, 502, map[string]any{"error": err.Error()})
				return
			}
			write(w, 202, ev)
		})
	}
	mux.HandleFunc("POST /vpp/{name}/assign", change(true))
	mux.HandleFunc("POST /vpp/{name}/unassign", change(false))
	return mux
}
