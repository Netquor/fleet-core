package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/micromdm/nanomdm/storage/mongodb"
)

// lister is what the listing API needs from the storage; the MongoDB storage has it.
type lister interface {
	ListEnrollments(ctx context.Context, f mongodb.EnrollmentFilter, p mongodb.Page) ([]mongodb.Enrollment, string, error)
	GetEnrollment(ctx context.Context, id string) (*mongodb.Enrollment, error)
	ListQueue(ctx context.Context, f mongodb.QueueFilter, p mongodb.Page) ([]mongodb.QueueEntry, string, error)
	ListCommands(ctx context.Context, requestType string, contents bool, p mongodb.Page) ([]mongodb.CommandInfo, string, error)
}

// commandLister adapts the storage to the command API's history listing.
type commandLister struct{ l lister }

func (c commandLister) ListCommands(ctx context.Context, requestType string, contents bool, after string, limit int) ([]map[string]any, string, error) {
	rows, next, err := c.l.ListCommands(ctx, requestType, contents, mongodb.Page{After: after, Limit: limit})
	if err != nil {
		return nil, "", err
	}
	b, _ := json.Marshal(rows)
	var out []map[string]any
	_ = json.Unmarshal(b, &out)
	return out, next, nil
}

// listingHandler serves enrollments and the command queue, in pages. Mount it with http.StripPrefix("/v1").
//
//	GET /enrollments?device=&type=&enabled=&cursor=&limit=
//	GET /enrollments/{id}
//	GET /enrollments/{id}/queue?status=pending|acknowledged|error|notnow&type=&cursor=&limit=
//	GET /queue?id=&status=&type=&command=&cursor=&limit=          the queue across enrollments
func listingHandler(l lister) http.Handler {
	write := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	page := func(r *http.Request) mongodb.Page {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		return mongodb.Page{After: r.URL.Query().Get("cursor"), Limit: n}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /enrollments", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := mongodb.EnrollmentFilter{DeviceID: q.Get("device"), Type: q.Get("type")}
		if v := q.Get("enabled"); v != "" {
			b := v == "true" || v == "1"
			f.Enabled = &b
		}
		rows, next, err := l.ListEnrollments(r.Context(), f, page(r))
		if err != nil {
			write(w, 400, map[string]any{"error": err.Error()})
			return
		}
		write(w, 200, map[string]any{"enrollments": rows, "next": next})
	})
	mux.HandleFunc("GET /enrollments/{id}", func(w http.ResponseWriter, r *http.Request) {
		e, err := l.GetEnrollment(r.Context(), r.PathValue("id"))
		switch {
		case err != nil:
			write(w, 500, map[string]any{"error": err.Error()})
		case e == nil:
			write(w, 404, map[string]any{"error": "not found"})
		default:
			write(w, 200, e)
		}
	})
	queue := func(w http.ResponseWriter, r *http.Request, id string) {
		q := r.URL.Query()
		rows, next, err := l.ListQueue(r.Context(), mongodb.QueueFilter{ID: id, CommandUUID: q.Get("command"), Status: q.Get("status"), RequestType: q.Get("type")}, page(r))
		if err != nil {
			write(w, 400, map[string]any{"error": err.Error()})
			return
		}
		write(w, 200, map[string]any{"queue": rows, "next": next})
	}
	mux.HandleFunc("GET /enrollments/{id}/queue", func(w http.ResponseWriter, r *http.Request) { queue(w, r, r.PathValue("id")) })
	mux.HandleFunc("GET /queue", func(w http.ResponseWriter, r *http.Request) { queue(w, r, r.URL.Query().Get("id")) })
	return mux
}
