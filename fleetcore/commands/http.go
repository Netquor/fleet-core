package commands

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/micromdm/nanolib/log"
	nanoapi "github.com/micromdm/nanomdm/api"
	"github.com/micromdm/nanomdm/push"
	"github.com/micromdm/nanomdm/storage"
)

// ResultReader reads what devices answered. The MongoDB storage implements it.
type ResultReader interface {
	CommandResults(ctx context.Context, commandUUID string) ([]Result, error)
}

// Result is one device's state for a command: queued, or what it answered (values as JSON: data as base64, dates as RFC 3339).
type Result struct {
	ID       string         `json:"id"`
	Status   string         `json:"status"`
	QueuedAt time.Time      `json:"queued_at"`
	ResultAt *time.Time     `json:"result_at,omitempty"`
	Result   map[string]any `json:"result,omitempty"`
}

// Request is the body of POST {prefix}/.
type Request struct {
	// RequestType is an MDM command, for example DeviceLock; GET {prefix}/types lists them.
	RequestType string `json:"request_type"`
	// Params are the command's keys, for example {"Message": "Call IT"}.
	Params map[string]any `json:"params"`
	// Devices are the enrollment IDs (UDIDs) to send it to.
	Devices []string `json:"devices"`
	// Platform, if given, rejects what does not exist there (macOS, iOS, tvOS, visionOS, watchOS).
	Platform string `json:"platform,omitempty"`
	// Confirm must be true for commands that lose data or lock someone out.
	Confirm bool `json:"confirm,omitempty"`
	// NoPush queues the command without waking the devices.
	NoPush bool `json:"no_push,omitempty"`
	// CommandUUID, optional: your own id for the command.
	CommandUUID string `json:"command_uuid,omitempty"`
}

// Handler serves the JSON command API under prefix (for example /v1/commands). Authentication is the caller's.
//
//	GET  {prefix}/types            the commands
//	GET  {prefix}/types/{Type}     one command's schema
//	POST {prefix}/                 validate, build and enqueue (with a push) a command
//	GET  {prefix}/{uuid}           per device: queued, or what the device answered, as JSON
func Handler(prefix string, cat *Catalog, enq storage.CommandEnqueuer, pusher push.Pusher, results ResultReader, logger log.Logger) (http.Handler, error) {
	pe, err := nanoapi.NewPushEnqueuer(enq, pusher, nanoapi.WithLogger(logger))
	if err != nil {
		return nil, err
	}
	prefix = strings.TrimRight(prefix, "/")
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(w http.ResponseWriter, code int, msg string, ps ...Problem) {
		writeJSON(w, code, map[string]any{"error": msg, "problems": ps})
	}

	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/types", func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			RequestType string            `json:"request_type"`
			Title       string            `json:"title"`
			Description string            `json:"description,omitempty"`
			Destructive bool              `json:"destructive,omitempty"`
			OS          map[string]OSInfo `json:"os,omitempty"`
		}
		rows := make([]row, 0, len(cat.Commands))
		for _, c := range cat.Commands {
			rows = append(rows, row{c.RequestType, c.Title, c.Description, c.Destructive, c.OS})
		}
		writeJSON(w, 200, map[string]any{"ref": cat.Ref, "commands": rows})
	})
	mux.HandleFunc(prefix+"/types/", func(w http.ResponseWriter, r *http.Request) {
		c, ok := cat.Get(strings.TrimPrefix(r.URL.Path, prefix+"/types/"))
		if !ok {
			fail(w, 404, "no such command")
			return
		}
		writeJSON(w, 200, c)
	})
	mux.HandleFunc(prefix+"/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && (r.URL.Path == prefix+"/" || r.URL.Path == prefix):
			var req Request
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
			dec.UseNumber()
			if err := dec.Decode(&req); err != nil {
				fail(w, 400, "the body is not valid JSON: "+err.Error())
				return
			}
			c, ok := cat.Get(req.RequestType)
			if !ok {
				fail(w, 422, "unknown request_type "+req.RequestType)
				return
			}
			if len(req.Devices) == 0 {
				fail(w, 422, "devices is empty")
				return
			}
			if c.Destructive && !req.Confirm {
				fail(w, 422, req.RequestType+" can lose data or lock someone out: send \"confirm\": true to proceed")
				return
			}
			body, uuid, ps := c.Build(req.Params, Options{Platform: req.Platform, CommandUUID: req.CommandUUID})
			if len(ps) > 0 {
				fail(w, 422, "the command is not valid", ps...)
				return
			}
			res, _, err := pe.RawCommandEnqueueWithPush(r.Context(), body, req.Devices, req.NoPush)
			if err != nil && res == nil {
				fail(w, 500, err.Error())
				return
			}
			code := 200
			if err != nil {
				code = 207
			}
			writeJSON(w, code, map[string]any{"command_uuid": uuid, "request_type": req.RequestType, "result": res})
		case r.Method == http.MethodGet:
			if results == nil {
				fail(w, 501, "this storage cannot report results")
				return
			}
			uuid := strings.TrimPrefix(r.URL.Path, prefix+"/")
			rows, err := results.CommandResults(r.Context(), uuid)
			if err != nil && !errors.Is(err, context.Canceled) {
				fail(w, 500, err.Error())
				return
			}
			if len(rows) == 0 {
				fail(w, 404, "no such command")
				return
			}
			writeJSON(w, 200, map[string]any{"command_uuid": uuid, "devices": rows})
		default:
			fail(w, 405, "method not allowed")
		}
	})
	return mux, nil
}
