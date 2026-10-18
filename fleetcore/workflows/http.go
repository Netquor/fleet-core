package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/micromdm/nanomdm/fleetcore/admin"
	"github.com/micromdm/nanomdm/fleetcore/blueprints"
	"github.com/micromdm/nanomdm/fleetcore/vault"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// BootstrapReader reads a device's bootstrap token from the MDM storage.
type BootstrapReader interface {
	BootstrapTokenString(ctx context.Context, id string) (string, bool, error)
}

// API is the HTTP face of the workflows. Mount Handler with http.StripPrefix("/v1"); anything it does not serve goes to fallback.
//
//	GET  /devices/{id}/secrets                          what is stored (kinds, versions, who, when), never values
//	POST /devices/{id}/secrets/{kind}/reveal            {"reason": "...", "version": 0}: the value, with the access recorded
//	GET  /devices/{id}/secrets/audit                    who read what, and why
//	POST /devices/{id}/lost-mode  DELETE  /locate  /play-sound   GET /lost-mode
//	POST /devices/{id}/activation-lock/bypass-code      DELETE clears it on the device
//	POST /devices/{id}/filevault/rotate                 {"password": ""}: empty uses the stored recovery key
//	POST /devices/{id}/recovery-lock                    {"password": "", "clear": false}   (Apple silicon Macs)
//	POST /devices/{id}/firmware-password                same, for Intel Macs
type API struct {
	S         *Service
	Bootstrap BootstrapReader
}

func write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	var u ErrUnavailable
	switch {
	case errors.As(err, &u):
		write(w, 422, map[string]any{"error": err.Error()})
	case errors.Is(err, blueprints.ErrNotFound), errors.Is(err, mongo.ErrNoDocuments):
		write(w, 404, map[string]any{"error": "not found"})
	case errors.Is(err, vault.ErrNoReason):
		write(w, 400, map[string]any{"error": err.Error()})
	default:
		write(w, 500, map[string]any{"error": err.Error()})
	}
}

func body(r *http.Request, v any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v) == nil
}

// Handler returns the routes.
func (a *API) Handler(fallback http.Handler) http.Handler {
	s := a.S
	mux := http.NewServeMux()
	if fallback != nil {
		mux.Handle("/", fallback)
	}
	queued := func(w http.ResponseWriter, uuid string, err error) {
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 202, map[string]any{"command_uuid": uuid})
	}
	who := func(r *http.Request) string { return admin.Who(r.Context()) }

	mux.HandleFunc("GET /devices/{id}/secrets", func(w http.ResponseWriter, r *http.Request) {
		metas, err := s.Vault.List(r.Context(), r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		out := map[string]any{"secrets": metas}
		if a.Bootstrap != nil {
			if _, ok, err := a.Bootstrap.BootstrapTokenString(r.Context(), r.PathValue("id")); err == nil && ok {
				out["bootstrap_token"] = map[string]any{"escrowed": true}
			}
		}
		write(w, 200, out)
	})
	mux.HandleFunc("POST /devices/{id}/secrets/{kind}/reveal", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Reason  string `json:"reason"`
			Version int    `json:"version"`
		}
		if !body(r, &req) {
			write(w, 400, map[string]any{"error": "the body is not valid JSON"})
			return
		}
		id, kind := r.PathValue("id"), r.PathValue("kind")
		if kind == vault.BootstrapTokenEscrowed {
			if a.Bootstrap == nil {
				write(w, 501, map[string]any{"error": "the storage cannot read bootstrap tokens"})
				return
			}
			if req.Reason == "" {
				fail(w, vault.ErrNoReason)
				return
			}
			if err := s.Vault.Record(r.Context(), id, kind, "revealed", who(r), req.Reason); err != nil {
				fail(w, err)
				return
			}
			tok, ok, err := a.Bootstrap.BootstrapTokenString(r.Context(), id)
			if err != nil || !ok {
				fail(w, mongo.ErrNoDocuments)
				return
			}
			write(w, 200, map[string]any{"kind": kind, "value": tok})
			return
		}
		val, meta, err := s.Vault.Reveal(r.Context(), id, kind, req.Version, who(r), req.Reason)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"kind": kind, "version": meta.Version, "created_at": meta.CreatedAt, "value": val})
	})
	mux.HandleFunc("GET /devices/{id}/secrets/audit", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		rows, err := s.Vault.Audit(r.Context(), r.PathValue("id"), n)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"audit": rows})
	})

	mux.HandleFunc("POST /devices/{id}/lost-mode", func(w http.ResponseWriter, r *http.Request) {
		var req LostModeRequest
		if !body(r, &req) {
			write(w, 400, map[string]any{"error": "the body is not valid JSON"})
			return
		}
		u, err := s.EnableLostMode(r.Context(), r.PathValue("id"), who(r), req)
		queued(w, u, err)
	})
	mux.HandleFunc("DELETE /devices/{id}/lost-mode", func(w http.ResponseWriter, r *http.Request) {
		u, err := s.DisableLostMode(r.Context(), r.PathValue("id"), who(r))
		queued(w, u, err)
	})
	mux.HandleFunc("GET /devices/{id}/lost-mode", func(w http.ResponseWriter, r *http.Request) {
		d, err := s.device(r.Context(), r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"lost_mode": d.LostMode, "location": d.Location})
	})
	mux.HandleFunc("POST /devices/{id}/locate", func(w http.ResponseWriter, r *http.Request) {
		u, err := s.Locate(r.Context(), r.PathValue("id"), who(r))
		queued(w, u, err)
	})
	mux.HandleFunc("POST /devices/{id}/play-sound", func(w http.ResponseWriter, r *http.Request) {
		u, err := s.PlaySound(r.Context(), r.PathValue("id"), who(r))
		queued(w, u, err)
	})
	mux.HandleFunc("POST /devices/{id}/activation-lock/bypass-code", func(w http.ResponseWriter, r *http.Request) {
		u, err := s.RequestBypassCode(r.Context(), r.PathValue("id"), who(r))
		queued(w, u, err)
	})
	mux.HandleFunc("DELETE /devices/{id}/activation-lock/bypass-code", func(w http.ResponseWriter, r *http.Request) {
		u, err := s.ClearBypassCode(r.Context(), r.PathValue("id"), who(r))
		queued(w, u, err)
	})
	mux.HandleFunc("POST /devices/{id}/filevault/rotate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if !body(r, &req) {
			write(w, 400, map[string]any{"error": "the body is not valid JSON"})
			return
		}
		u, err := s.RotateFileVault(r.Context(), r.PathValue("id"), who(r), req.Password)
		queued(w, u, err)
	})
	lock := func(set func(ctx context.Context, device, by, pw string, clear bool) (string, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Password string `json:"password"`
				Clear    bool   `json:"clear"`
			}
			if !body(r, &req) {
				write(w, 400, map[string]any{"error": "the body is not valid JSON"})
				return
			}
			u, err := set(r.Context(), r.PathValue("id"), who(r), req.Password, req.Clear)
			queued(w, u, err)
		}
	}
	mux.HandleFunc("POST /devices/{id}/recovery-lock", lock(s.SetRecoveryLock))
	mux.HandleFunc("POST /devices/{id}/firmware-password", lock(s.SetFirmwarePassword))
	return mux
}
