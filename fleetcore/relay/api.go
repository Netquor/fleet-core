package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// API serves the event log and the subscriptions under /v1 (authentication is the caller's).
//
//	GET    /events/types                      every event type
//	GET    /events?after=&types=&key=&limit=  the log, oldest first, from a sequence number
//	GET    /events/stream                     the log as Server-Sent Events, live (Last-Event-ID or ?after= resumes)
//	GET    /event-subscriptions               list
//	POST   /event-subscriptions               create {name, url, types, from_seq}; the signing secret is returned once
//	GET    /event-subscriptions/{id}          one, with its cursor, lag and last error
//	PUT    /event-subscriptions/{id}          change name, url, types, enabled
//	DELETE /event-subscriptions/{id}
//	POST   /event-subscriptions/{id}/resume   continue a paused subscription from its cursor
//	POST   /event-subscriptions/{id}/replay   {from_seq} deliver again from a sequence number
//	POST   /event-subscriptions/{id}/test     send a test event now and report the answer
//	GET    /event-subscriptions/{id}/deliveries the latest attempts
type API struct {
	Store      *Store
	Dispatcher *Dispatcher
	// AllowPrivate allows subscription URLs on private, loopback and link-local addresses (and plain http there). By default a subscription cannot be aimed at the inside of the network.
	AllowPrivate bool
}

func write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) { write(w, code, map[string]any{"error": msg}) }

func isPrivate(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// SafeClient returns an HTTP client that refuses to connect to private addresses, checked at connection time on the address actually dialed (so a name that changes its answer, or a
// redirect, cannot reach the inside of the network).
func SafeClient(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		if allowPrivate {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || isPrivate(ip) {
			return fmt.Errorf("connections to %s are not allowed", host)
		}
		return nil
	}}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: d.DialContext, Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (a *API) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("the url is not valid")
	}
	if u.User != nil {
		return fmt.Errorf("the url must not carry a user name or password: the signature authenticates deliveries")
	}
	if u.Scheme != "https" && !(a.AllowPrivate && u.Scheme == "http") {
		return fmt.Errorf("the url must be https")
	}
	if !a.AllowPrivate {
		host := u.Hostname()
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("the host does not resolve: %v", err)
		}
		for _, ip := range ips {
			if isPrivate(ip) {
				return fmt.Errorf("the host resolves to a private address (%s)", ip)
			}
		}
	}
	return nil
}

type subRequest struct {
	Name    *string   `json:"name"`
	URL     *string   `json:"url"`
	Types   *[]string `json:"types"`
	Enabled *bool     `json:"enabled"`
	FromSeq *int64    `json:"from_seq"`
}

// Handler returns the routes.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /events/types", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"types": Catalog})
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
		n, _ := strconv.Atoi(q.Get("limit"))
		if n <= 0 || n > 1000 {
			n = 100
		}
		types := SplitList(q.Get("types"))
		if bad := ValidPatterns(types); bad != "" {
			fail(w, 422, fmt.Sprintf("%q matches no event type", bad))
			return
		}
		evs, err := a.Store.Events(r.Context(), after, types, q.Get("key"), n+1)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		next := int64(0)
		if len(evs) > n {
			evs = evs[:n]
			next = evs[n-1].Seq
		}
		last, _ := a.Store.LastSeq(r.Context())
		write(w, 200, map[string]any{"events": evs, "next": next, "last_seq": last})
	})
	mux.HandleFunc("GET /events/stream", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			fail(w, 500, "streaming is not supported here")
			return
		}
		q := r.URL.Query()
		after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
		if h := r.Header.Get("Last-Event-ID"); h != "" {
			after, _ = strconv.ParseInt(h, 10, 64)
		} else if q.Get("after") == "" {
			after, _ = a.Store.LastSeq(r.Context()) // a new listener sees what happens from now on
		}
		types := SplitList(q.Get("types"))
		if bad := ValidPatterns(types); bad != "" {
			fail(w, 422, fmt.Sprintf("%q matches no event type", bad))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		fl.Flush()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		beat := 0
		for {
			evs, err := a.Store.Events(r.Context(), after, types, q.Get("key"), 200)
			if err != nil {
				return
			}
			for _, e := range evs {
				b, _ := json.Marshal(e)
				fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.Seq, e.Type, b)
				after = e.Seq
			}
			if len(evs) > 0 {
				fl.Flush()
			} else if beat++; beat%15 == 0 {
				fmt.Fprint(w, ": keep-alive\n\n")
				fl.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
			}
		}
	})
	mux.HandleFunc("GET /event-subscriptions", func(w http.ResponseWriter, r *http.Request) {
		subs, err := a.Store.Subscriptions(r.Context())
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		last, _ := a.Store.LastSeq(r.Context())
		out := make([]map[string]any, len(subs))
		for i := range subs {
			out[i] = describe(&subs[i], last)
		}
		write(w, 200, map[string]any{"subscriptions": out})
	})
	mux.HandleFunc("POST /event-subscriptions", func(w http.ResponseWriter, r *http.Request) {
		var req subRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			fail(w, 400, "the body is not valid JSON: "+err.Error())
			return
		}
		if req.URL == nil {
			fail(w, 422, "url is required")
			return
		}
		if err := a.checkURL(*req.URL); err != nil {
			fail(w, 422, err.Error())
			return
		}
		sub := Subscription{URL: *req.URL}
		if req.Name != nil {
			sub.Name = *req.Name
		}
		if req.Types != nil {
			if bad := ValidPatterns(*req.Types); bad != "" {
				fail(w, 422, fmt.Sprintf("%q matches no event type", bad))
				return
			}
			sub.Types = *req.Types
		}
		made, secret, err := a.Store.CreateSubscription(r.Context(), sub, req.FromSeq)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		last, _ := a.Store.LastSeq(r.Context())
		d := describe(made, last)
		d["secret"] = secret // shown once
		write(w, 201, d)
	})
	get := func(w http.ResponseWriter, r *http.Request) *Subscription {
		sub, err := a.Store.Subscription(r.Context(), r.PathValue("id"))
		if err != nil {
			fail(w, 500, err.Error())
			return nil
		}
		if sub == nil {
			fail(w, 404, "no such subscription")
		}
		return sub
	}
	mux.HandleFunc("GET /event-subscriptions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if sub := get(w, r); sub != nil {
			last, _ := a.Store.LastSeq(r.Context())
			write(w, 200, describe(sub, last))
		}
	})
	mux.HandleFunc("PUT /event-subscriptions/{id}", func(w http.ResponseWriter, r *http.Request) {
		sub := get(w, r)
		if sub == nil {
			return
		}
		var req subRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			fail(w, 400, "the body is not valid JSON: "+err.Error())
			return
		}
		set := bson.D{}
		if req.Name != nil {
			set = append(set, bson.E{Key: "name", Value: *req.Name})
		}
		if req.URL != nil {
			if err := a.checkURL(*req.URL); err != nil {
				fail(w, 422, err.Error())
				return
			}
			set = append(set, bson.E{Key: "url", Value: *req.URL})
		}
		if req.Types != nil {
			if bad := ValidPatterns(*req.Types); bad != "" {
				fail(w, 422, fmt.Sprintf("%q matches no event type", bad))
				return
			}
			set = append(set, bson.E{Key: "types", Value: *req.Types})
		}
		if req.Enabled != nil {
			set = append(set, bson.E{Key: "enabled", Value: *req.Enabled})
		}
		if len(set) > 0 {
			if err := a.Store.UpdateSubscription(r.Context(), sub.ID, set); err != nil {
				fail(w, 500, err.Error())
				return
			}
		}
		sub, _ = a.Store.Subscription(r.Context(), sub.ID)
		last, _ := a.Store.LastSeq(r.Context())
		write(w, 200, describe(sub, last))
	})
	mux.HandleFunc("DELETE /event-subscriptions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if sub := get(w, r); sub != nil {
			if err := a.Store.DeleteSubscription(r.Context(), sub.ID); err != nil {
				fail(w, 500, err.Error())
				return
			}
			w.WriteHeader(204)
		}
	})
	mux.HandleFunc("POST /event-subscriptions/{id}/resume", func(w http.ResponseWriter, r *http.Request) {
		if sub := get(w, r); sub != nil {
			err := a.Store.UpdateSubscription(r.Context(), sub.ID, bson.D{{Key: "paused_reason", Value: ""}, {Key: "failures", Value: 0}, {Key: "next_attempt_at", Value: time.Time{}}, {Key: "enabled", Value: true}})
			if err != nil {
				fail(w, 500, err.Error())
				return
			}
			w.WriteHeader(204)
		}
	})
	mux.HandleFunc("POST /event-subscriptions/{id}/replay", func(w http.ResponseWriter, r *http.Request) {
		sub := get(w, r)
		if sub == nil {
			return
		}
		var req struct {
			FromSeq *int64 `json:"from_seq"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.FromSeq == nil || *req.FromSeq < 0 {
			fail(w, 422, "from_seq is required (events after it are delivered again; 0 is everything kept)")
			return
		}
		if err := a.Store.UpdateSubscription(r.Context(), sub.ID, bson.D{{Key: "cursor", Value: *req.FromSeq}}); err != nil {
			fail(w, 500, err.Error())
			return
		}
		w.WriteHeader(202)
	})
	mux.HandleFunc("POST /event-subscriptions/{id}/test", func(w http.ResponseWriter, r *http.Request) {
		sub := get(w, r)
		if sub == nil {
			return
		}
		secret, err := a.Store.OpenSecret(sub)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		e := Event{ID: "test." + strconv.FormatInt(time.Now().UnixNano(), 36), Type: "test", Key: sub.ID, Data: map[string]any{"subscription": sub.ID}, At: time.Now().UTC(), Origin: "fleetcore"}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		status, took, err := a.Dispatcher.deliver(ctx, sub, secret, e)
		out := map[string]any{"ok": err == nil, "status": status, "millis": took.Milliseconds()}
		if err != nil {
			out["error"] = err.Error()
		}
		write(w, 200, out)
	})
	mux.HandleFunc("GET /event-subscriptions/{id}/deliveries", func(w http.ResponseWriter, r *http.Request) {
		if sub := get(w, r); sub != nil {
			n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			d, err := a.Store.Deliveries(r.Context(), sub.ID, n)
			if err != nil {
				fail(w, 500, err.Error())
				return
			}
			write(w, 200, map[string]any{"deliveries": d})
		}
	})
	return mux
}

func describe(s *Subscription, last int64) map[string]any {
	b, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["behind"] = last - s.Cursor
	if m["behind"].(int64) < 0 {
		m["behind"] = int64(0)
	}
	m["state"] = "active"
	switch {
	case s.PausedReason != "":
		m["state"] = "paused"
	case !s.Enabled:
		m["state"] = "disabled"
	case s.Failures > 0:
		m["state"] = "failing"
	}
	_ = strings.TrimSpace
	return m
}
