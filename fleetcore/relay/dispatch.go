package relay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// MaxFailures is how many deliveries in a row may fail before a subscription pauses itself.
const MaxFailures = 25

// Dispatcher delivers the event log to the subscriptions, each in order from its own cursor, one event at a time, so a slow or broken endpoint holds back only itself.
// It runs on one process of the tenant at a time (a lease in the database) and starts from the saved cursors, so a restart or a takeover repeats at most one event.
type Dispatcher struct {
	Relay  *Relay // for the lease, the clock and hooks
	Store  *Store
	Client *http.Client
	// Interval is how often idle subscriptions are checked (default one second).
	Interval time.Duration
	mu       sync.Mutex
	busy     map[string]bool
}

func (d *Dispatcher) client() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Run delivers until the context ends.
func (d *Dispatcher) Run(ctx context.Context) {
	iv := d.Interval
	if iv == 0 {
		iv = time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if held, err := d.Relay.leaseNamed(ctx, "dispatch"); err != nil || !held {
			continue
		}
		subs, err := d.Store.Subscriptions(ctx)
		if err != nil {
			d.Relay.logf("subscriptions: %v", err)
			continue
		}
		last, _ := d.Store.LastSeq(ctx)
		for i := range subs {
			if d.Relay.Hooks.Lag != nil {
				d.Relay.Hooks.Lag(subs[i].ID, last-subs[i].Cursor)
			}
			// each subscription is served on its own, so one slow endpoint does not hold back the others; one at a time per subscription, to keep its order
			d.mu.Lock()
			busy := d.busy[subs[i].ID]
			if !busy {
				if d.busy == nil {
					d.busy = map[string]bool{}
				}
				d.busy[subs[i].ID] = true
			}
			d.mu.Unlock()
			if busy {
				continue
			}
			go func(sub Subscription) {
				defer func() { d.mu.Lock(); delete(d.busy, sub.ID); d.mu.Unlock() }()
				d.serve(ctx, &sub, last)
			}(subs[i])
		}
	}
}

// serve delivers a batch to one subscription.
func (d *Dispatcher) serve(ctx context.Context, sub *Subscription, last int64) {
	if !sub.Enabled || sub.PausedReason != "" || (!sub.NextAttemptAt.IsZero() && d.Relay.now().Before(sub.NextAttemptAt)) {
		return
	}
	evs, err := d.Store.Events(ctx, sub.Cursor, sub.Types, "", 50)
	if err != nil {
		return
	}
	if len(evs) == 0 {
		// nothing it selects since the cursor: move the cursor up to what existed before the look, so it is not scanned again
		if last > sub.Cursor {
			sub.Cursor = last
			_ = d.Store.UpdateSubscription(ctx, sub.ID, bson.D{{Key: "cursor", Value: last}})
		}
		return
	}
	secret, err := d.Store.OpenSecret(sub)
	if err != nil {
		d.Relay.logf("subscription %s secret: %v", sub.ID, err)
		return
	}
	// The cursor moves past events the subscription does not select, so it does not rescan them.
	for _, e := range evs {
		status, took, err := d.deliver(ctx, sub, secret, e)
		ok := err == nil
		d.Store.RecordDelivery(ctx, Delivery{Subscription: sub.ID, Seq: e.Seq, Event: e.Type, At: d.Relay.now(), Status: status, OK: ok, Error: errString(err), Millis: took.Milliseconds()})
		if d.Relay.Hooks.Delivery != nil {
			d.Relay.Hooks.Delivery(sub.ID, ok, status, took)
		}
		if ok {
			sub.Cursor, sub.Failures, sub.Delivered = e.Seq, 0, sub.Delivered+1
			_ = d.Store.UpdateSubscription(ctx, sub.ID, bson.D{{Key: "cursor", Value: e.Seq}, {Key: "failures", Value: 0}, {Key: "delivered", Value: sub.Delivered}, {Key: "last_success_at", Value: d.Relay.now()}, {Key: "next_attempt_at", Value: time.Time{}}})
			continue
		}
		sub.Failures++
		set := bson.D{{Key: "failures", Value: sub.Failures}, {Key: "last_error", Value: err.Error()}, {Key: "last_error_at", Value: d.Relay.now()}}
		if sub.Failures >= MaxFailures {
			set = append(set, bson.E{Key: "paused_reason", Value: fmt.Sprintf("paused after %d failed deliveries in a row: %v", sub.Failures, err)})
		} else {
			pause := time.Duration(1<<min(sub.Failures, 10)) * time.Second // 2s, 4s ... about 17 minutes
			set = append(set, bson.E{Key: "next_attempt_at", Value: d.Relay.now().Add(pause)})
		}
		_ = d.Store.UpdateSubscription(ctx, sub.ID, set)
		return
	}
	if len(evs) < 50 && last > sub.Cursor {
		// every selected event up to now was delivered: skip the ones it does not select
		sub.Cursor = last
		_ = d.Store.UpdateSubscription(ctx, sub.ID, bson.D{{Key: "cursor", Value: last}})
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// deliver posts one event: JSON body, X-Fleetcore-Event (id), X-Fleetcore-Seq, X-Fleetcore-Subscription and the HMAC signature.
func (d *Dispatcher) deliver(ctx context.Context, sub *Subscription, secret string, e Event) (int, time.Duration, error) {
	body, _ := json.Marshal(e)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.URL, bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fleetcore-Event", e.ID)
	req.Header.Set("X-Fleetcore-Seq", fmt.Sprint(e.Seq))
	req.Header.Set("X-Fleetcore-Subscription", sub.ID)
	ts := fmt.Sprint(d.Relay.now().Unix())
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "." + string(body)))
	req.Header.Set("X-Fleetcore-Timestamp", ts)
	req.Header.Set("X-Fleetcore-Signature", "sha256="+hex.EncodeToString(m.Sum(nil)))
	start := time.Now()
	resp, err := d.client().Do(req)
	if err != nil {
		return 0, time.Since(start), err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, time.Since(start), fmt.Errorf("the endpoint answered %d", resp.StatusCode)
	}
	return resp.StatusCode, time.Since(start), nil
}
