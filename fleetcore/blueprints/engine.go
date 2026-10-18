package blueprints

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/fleetcore/applicability"
	"github.com/micromdm/nanomdm/fleetcore/commands"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/plist"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Enqueuer queues a command plist for devices and wakes them.
type Enqueuer interface {
	Enqueue(ctx context.Context, ids []string, commandPlist []byte) error
}

// Config tunes the engine; zero values are sensible.
type Config struct {
	// Workers reconcile devices in parallel (default 8).
	Workers int
	// DriftInterval is how often a device is looked at again with no event (default 6 hours).
	DriftInterval time.Duration
	// OSCheckInterval is how often a device is asked for its OS version (default 24 hours).
	OSCheckInterval time.Duration
	// Lease is how long a worker holds a device (default 2 minutes).
	Lease time.Duration
	// PendingTimeout is how long a command may wait for an answer before it is sent again (default 1 hour).
	PendingTimeout time.Duration
}

func (c *Config) defaults() {
	if c.Workers <= 0 {
		c.Workers = 8
	}
	if c.DriftInterval <= 0 {
		c.DriftInterval = 6 * time.Hour
	}
	if c.OSCheckInterval <= 0 {
		c.OSCheckInterval = 24 * time.Hour
	}
	if c.Lease <= 0 {
		c.Lease = 2 * time.Minute
	}
	if c.PendingTimeout <= 0 {
		c.PendingTimeout = time.Hour
	}
}

// Engine keeps devices matching their blueprints.
type Engine struct {
	Store    *Store
	Enq      Enqueuer
	Profiles *applicability.Registry
	Releases *osreleases.Catalog
	Logger   log.Logger
	Cfg      Config
	Now      func() time.Time

	mu       sync.Mutex
	cached   []compiled
	cachedAt time.Time
}

type compiled struct {
	bp    Blueprint
	scope Rule // expanded: no group tests, no "latest"
}

// New returns an engine.
func New(st *Store, enq Enqueuer, profiles *applicability.Registry, releases *osreleases.Catalog, logger log.Logger, cfg Config) *Engine {
	cfg.defaults()
	if logger == nil {
		logger = log.NopLogger
	}
	return &Engine{Store: st, Enq: enq, Profiles: profiles, Releases: releases, Logger: logger, Cfg: cfg, Now: func() time.Time { return time.Now().UTC() }}
}

// Env is what rules are made concrete with.
func (e *Engine) Env(ctx context.Context) (Env, error) {
	groups, err := e.Store.ListGroups(ctx)
	if err != nil {
		return Env{}, err
	}
	byName := make(map[string]*Group, len(groups)*2)
	for i := range groups {
		byName[groups[i].Name] = &groups[i]
		byName[groups[i].ID] = &groups[i]
	}
	return Env{Groups: func(n string) (*Group, bool) { g, ok := byName[n]; return g, ok }, Releases: e.Releases}, nil
}

// Invalidate drops the blueprint cache (after a change in this process).
func (e *Engine) Invalidate() {
	e.mu.Lock()
	e.cachedAt = time.Time{}
	e.mu.Unlock()
}

func (e *Engine) blueprints(ctx context.Context) ([]compiled, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cached != nil && e.Now().Sub(e.cachedAt) < 3*time.Second {
		return e.cached, nil
	}
	bps, err := e.Store.ListBlueprints(ctx, true)
	if err != nil {
		return nil, err
	}
	env, err := e.Env(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]compiled, 0, len(bps))
	for _, b := range bps {
		scope, err := b.Scope.Expand(env)
		if err != nil {
			e.Logger.Info("msg", "blueprint scope cannot be evaluated", "blueprint", b.Name, "err", err)
			continue
		}
		out = append(out, compiled{b, scope})
	}
	e.cached, e.cachedAt = out, e.Now()
	return out, nil
}

// Run claims due devices and reconciles them until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < e.Cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if !e.Once(ctx) {
					select {
					case <-ctx.Done():
					case <-time.After(time.Second):
					}
				}
			}
		}()
	}
	wg.Wait()
}

// Once claims and reconciles one due device; false when none was due.
func (e *Engine) Once(ctx context.Context) bool {
	now := e.Now()
	d, err := e.Store.Claim(ctx, now, e.Cfg.Lease)
	if err != nil {
		if ctx.Err() == nil {
			e.Logger.Info("msg", "claiming a device", "err", err)
		}
		return false
	}
	if d == nil {
		return false
	}
	next, err := e.Reconcile(ctx, d)
	if err != nil {
		e.Logger.Info("msg", "reconcile", "device", d.ID, "err", err)
		next = now.Add(time.Minute)
	}
	if err := e.Store.Release(ctx, d.ID, d.ReconcileAt, next); err != nil {
		e.Logger.Info("msg", "releasing a device", "device", d.ID, "err", err)
	}
	return true
}

type want struct {
	bp         *Blueprint
	item       Item
	identifier string
	hash       string
	state      string // "" to send, or StateNA
	note       string
	send       []byte // the command plist
	uuid       string
	held       bool // not yet this device's turn in a staged rollout
}

func appKey(bp, item string) string { return bp + "\x1f" + item }

func shortHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:6]) }

// bucket places a device in 0..99 for a blueprint, the same every time, so staged rollouts hit the same devices in the same order.
func bucket(blueprint, device string) int {
	h := fnv.New32a()
	h.Write([]byte(blueprint + "|" + device))
	return int(h.Sum32() % 100)
}

// eligibleAt is when a staged rollout reaches a device; ok false when the rings do not reach it at all.
func eligibleAt(bp *Blueprint, device string) (time.Time, bool) {
	if len(bp.Rings) == 0 {
		return bp.RolloutAt, true
	}
	rings := append([]Ring(nil), bp.Rings...)
	sort.Slice(rings, func(i, j int) bool { return rings[i].Percent < rings[j].Percent })
	b := bucket(bp.ID, device)
	for _, r := range rings {
		if b < r.Percent {
			return bp.RolloutAt.Add(time.Duration(r.AfterSeconds) * time.Second), true
		}
	}
	return time.Time{}, false
}

// Reconcile makes one device match its blueprints: it works out what the device should have, compares that with what has been sent and confirmed, and queues the difference.
// It is idempotent. It returns when the device should be looked at next.
func (e *Engine) Reconcile(ctx context.Context, d *Device) (time.Time, error) {
	now := e.Now()
	next := now.Add(e.Cfg.DriftInterval)
	soonest := func(t time.Time) {
		if t.After(now) && t.Before(next) {
			next = t
		}
	}
	bps, err := e.blueprints(ctx)
	if err != nil {
		return next, err
	}
	existing, err := e.Store.Applications(ctx, d.ID)
	if err != nil {
		return next, err
	}
	have := make(map[string]*Application, len(existing))
	for i := range existing {
		have[appKey(existing[i].Blueprint, existing[i].Item)] = &existing[i]
	}
	osCtx := d.Platform + " " + d.OSVersion

	// 1. what the device should have
	var wants []*want
	desiredKeys := map[string]bool{}
	desiredIdentifiers := map[string]bool{}
	for _, c := range bps {
		if !c.scope.Match(d) {
			continue
		}
		bp := c.bp
		at, reaches := eligibleAt(&bp, d.ID)
		held := !reaches || at.After(now)
		if reaches && held {
			soonest(at)
		}
		for _, it := range bp.Items {
			k := appKey(bp.ID, it.ID)
			w := &want{bp: &bp, item: it, held: held}
			switch it.Kind {
			case "profile":
				if desiredIdentifiers[it.Identifier] {
					continue // a higher-priority blueprint already puts this profile on the device
				}
				desiredIdentifiers[it.Identifier] = true
				w.identifier = it.Identifier
				res, err := e.Profiles.Apply(it.Payload, d.Platform, d.OSVersion)
				if err != nil {
					w.state, w.note, w.hash = StateNA, err.Error(), it.Hash()
					break
				}
				if len(res.LeftOut) > 0 {
					w.note = summarize(res.LeftOut)
				}
				if res.NotApplicable {
					w.state, w.hash = StateNA, it.Hash()+"|na"
					if w.note == "" {
						w.note = "nothing in this profile applies to " + osCtx
					}
					break
				}
				w.hash = it.Hash() + "|" + shortHash(res.Profile)
				cmd, _ := commandsGet("InstallProfile")
				body, uuid, ps := commands.Build(cmd, map[string]any{"Payload": base64.StdEncoding.EncodeToString(res.Profile)}, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion})
				if len(ps) > 0 {
					w.state, w.note = StateNA, ps[0].Error()
					break
				}
				w.send, w.uuid = body, uuid
			case "command":
				cmd, ok := commandsGet(it.RequestType)
				if !ok {
					w.state, w.note, w.hash = StateNA, "unknown command "+it.RequestType, it.Hash()
					break
				}
				w.hash = it.Hash()
				body, uuid, ps := commands.Build(cmd, it.Params, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion})
				if len(ps) > 0 {
					w.state, w.note = StateNA, ps[0].Error()
					break
				}
				w.send, w.uuid = body, uuid
			default:
				continue
			}
			desiredKeys[k] = true
			wants = append(wants, w)
		}
	}

	// 2. send what is missing or changed
	for _, w := range wants {
		k := appKey(w.bp.ID, w.item.ID)
		a := have[k]
		sameHash := a != nil && a.Hash == w.hash
		record := Application{Device: d.ID, Blueprint: w.bp.ID, Item: w.item.ID, Kind: w.item.Kind, Identifier: w.identifier, Hash: w.hash, Context: osCtx, Note: w.note}
		switch {
		case w.state == StateNA:
			if !sameHash || a.State != StateNA || a.Context != osCtx {
				record.State = StateNA
				if err := e.Store.PutApplication(ctx, record); err != nil {
					return next, err
				}
			}
			continue
		case sameHash && a.State == StateApplied:
			continue
		case sameHash && a.State == StatePending:
			if retry := a.UpdatedAt.Add(e.Cfg.PendingTimeout); retry.After(now) {
				soonest(retry)
				continue
			}
			record.Attempts = a.Attempts + 1
		case sameHash && a.State == StateFailed:
			retry := a.UpdatedAt.Add(5 * time.Minute << uint(a.Attempts))
			if a.Attempts >= 5 {
				continue // gave up; a change to the item or a manual retry starts over
			}
			if retry.After(now) {
				soonest(retry)
				continue
			}
			record.Attempts = a.Attempts + 1
		}
		if w.held {
			continue
		}
		if err := e.Enq.Enqueue(ctx, []string{d.ID}, w.send); err != nil {
			return next, fmt.Errorf("queueing %s: %w", w.item.ID, err)
		}
		record.State, record.CommandUUID = StatePending, w.uuid
		if err := e.Store.PutApplication(ctx, record); err != nil {
			return next, err
		}
		soonest(now.Add(e.Cfg.PendingTimeout))
	}

	// 3. take away what no blueprint wants any more
	for k, a := range have {
		if desiredKeys[k] {
			continue
		}
		keep := a.OrphanKeep
		if !keep {
			for _, c := range bps {
				if c.bp.ID == a.Blueprint {
					keep = c.bp.KeepOnLeave
				}
			}
		}
		removable := a.Kind == "profile" && a.Identifier != "" && !keep && !desiredIdentifiers[a.Identifier] && (a.State == StateApplied || a.State == StatePending || a.State == StateFailed || a.State == StateRemoving)
		if !removable {
			if err := e.Store.DeleteApplication(ctx, d.ID, a.Blueprint, a.Item); err != nil {
				return next, err
			}
			continue
		}
		if a.State == StateRemoving && a.UpdatedAt.Add(e.Cfg.PendingTimeout).After(now) {
			soonest(a.UpdatedAt.Add(e.Cfg.PendingTimeout))
			continue
		}
		cmd, _ := commandsGet("RemoveProfile")
		body, uuid, ps := commands.Build(cmd, map[string]any{"Identifier": a.Identifier}, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion})
		if len(ps) > 0 {
			return next, errors.New(ps[0].Error())
		}
		if err := e.Enq.Enqueue(ctx, []string{d.ID}, body); err != nil {
			return next, fmt.Errorf("queueing removal of %s: %w", a.Identifier, err)
		}
		a.State, a.CommandUUID = StateRemoving, uuid
		if err := e.Store.PutApplication(ctx, *a); err != nil {
			return next, err
		}
		soonest(now.Add(e.Cfg.PendingTimeout))
	}

	// 4. keep the device's OS version fresh: it decides what applies and which devices are out of date
	if d.Platform != "" && now.Sub(d.OSCheckedAt) >= e.Cfg.OSCheckInterval && now.Sub(d.OSQueryAt) >= 6*time.Hour {
		cmd, _ := commandsGet("DeviceInformation")
		body, _, ps := commands.Build(cmd, map[string]any{"Queries": []any{"OSVersion", "BuildVersion", "DeviceName", "ProductName", "Model", "SerialNumber"}}, commands.Options{Platform: d.Platform})
		if len(ps) == 0 {
			if err := e.Enq.Enqueue(ctx, []string{d.ID}, body); err == nil {
				_ = e.Store.SetDeviceFields(ctx, d.ID, bson.D{{Key: "os_query_at", Value: now}}, false)
			}
		}
	}
	return next, nil
}

func commandsGet(rt string) (*commands.Command, bool) { return commands.Default().Get(rt) }

func summarize(l []applicability.LeftOut) string {
	parts := make([]string, 0, len(l))
	for _, x := range l {
		if x.Key != "" {
			parts = append(parts, x.Payload+" "+x.Key)
		} else {
			parts = append(parts, x.Payload)
		}
	}
	if len(parts) > 6 {
		parts = append(parts[:6], fmt.Sprintf("and %d more", len(parts)-6))
	}
	return "left out for this platform: " + strings.Join(parts, ", ")
}

// ProfileIdentifier reads the PayloadIdentifier of a profile.
func ProfileIdentifier(payload []byte) (string, error) {
	var p struct {
		PayloadIdentifier string
		PayloadType       string
	}
	if err := plist.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("not a valid property list: %w", err)
	}
	if p.PayloadType != "Configuration" {
		return "", errors.New("not a configuration profile (PayloadType must be Configuration)")
	}
	if p.PayloadIdentifier == "" {
		return "", errors.New("the profile has no PayloadIdentifier")
	}
	return p.PayloadIdentifier, nil
}
