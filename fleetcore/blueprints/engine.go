package blueprints

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"github.com/micromdm/plist"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// AppLicenser makes sure a device holds a license of an App Store app. ready: it does; pending: Apple is still doing it; err: it cannot be had.
type AppLicenser interface {
	EnsureLicense(ctx context.Context, token, adamID, serial, platform string) (ready, pending bool, err error)
}

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
	// AwaitTimeout is how long a device may wait in Setup Assistant for its Setup items before it is released anyway (default 30 minutes).
	AwaitTimeout time.Duration
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
	if c.AwaitTimeout <= 0 {
		c.AwaitTimeout = 30 * time.Minute
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
	// DDM, if set, enables declarative device management items (declarations and software updates).
	DDM *ddm.Store
	// Apps licenses App Store apps to devices (Apps and Books). Without it app items for App Store apps are not applicable.
	Apps AppLicenser
	// OnDEPDevice, if set, is told of each device Apple assigns to (or takes from) this server, before it enrolls. Work that can be done in advance (licensing an app to the serial
	// number) hangs here. removed is true when Apple took the device back.
	OnDEPDevice func(ctx context.Context, d DEPDevice, removed bool)
	// Observe, if set, is told how long each device's reconcile took and whether it failed (metrics).
	Observe func(d time.Duration, err error)
	// Organization names the organization to devices (the organization-info management declaration); empty sends none.
	Organization string
	// BaseURL is the server's public address; legacy-profile declarations point devices at it. Without it profiles are always delivered as MDM profiles.
	BaseURL string
	Logger  log.Logger
	Cfg     Config
	Now     func() time.Time

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
	started := time.Now()
	next, err := e.Reconcile(ctx, d)
	if e.Observe != nil {
		e.Observe(time.Since(started), err)
	}
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
	decls      []ddm.Declaration
	cfgToken   string
	// declarative: delivered through declarative management (a declaration, a software update, or a profile wrapped as a legacy-profile declaration).
	declarative bool
	blobs       []blobSpec // downloads the declarations point at (a legacy profile, an asset's data)
	needs       []string   // asset items (of the same blueprint) the declarations refer to
	user        string     // the user channel it goes to; empty for the device itself
	orig        string     // the item's own ID (it differs from item.ID for a user-scoped item, which has one record per user)
}

type blobSpec struct {
	key, contentType string
	body             []byte
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
	singleOwner := map[string]string{}
	extraStatus := map[string]bool{}
	for _, c := range bps {
		if !c.scope.Match(d) {
			continue
		}
		bp := c.bp
		for _, s := range bp.StatusItems {
			extraStatus[s] = true
		}
		at, reaches := eligibleAt(&bp, d.ID)
		held := !reaches || at.After(now)
		if reaches && held {
			soonest(at)
		}
		for _, ent := range expandItems(bp.Items, d) {
			it := ent.it
			oit := it // the item with its own ID: declaration identifiers come from it
			oit.ID = ent.orig
			k := appKey(bp.ID, it.ID)
			var ssoNote string
			if it.Kind == "platform_sso" {
				it, ssoNote = e.ssoAs(d, &bp, it)
				oit = it
				oit.ID = ent.orig
			}
			w := &want{bp: &bp, item: it, held: held, user: ent.user, orig: ent.orig}
			if ssoNote != "" {
				w.state, w.note, w.hash = StateNA, ssoNote, it.Hash()
				desiredKeys[k] = true
				wants = append(wants, w)
				continue
			}
			if ent.user == noUsers {
				w.state, w.note, w.hash, w.declarative = StateNA, "this device has no user channel enrolled yet", it.Hash(), true
				desiredKeys[k] = true
				wants = append(wants, w)
				continue
			}
			switch it.Kind {
			case "profile":
				if desiredIdentifiers[it.Identifier] {
					continue // a higher-priority blueprint already puts this profile on the device
				}
				desiredIdentifiers[it.Identifier] = true
				w.identifier = it.Identifier
				res, err := e.Profiles.Apply(it.Payload, d.Platform, d.OSVersion, d.profileOptions()...)
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
				if it.Delivery != "profile" && e.DDM != nil && e.BaseURL != "" {
					okLegacy, whyNot := declGate(d, typeLegacy)
					okBase, whyBase := declGate(d, typeStatusSubscriptions)
					switch {
					case okLegacy && okBase:
						key := shortHash(res.Profile)
						asAsset := supportsKey(d, typeLegacy, "ProfileAssetReference")
						base := strings.TrimRight(e.BaseURL, "/")
						ct, route := "application/x-apple-aspen-config", "/ddm/profile/"
						if asAsset {
							ct, route = "application/x-plist", "/ddm/asset/"
						}
						w.declarative, w.blobs = true, []blobSpec{{key, ct, res.Profile}}
						w.decls = legacyDeclarations(&bp, oit, it.ID, base+route+key, res.Profile, asAsset)
						w.cfgToken = primaryToken(w.decls)
						w.hash += "|decl|" + w.cfgToken
					case it.Delivery == "declarative":
						if !okLegacy {
							whyBase = whyNot
						}
						w.state, w.note = StateNA, "declarative delivery is not possible for this device: "+whyBase
					}
					if w.declarative || w.state == StateNA {
						break
					}
				}
				cmd, _ := commandsGet("InstallProfile")
				body, uuid, ps := commands.Build(cmd, map[string]any{"Payload": base64.StdEncoding.EncodeToString(res.Profile)}, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion, UserEnrollment: d.UserEnrollment()})
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
				body, uuid, ps := commands.Build(cmd, it.Params, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion, UserEnrollment: d.UserEnrollment()})
				if len(ps) > 0 {
					w.state, w.note = StateNA, ps[0].Error()
					break
				}
				w.send, w.uuid = body, uuid
			case "app":
				e.appWant(ctx, d, &bp, it, oit, w, soonest, now)
			case "declaration", "os_update", "asset":
				if e.DDM == nil {
					w.state, w.note, w.hash = StateNA, "declarative management is not enabled on this server", it.Hash()
					break
				}
				w.hash = it.Hash()
				w.declarative = true
				if it.Kind == "os_update" && ent.user == "" {
					// Where declarative enforcement is not possible the MDM command still works on an OS that has not removed it.
					okBase, _ := declGate(d, typeStatusSubscriptions)
					okEnf, _ := declGate(d, typeEnforceSpecific)
					if !okBase || !okEnf {
						_, body, uuid, target, note, ok := e.osUpdateCommand(d, it)
						if !ok && note != "" {
							_, why := declGate(d, typeEnforceSpecific)
							w.state, w.note = StateNA, why+"; "+note
							break
						}
						if ok {
							w.declarative = false
							w.hash += "|cmd|" + target
							w.note = note
							w.send, w.uuid = body, uuid
							if body == nil {
								w.state = StateApplied // nothing to send: already there, or nothing on offer
							}
							break
						}
					}
				}
				if ok, why := declGate(d, typeStatusSubscriptions); !ok {
					w.state, w.note = StateNA, "this device cannot take declarative management: "+why
					break
				}
				declType := it.DeclarationType
				if it.Kind == "os_update" {
					declType = typeEnforceSpecific
				}
				if ok, why := declGate(d, declType); !ok {
					w.state, w.note = StateNA, why
					break
				}
				if ent.user != "" && !scopeGate(d, declType, "user") {
					w.state, w.note = StateNA, declType+" cannot be delivered to a user channel on "+d.Platform
					break
				}
				if ent.user == "" && !scopeGate(d, declType, "system") {
					w.state, w.note = StateNA, declType+" is delivered to the user channel on "+d.Platform+": make the item user-scoped"
					break
				}
				switch it.Kind {
				case "declaration":
					// A type Apple allows only once per device: the higher-priority blueprint's wins (the device would report both invalid otherwise).
					if def, ok := schemas.Current().Declaration(it.DeclarationType); ok && def.Apply == "single" && ent.user == "" {
						if owner, taken := singleOwner[it.DeclarationType]; taken {
							w.state, w.note = StateNA, "conflicts with "+owner+": the device takes only one "+def.Title+" declaration"
							break
						}
						singleOwner[it.DeclarationType] = bp.ID + "/" + it.ID
					}
					w.needs = assetRefs(it.Declaration)
					w.decls = declarationFor(&bp, oit, it.ID)
				case "asset":
					if len(it.AssetData) > 0 {
						if e.BaseURL == "" {
							w.state, w.note = StateNA, "hosting asset data needs the server's public address"
							break
						}
						key := shortHash(it.AssetData)
						w.blobs = []blobSpec{{key, it.ContentType, it.AssetData}}
						w.decls = []ddm.Declaration{assetDeclaration(&bp, oit, it.ID, strings.TrimRight(e.BaseURL, "/")+"/ddm/asset/"+key)}
					} else {
						w.decls = []ddm.Declaration{assetDeclaration(&bp, oit, it.ID, "")}
					}
				default:
					decls, target, note, applicable := e.osUpdateFor(d, &bp, oit, it.ID)
					w.hash += "|" + target
					w.note = note
					if !applicable {
						w.state = StateNA
						break
					}
					w.decls = decls
					if len(decls) == 0 {
						w.state = StateApplied // nothing to enforce: the device is where it should be
					}
				}
				if w.state == "" {
					w.cfgToken = primaryToken(w.decls)
					w.hash += "|" + w.cfgToken
				}
			default:
				continue
			}
			desiredKeys[k] = true
			wants = append(wants, w)
		}
	}

	// A configuration that refers to an asset the device cannot take is itself not applicable.
	for _, w := range wants {
		for _, ref := range w.needs {
			for _, o := range wants {
				if o.bp.ID == w.bp.ID && o.orig == ref && o.user == w.user && o.state == StateNA {
					w.state, w.note, w.decls = StateNA, "needs asset "+ref+", which does not apply here: "+o.note, nil
				}
			}
		}
	}

	// 2a. declarations: the device's whole set is recomputed and compared with the stored one; only a difference is stored and the device told to sync
	if e.DDM != nil {
		if err := e.reconcileDeclarations(ctx, d, wants, have, osCtx, now, soonest, extraStatus); err != nil {
			return next, err
		}
	}

	// 2. send what is missing or changed
	for _, w := range wants {
		if w.declarative {
			continue
		}
		k := appKey(w.bp.ID, w.item.ID)
		a := have[k]
		sameHash := a != nil && a.Hash == w.hash
		record := Application{Device: d.ID, Blueprint: w.bp.ID, Item: w.item.ID, Kind: w.item.Kind, Identifier: w.identifier, Hash: w.hash, Delivery: "profile", Context: osCtx, Note: w.note}
		switch {
		case w.state == StateLicensing:
			record.State = StateLicensing
			if a == nil || a.State != StateLicensing || a.Note != w.note {
				if err := e.Store.PutApplication(ctx, record); err != nil {
					return next, err
				}
			}
			continue
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
		removable := (a.Kind == "profile" || a.Kind == "app") && a.Delivery != "declarative" && a.Identifier != "" && !keep && !(a.Kind == "profile" && desiredIdentifiers[a.Identifier]) && (a.State == StateApplied || a.State == StatePending || a.State == StateFailed || a.State == StateRemoving)
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
		removal := "RemoveProfile"
		if a.Kind == "app" {
			removal = "RemoveApplication"
		}
		cmd, _ := commandsGet(removal)
		body, uuid, ps := commands.Build(cmd, map[string]any{"Identifier": a.Identifier}, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion, UserEnrollment: d.UserEnrollment()})
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

	// 3b. a device held in Setup Assistant is released once what it waits for is done
	if d.Awaiting {
		if err := e.releaseIfReady(ctx, d, wants, now, soonest); err != nil {
			return next, err
		}
	}

	// 4. keep the device's OS version fresh: it decides what applies and which devices are out of date
	if d.Platform != "" && now.Sub(d.OSCheckedAt) >= e.Cfg.OSCheckInterval && now.Sub(d.OSQueryAt) >= 6*time.Hour {
		cmd, _ := commandsGet("DeviceInformation")
		body, _, ps := commands.Build(cmd, map[string]any{"Queries": []any{"OSVersion", "BuildVersion", "DeviceName", "ProductName", "Model", "SerialNumber", "IsSupervised"}}, commands.Options{Platform: d.Platform})
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

// noUsers marks a user-scoped item on a device that has no user channel (yet).
const noUsers = "\x00none"

type itemEntry struct {
	it   Item
	user string // the user channel; empty for the device
	orig string
}

// expandItems lists the items of a blueprint for one device: a user-scoped item once per user channel of the device (with its own record), the rest once.
func expandItems(items []Item, d *Device) []itemEntry {
	var out []itemEntry
	for _, it := range items {
		if it.Scope != "user" {
			out = append(out, itemEntry{it, "", it.ID})
			continue
		}
		if len(d.Users) == 0 {
			out = append(out, itemEntry{it, noUsers, it.ID})
			continue
		}
		for _, u := range d.Users {
			c := it
			c.ID = it.ID + "@" + u
			out = append(out, itemEntry{c, u, it.ID})
		}
	}
	return out
}

// primaryToken is the token that identifies what the device must report back as active: the configuration, or the asset or management declaration when there is no configuration.
func primaryToken(ds []ddm.Declaration) string {
	for _, k := range []string{ddm.KindConfiguration, ddm.KindAsset, ddm.KindManagement} {
		for _, d := range ds {
			if d.Kind == k {
				return d.Token()
			}
		}
	}
	return ""
}

// reconcileDeclarations stores each channel's declaration set (the device's, and each user channel's), records each declarative item's state, and tells a channel to sync when its set changed.
func (e *Engine) reconcileDeclarations(ctx context.Context, d *Device, wants []*want, have map[string]*Application, osCtx string, now time.Time, soonest func(time.Time), extraStatus map[string]bool) error {
	var extra []string
	for s := range extraStatus {
		extra = append(extra, s)
	}
	sort.Strings(extra)
	sets := map[string][]ddm.Declaration{"": systemDeclarations(d, e.Organization, extra)}
	for _, u := range d.Users {
		sets[u] = nil
	}
	var current map[string][]ddm.Declaration
	existing := func(target string) []ddm.Declaration {
		if current == nil {
			current = map[string][]ddm.Declaration{}
		}
		if _, ok := current[target]; !ok {
			current[target], _ = e.DDM.List(ctx, targetID(d, target))
		}
		return current[target]
	}
	for _, w := range wants {
		if !w.declarative {
			continue
		}
		k := appKey(w.bp.ID, w.item.ID)
		a := have[k]
		sameHash := a != nil && a.Hash == w.hash
		rec := Application{Device: d.ID, Blueprint: w.bp.ID, Item: w.item.ID, Kind: w.item.Kind, Identifier: w.identifier, Hash: w.hash, Delivery: "declarative", Context: osCtx, Note: w.note, ServerToken: w.cfgToken}
		// A profile already installed by command moves to declarative delivery by being removed first; the declaration follows once the device confirms.
		if w.item.Kind == "profile" && a != nil && a.Delivery != "declarative" && a.State != StateNA {
			if a.State != StateRemoving || a.UpdatedAt.Add(e.Cfg.PendingTimeout).Before(now) {
				cmd, _ := commandsGet("RemoveProfile")
				body, uuid, ps := commands.Build(cmd, map[string]any{"Identifier": w.identifier}, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion, UserEnrollment: d.UserEnrollment()})
				if len(ps) > 0 {
					return errors.New(ps[0].Error())
				}
				if err := e.Enq.Enqueue(ctx, []string{d.ID}, body); err != nil {
					return fmt.Errorf("queueing removal of %s: %w", w.identifier, err)
				}
				a.State, a.CommandUUID, a.Note = StateRemoving, uuid, "moving to declarative delivery"
				if err := e.Store.PutApplication(ctx, *a); err != nil {
					return err
				}
				soonest(now.Add(e.Cfg.PendingTimeout))
			}
			continue
		}
		switch {
		case w.state == StateLicensing:
			rec.State = StateLicensing
		case w.state == StateNA:
			rec.State = StateNA
		case w.state == StateApplied: // an update item for a device that is already there
			rec.State = StateApplied
		case w.held && !sameHash:
			// Not this device's turn for the change: leave what it has (the previous version of this item's declarations) in place.
			for _, c := range existing(w.user) {
				if c.Source == w.bp.ID+"/"+w.item.ID {
					sets[w.user] = append(sets[w.user], c)
				}
			}
			continue
		default:
			sets[w.user] = append(sets[w.user], w.decls...)
			if !sameHash || a.State == StateNA {
				for _, b := range w.blobs {
					if err := e.DDM.PutBlob(ctx, d.ID, b.key, b.contentType, b.body); err != nil {
						return err
					}
				}
			}
			rec.State = StatePending
			if sameHash {
				rec.State, rec.Error, rec.Attempts = a.State, a.Error, a.Attempts // the status channel moves it on
			}
		}
		if a == nil || a.Hash != rec.Hash || a.State != rec.State || a.Note != rec.Note || a.Context != rec.Context {
			if err := e.Store.PutApplication(ctx, rec); err != nil {
				return err
			}
		}
	}

	// Downloads still referred to by a declaration of this device stay available; the rest go.
	var keep []string
	for _, ds := range sets {
		for _, c := range ds {
			collectDownloadKeys(c.Payload, &keep)
		}
	}
	if err := e.DDM.PruneProfiles(ctx, d.ID, keep); err != nil {
		return err
	}

	for target, decls := range sets {
		if err := e.syncChannel(ctx, d, target, decls, now, soonest); err != nil {
			return err
		}
	}
	return nil
}

// targetID is the enrollment ID of a channel: the device's, or the user channel's.
func targetID(d *Device, target string) string {
	if target == "" {
		return d.ID
	}
	return target
}

// collectDownloadKeys finds the keys of server-hosted downloads referred to in a payload (URLs under /ddm/).
func collectDownloadKeys(v any, keys *[]string) {
	switch t := v.(type) {
	case string:
		if i := strings.Index(t, "/ddm/"); i >= 0 && strings.HasPrefix(t, "https://") {
			*keys = append(*keys, t[strings.LastIndex(t, "/")+1:])
		}
	case map[string]any:
		for _, e := range t {
			collectDownloadKeys(e, keys)
		}
	case []any:
		for _, e := range t {
			collectDownloadKeys(e, keys)
		}
	}
}

// syncChannel makes one channel's stored set exactly decls and, if it changed, tells that enrollment to sync.
func (e *Engine) syncChannel(ctx context.Context, d *Device, target string, decls []ddm.Declaration, now time.Time, soonest func(time.Time)) error {
	id := targetID(d, target)
	changed, st, err := e.DDM.Replace(ctx, id, decls)
	if err != nil {
		return err
	}
	if len(decls) == 0 && st.Token == "" {
		return nil // never had any: nothing to tell it
	}
	needNudge := changed || st.NotifiedToken != st.Token || (st.SyncedToken != st.Token && now.Sub(st.NotifiedAt) >= e.Cfg.PendingTimeout)
	if !needNudge {
		if st.SyncedToken != st.Token {
			soonest(st.NotifiedAt.Add(e.Cfg.PendingTimeout))
		}
		return nil
	}
	// The command carries the tokens (Apple allows this), so a channel that is already current skips its first round trip.
	tokens, _ := json.Marshal(map[string]any{"SyncTokens": map[string]any{"DeclarationsToken": st.Token, "Timestamp": st.UpdatedAt.UTC().Format(time.RFC3339)}})
	cmd, _ := commandsGet("DeclarativeManagement")
	body, _, ps := commands.Build(cmd, map[string]any{"Data": base64.StdEncoding.EncodeToString(tokens)}, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion, UserEnrollment: d.UserEnrollment()})
	if len(ps) > 0 {
		return errors.New(ps[0].Error())
	}
	if err := e.Enq.Enqueue(ctx, []string{id}, body); err != nil {
		return fmt.Errorf("telling %s to sync declarations: %w", id, err)
	}
	soonest(now.Add(e.Cfg.PendingTimeout))
	return e.DDM.Notified(ctx, id, st.Token)
}

// osUpdateCommand is the MDM fallback for a software update: a ScheduleOSUpdate command, for a device that cannot take declarative enforcement yet still has the command.
// body is nil when there is nothing to send (the device is already there, or Apple offers nothing); ok is false when the command is not available either.
func (e *Engine) osUpdateCommand(d *Device, it Item) (cmd *commands.Command, body []byte, uuid, target, note string, ok bool) {
	cmd, found := commandsGet("ScheduleOSUpdate")
	if !found {
		return nil, nil, "", "", "", false
	}
	info, listed := cmd.OS[schemas.SchemaOS(d.Platform)]
	if !listed || info.UnsupportedOn(d.OSVersion) {
		return nil, nil, "", "", "", false
	}
	if info.Supervised && (d.Supervised == nil || !*d.Supervised) {
		return nil, nil, "", "", "ScheduleOSUpdate needs a supervised " + d.Platform + " device", false
	}
	rel, found := e.resolveTarget(d, it)
	if !found {
		return cmd, nil, "", "", "Apple offers no matching update for this device right now", true
	}
	cur, _ := schemas.VersionNum(d.OSVersion)
	if cur >= rel.Num {
		return cmd, nil, "", rel.Version, "already on " + d.OSVersion, true
	}
	action := it.InstallAction
	if action == "" {
		action = "Default"
	}
	body, uuid, ps := commands.Build(cmd, map[string]any{"Updates": []any{map[string]any{"ProductVersion": rel.Version, "InstallAction": action}}}, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion, UserEnrollment: d.UserEnrollment()})
	if len(ps) > 0 {
		return cmd, nil, "", "", ps[0].Error(), false
	}
	return cmd, body, uuid, rel.Version, "ScheduleOSUpdate " + rel.Version + " (" + action + "): this device cannot take declarative enforcement", true
}

// releaseIfReady sends DeviceConfigured to a device waiting in Setup Assistant when every Setup item is applied, not applicable or failed for good, or the wait ran out.
func (e *Engine) releaseIfReady(ctx context.Context, d *Device, wants []*want, now time.Time, soonest func(time.Time)) error {
	apps, err := e.Store.Applications(ctx, d.ID)
	if err != nil {
		return err
	}
	state := map[string]*Application{}
	for i := range apps {
		state[appKey(apps[i].Blueprint, apps[i].Item)] = &apps[i]
	}
	waiting := 0
	for _, w := range wants {
		if !w.item.Setup {
			continue
		}
		a := state[appKey(w.bp.ID, w.item.ID)]
		done := a != nil && (a.State == StateApplied || a.State == StateNA || (a.State == StateFailed && a.Attempts >= 3))
		if !done {
			waiting++
		}
	}
	timedOut := !d.AwaitingSince.IsZero() && now.Sub(d.AwaitingSince) >= e.Cfg.AwaitTimeout
	if waiting > 0 && !timedOut {
		soonest(now.Add(30 * time.Second))
		return nil
	}
	cmd, _ := commandsGet("DeviceConfigured")
	body, _, ps := commands.Build(cmd, map[string]any{}, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion, UserEnrollment: d.UserEnrollment()})
	if len(ps) > 0 {
		// not a command this device has: it cannot be waiting on it
		return e.Store.SetDeviceFields(ctx, d.ID, bson.D{{Key: "awaiting", Value: false}}, false)
	}
	if err := e.Enq.Enqueue(ctx, []string{d.ID}, body); err != nil {
		return fmt.Errorf("releasing the device from Setup Assistant: %w", err)
	}
	return e.Store.SetDeviceFields(ctx, d.ID, bson.D{{Key: "awaiting", Value: false}, {Key: "released_at", Value: now}}, false)
}

// DEPDeviceEvent records a device Apple assigned (or took back) and tells whoever waits for it. The device is also looked at again if it is already enrolled.
func (e *Engine) DEPDeviceEvent(ctx context.Context, d DEPDevice, removed bool) {
	var err error
	if removed {
		err = e.Store.ForgetDEP(ctx, d.Serial)
	} else {
		err = e.Store.RecordDEP(ctx, d)
	}
	if err != nil {
		e.Logger.Info("msg", "recording a DEP device", "serial", d.Serial, "err", err)
		return
	}
	if !removed {
		// an enrolled device with this serial learns its DEP name now
		_, _ = e.Store.db.Collection(cDevices).UpdateMany(ctx, e.Store.scope(bson.D{{Key: "serial", Value: d.Serial}}), bson.D{{Key: "$set", Value: bson.D{{Key: "dep_name", Value: d.DEPName}, {Key: "reconcile_at", Value: e.Now()}}}})
	}
	if e.OnDEPDevice != nil {
		e.OnDEPDevice(ctx, d, removed)
	}
}

// PreLicense gets ready a device Apple has just assigned to this server, before it enrolls: the licenses of the App Store apps the blueprints will give it are assigned to its serial number
// now, so they are in place when it comes out of Setup Assistant. Only blueprints whose scope can already be decided from what Apple says (DEP name, model, serial) count.
func (e *Engine) PreLicense(ctx context.Context, dd DEPDevice) {
	if e.Apps == nil {
		return
	}
	bps, err := e.blueprints(ctx)
	if err != nil {
		return
	}
	d := &Device{ID: "pre:" + dd.Serial, Serial: dd.Serial, Model: dd.Model, DEPName: dd.DEPName, Platform: depPlatform(dd), Active: true}
	for _, c := range bps {
		if !c.scope.Match(d) {
			continue
		}
		for _, it := range c.bp.Items {
			if it.Kind == "app" && it.AdamID != "" && it.VPPToken != "" {
				if _, _, err := e.Apps.EnsureLicense(ctx, it.VPPToken, it.AdamID, dd.Serial, d.Platform); err != nil {
					e.Logger.Info("msg", "pre-licensing", "serial", dd.Serial, "adam_id", it.AdamID, "err", err)
				}
			}
		}
	}
}

// depPlatform names the platform of a device Apple assigned: DEP says "OSX" for a Mac, and the model tells an iPad from an iPhone.
func depPlatform(d DEPDevice) string {
	switch strings.ToLower(d.OS) {
	case "osx", "macos":
		return "macOS"
	case "tvos":
		return "tvOS"
	case "visionos":
		return "visionOS"
	}
	if p := PlatformOf(d.Model); p != "" {
		return p
	}
	if strings.EqualFold(d.OS, "ios") {
		if strings.Contains(strings.ToLower(d.Model), "ipad") {
			return "iPadOS"
		}
		return "iOS"
	}
	return ""
}

// ssoAs turns a Platform SSO item into what this device takes: a declaration where it has declarative management, a profile otherwise. A non-empty note says it does not apply.
func (e *Engine) ssoAs(d *Device, bp *Blueprint, it Item) (Item, string) {
	payload, err := SSOPayload(it)
	if err != nil {
		return it, err.Error()
	}
	if _, has := payload["PlatformSSO"]; has && d.Platform != "macOS" {
		return it, "Platform SSO is for Macs; " + d.Platform + " takes the extension without it"
	}
	okDecl, _ := declGate(d, typeExtensibleSSO)
	okBase, _ := declGate(d, typeStatusSubscriptions)
	out := it
	if e.DDM != nil && it.Delivery != "profile" && okDecl && okBase {
		decl, _ := SSODeclaration(payload, d.Platform)
		out.Kind, out.DeclarationType, out.Declaration = "declaration", typeExtensibleSSO, decl
		return out, ""
	}
	if it.Delivery == "declarative" {
		return it, "declarative delivery is not possible for this device"
	}
	identifier := "fc.sso." + bp.ID + "." + it.ID
	prof, err := ssoProfile(identifier, payload)
	if err != nil {
		return it, err.Error()
	}
	out.Kind, out.Payload, out.Identifier, out.Delivery = "profile", prof, identifier, "profile"
	return out, ""
}
