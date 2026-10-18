package blueprints

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	typeStatusSubscriptions = "com.apple.configuration.management.status-subscriptions"
	typeSimpleActivation    = "com.apple.activation.simple"
	typeEnforceSpecific     = "com.apple.configuration.softwareupdate.enforcement.specific"
	typeLegacy              = "com.apple.configuration.legacy"
	typeOrgInfo             = "com.apple.management.organization-info"
	typeCapabilities        = "com.apple.management.server-capabilities"
	typeProperties          = "com.apple.management.properties"
)

// statusItems are what every device is asked to report: enough to keep the inventory true, to know what the declarations did, and to follow a software update.
var statusItems = []string{
	"management.declarations",
	"device.operating-system.version", "device.operating-system.build-version", "device.operating-system.supplemental.build-version",
	"device.model.identifier", "device.identifier.serial-number",
	"softwareupdate.pending-version", "softwareupdate.install-state", "softwareupdate.failure-reason", "softwareupdate.install-reason",
}

// declGate says whether a declaration type can go to the device: Apple's schema must define it for the platform, from an OS version the device has, for the device's kind of enrollment.
// The returned text says why not.
func declGate(d *Device, declType string) (ok bool, why string) {
	def, found := schemas.Current().Declaration(declType)
	if !found {
		return true, "" // not in the schema in use: Apple may have just added it; the device decides
	}
	if d.Platform == "" {
		return false, "the device's platform is not known yet"
	}
	info, listed := def.OS[schemas.SchemaOS(d.Platform)]
	if !listed || info.Unsupported() {
		return false, fmt.Sprintf("%s does not exist on %s", def.Title, d.Platform)
	}
	if info.UnsupportedOn(d.OSVersion) {
		return false, fmt.Sprintf("%s was removed before %s %s", def.Title, d.Platform, d.OSVersion)
	}
	if have, ok := schemas.VersionNum(d.OSVersion); ok {
		if need, ok := schemas.VersionNum(info.Introduced); ok && have < need {
			return false, fmt.Sprintf("%s needs %s %s or later", def.Title, d.Platform, info.Introduced)
		}
	}
	if !info.AllowsEnrollment(d.EnrollKind()) {
		return false, fmt.Sprintf("%s is not available to a %s enrollment (it needs one of: %s)", def.Title, d.EnrollKind(), strings.Join(info.AllowedEnrollments, ", "))
	}
	return true, ""
}

// systemDeclarations are on every device that can take them: the status subscription, so the server hears what the device is running and what became of its declarations.
func systemDeclarations(d *Device, org string, extra []string) []ddm.Declaration {
	if ok, _ := declGate(d, typeStatusSubscriptions); !ok {
		return nil
	}
	set := schemas.Current()
	os := schemas.SchemaOS(d.Platform)
	var items []any
	seen := map[string]bool{}
	for _, name := range append(append([]string(nil), statusItems...), extra...) {
		if seen[name] {
			continue
		}
		seen[name] = true
		if def, ok := set.StatusItem(name); ok {
			info, listed := def.OS[os]
			if !listed || info.Unsupported() || !info.AllowsEnrollment(d.EnrollKind()) {
				continue
			}
			if have, ok := schemas.VersionNum(d.OSVersion); ok {
				if need, ok := schemas.VersionNum(info.Introduced); ok && have < need {
					continue
				}
			}
		}
		items = append(items, map[string]any{"Name": name})
	}
	out := []ddm.Declaration{
		{Identifier: "fc.status", Kind: ddm.KindConfiguration, Type: typeStatusSubscriptions, Payload: map[string]any{"StatusItems": items}, Source: "system"},
		{Identifier: "fc.status.act", Kind: ddm.KindActivation, Type: typeSimpleActivation, Payload: map[string]any{"StandardConfigurations": []any{"fc.status"}}, Source: "system"},
	}
	if ok, _ := declGate(d, typeCapabilities); ok {
		out = append(out, ddm.Declaration{Identifier: "fc.capabilities", Kind: ddm.KindManagement, Type: typeCapabilities, Payload: map[string]any{"Version": "1.0", "SupportedFeatures": map[string]any{}}, Source: "system"})
	}
	// Properties the device can use in activation predicates: what the server knows that the device does not (its tags and groups).
	if ok, _ := declGate(d, typeProperties); ok {
		tags, groups := []any{}, []any{}
		for _, t := range d.Tags {
			tags = append(tags, t)
		}
		for _, g := range d.Groups {
			groups = append(groups, g)
		}
		out = append(out, ddm.Declaration{Identifier: "fc.properties", Kind: ddm.KindManagement, Type: typeProperties, Payload: map[string]any{"tags": tags, "groups": groups}, Source: "system"})
	}
	if org != "" {
		if ok, _ := declGate(d, typeOrgInfo); ok {
			out = append(out, ddm.Declaration{Identifier: "fc.org", Kind: ddm.KindManagement, Type: typeOrgInfo, Payload: map[string]any{"Name": org}, Source: "system"})
		}
	}
	return out
}

func declIdentifier(bp, item string) string { return "fc." + bp + "." + item }

const assetPrefix = "$asset:"

// assetRefs lists the asset items a payload refers to ("$asset:<item id>" where an asset's identifier belongs).
func assetRefs(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, assetPrefix) {
			out = append(out, strings.TrimPrefix(t, assetPrefix))
		}
	case map[string]any:
		for _, e := range t {
			out = append(out, assetRefs(e)...)
		}
	case []any:
		for _, e := range t {
			out = append(out, assetRefs(e)...)
		}
	}
	return out
}

// resolveAssets replaces each "$asset:<item id>" with the identifier that asset has on the device.
func resolveAssets(v any, bp string) any {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, assetPrefix) {
			return declIdentifier(bp, strings.TrimPrefix(t, assetPrefix))
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = resolveAssets(e, bp)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = resolveAssets(e, bp)
		}
		return out
	}
	return v
}

// declarationFor compiles a "declaration" item: the configuration (or management declaration), and for a configuration the activation that turns it on.
// it carries the item's own ID (which names the declaration); src is the application record it belongs to (the same, plus the user for a user-scoped item).
func declarationFor(bp *Blueprint, it Item, src string) []ddm.Declaration {
	id := declIdentifier(bp.ID, it.ID)
	payload, _ := resolveAssets(it.Declaration, bp.ID).(map[string]any)
	if payload == nil {
		payload = map[string]any{}
	}
	kind := ddm.KindConfiguration
	if def, ok := schemas.Current().Declaration(it.DeclarationType); ok && def.Kind == "management" {
		kind = ddm.KindManagement
	}
	out := []ddm.Declaration{{Identifier: id, Kind: kind, Type: it.DeclarationType, Payload: payload, Source: bp.ID + "/" + src}}
	if kind == ddm.KindConfiguration && !it.NoActivation {
		act := map[string]any{"StandardConfigurations": []any{id}}
		if it.Predicate != "" {
			act["Predicate"] = it.Predicate
		}
		out = append(out, ddm.Declaration{Identifier: id + ".act", Kind: ddm.KindActivation, Type: typeSimpleActivation, Payload: act, Source: bp.ID + "/" + src})
	}
	return out
}

// assetDeclaration compiles an "asset" item. With data the server hosts it: the asset's Reference points at url and carries the size and hash the device checks.
func assetDeclaration(bp *Blueprint, it Item, src, url string) ddm.Declaration {
	payload := map[string]any{}
	for k, v := range it.Declaration {
		payload[k] = v
	}
	if len(it.AssetData) > 0 {
		sum := sha256.Sum256(it.AssetData)
		payload["Reference"] = map[string]any{"DataURL": url, "ContentType": it.ContentType, "Size": int64(len(it.AssetData)), "Hash-SHA-256": hex.EncodeToString(sum[:])}
	}
	return ddm.Declaration{Identifier: declIdentifier(bp.ID, it.ID), Kind: ddm.KindAsset, Type: it.DeclarationType, Payload: payload, Source: bp.ID + "/" + src}
}

// legacyDeclarations wraps a profile as a legacy-profile declaration: the device downloads it from the server (with its device identity, like any MDM request) and installs it as if
// it had arrived by command, but under declarative management, so it follows the activation and reports status. From OS 27 the profile can be an asset the device checks by size and hash
// (ProfileAssetReference); before that it is a URL.
func legacyDeclarations(bp *Blueprint, it Item, src, url string, body []byte, asAsset bool) []ddm.Declaration {
	id := declIdentifier(bp.ID, it.ID)
	cfg := map[string]any{"ProfileURL": url}
	var out []ddm.Declaration
	if asAsset {
		sum := sha256.Sum256(body)
		out = append(out, ddm.Declaration{Identifier: id + ".asset", Kind: ddm.KindAsset, Type: "com.apple.asset.data", Source: bp.ID + "/" + src, Payload: map[string]any{
			"Reference": map[string]any{"DataURL": url, "ContentType": "application/x-plist", "Size": int64(len(body)), "Hash-SHA-256": hex.EncodeToString(sum[:])}}})
		cfg = map[string]any{"ProfileAssetReference": id + ".asset"}
	}
	return append(out,
		ddm.Declaration{Identifier: id, Kind: ddm.KindConfiguration, Type: typeLegacy, Payload: cfg, Source: bp.ID + "/" + src},
		ddm.Declaration{Identifier: id + ".act", Kind: ddm.KindActivation, Type: typeSimpleActivation, Payload: map[string]any{"StandardConfigurations": []any{id}}, Source: bp.ID + "/" + src})
}

// supportsKey reports whether a declaration's key exists on the device's OS version (a key can be newer than the declaration).
func supportsKey(d *Device, declType, key string) bool {
	def, ok := schemas.Current().Declaration(declType)
	if !ok {
		return false
	}
	os := schemas.SchemaOS(d.Platform)
	for _, k := range def.Keys {
		if k.Key != key {
			continue
		}
		info, listed := k.OS[os]
		if !listed {
			return true // inherits the declaration's own support
		}
		if info.Unsupported() {
			return false
		}
		have, ok1 := schemas.VersionNum(d.OSVersion)
		need, ok2 := schemas.VersionNum(info.Introduced)
		return ok1 && ok2 && have >= need
	}
	return false
}

// scopeGate reports whether the declaration can be delivered to the "user" scope on this device's platform.
func scopeGate(d *Device, declType, scope string) bool {
	def, ok := schemas.Current().Declaration(declType)
	if !ok {
		return true
	}
	info, listed := def.OS[schemas.SchemaOS(d.Platform)]
	if !listed {
		return false
	}
	for _, s := range info.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return scope == "system" && len(info.AllowedScopes) == 0
}

// resolveTarget picks the release an os_update item moves this device to.
func (e *Engine) resolveTarget(d *Device, it Item) (rel osreleases.Release, found bool) {
	cur, _ := schemas.VersionNum(d.OSVersion)
	switch it.Target {
	case "latest":
		rel, found = e.Releases.BestFor(d.Platform, d.Model, 0)
	case "latest-in-major", "":
		rel, found = e.Releases.BestFor(d.Platform, d.Model, int(cur/1_000_000))
	default:
		num, _ := schemas.VersionNum(it.Target)
		rel, found = e.Releases.BestFor(d.Platform, d.Model, int(num/1_000_000))
		if found && rel.Version != it.Target {
			// The exact version asked for: it must be on offer for this device.
			found = false
			for _, r := range e.Releases.All() {
				if (r.Platform == d.Platform || d.Platform == "iPadOS" && r.Platform == "iOS") && r.Version == it.Target && e.Releases.Available(r.Platform, r.Version) {
					rel, found = r, true
					break
				}
			}
		}
	}
	return rel, found
}

// osUpdateFor compiles an "os_update" item for one device. decls is nil when the device needs nothing (already there, or no update is on offer); note says why.
func (e *Engine) osUpdateFor(d *Device, bp *Blueprint, it Item, src string) (decls []ddm.Declaration, target string, note string, applicable bool) {
	if ok, why := declGate(d, typeEnforceSpecific); !ok {
		return nil, "", why, false
	}
	cur, _ := schemas.VersionNum(d.OSVersion)
	rel, found := e.resolveTarget(d, it)
	if !found {
		return nil, "", "Apple offers no matching update for this device right now", true
	}
	if cur >= rel.Num {
		return nil, rel.Version, "already on " + d.OSVersion, true
	}
	days := it.DeadlineDays
	if days == 0 {
		days = 7 // unset
	}
	hour := 17
	if it.DeadlineHour != nil {
		hour = *it.DeadlineHour
	}
	base := rel.PublishedAt
	if bp.RolloutAt.After(base) {
		base = bp.RolloutAt
	}
	day := base.AddDate(0, 0, days)
	deadline := time.Date(day.Year(), day.Month(), day.Day(), hour, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05")
	payload := map[string]any{"TargetOSVersion": rel.Version, "TargetLocalDateTime": deadline}
	if it.DetailsURL != "" {
		payload["DetailsURL"] = it.DetailsURL
	}
	id := declIdentifier(bp.ID, it.ID)
	return []ddm.Declaration{
		{Identifier: id, Kind: ddm.KindConfiguration, Type: typeEnforceSpecific, Payload: payload, Source: bp.ID + "/" + src},
		{Identifier: id + ".act", Kind: ddm.KindActivation, Type: typeSimpleActivation, Payload: map[string]any{"StandardConfigurations": []any{id}}, Source: bp.ID + "/" + src},
	}, rel.Version, "install " + rel.Version + " by " + deadline, true
}

// OnStatus is the status channel: a device's report brings its inventory up to date and tells how its declarations fared. Connect it to ddm.Service.OnStatus.
func (e *Engine) OnStatus(ctx context.Context, enrollment string, rep ddm.Report) {
	log := e.Logger
	// A report from a user channel says how its declarations fared; the inventory is the device's, and the records are kept under the device.
	device := enrollment
	if parent, err := e.Store.ParentOf(ctx, enrollment); err == nil && parent != "" {
		device = parent
		e.recordDeclarationStatus(ctx, device, enrollment, rep)
		return
	}
	fields := bson.D{{Key: "os_checked_at", Value: e.Now()}}
	touch := false
	if v := rep.String("device.operating-system.version"); v != "" {
		if old, err := e.Store.GetDevice(ctx, device); err == nil && old.OSVersion != v {
			touch = true
		}
		fields = append(fields, bson.E{Key: "os_version", Value: v})
		if n, ok := schemas.VersionNum(v); ok {
			fields = append(fields, bson.E{Key: "os_num", Value: n})
		}
	}
	if v := rep.String("device.model.identifier"); v != "" {
		fields = append(fields, bson.E{Key: "model", Value: v})
		if p := PlatformOf(v); p != "" {
			fields = append(fields, bson.E{Key: "platform", Value: p})
		}
	}
	if v := rep.String("device.identifier.serial-number"); v != "" {
		fields = append(fields, bson.E{Key: "serial", Value: v})
	}
	if err := e.Store.SetDeviceFields(ctx, device, fields, touch); err != nil {
		log.Info("msg", "recording status", "device", device, "err", err)
	}
	e.recordDeclarationStatus(ctx, device, enrollment, rep)
}

// recordDeclarationStatus moves the applications of a channel on from what it reported: device is the device whose records they are, channel the enrollment that reported.
func (e *Engine) recordDeclarationStatus(ctx context.Context, device, channel string, rep ddm.Report) {
	log := e.Logger
	statuses := rep.Declarations()
	if len(statuses) == 0 || e.DDM == nil {
		return
	}
	sources, err := e.DDM.BySource(ctx, channel)
	if err != nil {
		log.Info("msg", "reading declarations", "device", device, "err", err)
		return
	}
	apps, err := e.Store.Applications(ctx, device)
	if err != nil {
		return
	}
	byKey := make(map[string]*Application, len(apps))
	for i := range apps {
		byKey[apps[i].Blueprint+"/"+apps[i].Item] = &apps[i]
	}
	for _, st := range statuses {
		src := sources[st.Identifier]
		a := byKey[src]
		if a == nil || a.ServerToken != st.ServerToken || strings.HasSuffix(st.Identifier, ".act") {
			continue // not ours, stale, or an activation (the configuration's state tells the story)
		}
		next, msg := StatePending, ""
		switch {
		case st.Valid == "invalid":
			next, msg = StateFailed, reasonText(st.Reasons)
		case st.Valid == "valid" && st.Active:
			next = StateApplied
		}
		if a.State != next || a.Error != msg {
			a.State, a.Error = next, msg
			if err := e.Store.PutApplication(ctx, *a); err != nil {
				log.Info("msg", "recording declaration status", "device", device, "err", err)
			}
		}
	}
}

func reasonText(rs []ddm.Reason) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.Description != "" {
			parts = append(parts, r.Description)
		} else {
			parts = append(parts, r.Code)
		}
	}
	if len(parts) == 0 {
		return "the device reported the declaration invalid"
	}
	return strings.Join(parts, "; ")
}
