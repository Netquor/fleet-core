package blueprints

import (
	"context"
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
func systemDeclarations(d *Device, org string) []ddm.Declaration {
	if ok, _ := declGate(d, typeStatusSubscriptions); !ok {
		return nil
	}
	set := schemas.Current()
	os := schemas.SchemaOS(d.Platform)
	var items []any
	for _, name := range statusItems {
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
	if org != "" {
		if ok, _ := declGate(d, typeOrgInfo); ok {
			out = append(out, ddm.Declaration{Identifier: "fc.org", Kind: ddm.KindManagement, Type: typeOrgInfo, Payload: map[string]any{"Name": org}, Source: "system"})
		}
	}
	return out
}

func declIdentifier(bp, item string) string { return "fc." + bp + "." + item }

// declarationFor compiles a "declaration" item: the configuration, and the activation that turns it on.
func declarationFor(bp *Blueprint, it Item) []ddm.Declaration {
	id := declIdentifier(bp.ID, it.ID)
	src := bp.ID + "/" + it.ID
	out := []ddm.Declaration{{Identifier: id, Kind: ddm.KindConfiguration, Type: it.DeclarationType, Payload: it.Declaration, Source: src}}
	if !it.NoActivation {
		out = append(out, ddm.Declaration{Identifier: id + ".act", Kind: ddm.KindActivation, Type: typeSimpleActivation, Payload: map[string]any{"StandardConfigurations": []any{id}}, Source: src})
	}
	return out
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
func (e *Engine) osUpdateFor(d *Device, bp *Blueprint, it Item) (decls []ddm.Declaration, target string, note string, applicable bool) {
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
	src := bp.ID + "/" + it.ID
	return []ddm.Declaration{
		{Identifier: id, Kind: ddm.KindConfiguration, Type: typeEnforceSpecific, Payload: payload, Source: src},
		{Identifier: id + ".act", Kind: ddm.KindActivation, Type: typeSimpleActivation, Payload: map[string]any{"StandardConfigurations": []any{id}}, Source: src},
	}, rel.Version, "install " + rel.Version + " by " + deadline, true
}

// OnStatus is the status channel: a device's report brings its inventory up to date and tells how its declarations fared. Connect it to ddm.Service.OnStatus.
func (e *Engine) OnStatus(ctx context.Context, device string, rep ddm.Report) {
	log := e.Logger
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
	statuses := rep.Declarations()
	if len(statuses) == 0 || e.DDM == nil {
		return
	}
	sources, err := e.DDM.BySource(ctx, device)
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

// legacyDeclarations wraps a profile as a legacy-profile declaration: the device downloads it from the server (with its device identity, like any MDM request) and installs it as if
// it had arrived by command, but under declarative management, so it follows the activation and reports status.
func legacyDeclarations(bp *Blueprint, it Item, profileURL string) []ddm.Declaration {
	id := declIdentifier(bp.ID, it.ID)
	src := bp.ID + "/" + it.ID
	return []ddm.Declaration{
		{Identifier: id, Kind: ddm.KindConfiguration, Type: typeLegacy, Payload: map[string]any{"ProfileURL": profileURL}, Source: src},
		{Identifier: id + ".act", Kind: ddm.KindActivation, Type: typeSimpleActivation, Payload: map[string]any{"StandardConfigurations": []any{id}}, Source: src},
	}
}
