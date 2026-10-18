package blueprints

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/micromdm/nanomdm/fleetcore/commands"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Prepare checks a blueprint and fills in what can be worked out: the profile identifiers, item IDs, defaults. Call it before saving.
func (b *Blueprint) Prepare() error {
	if !idPattern.MatchString(b.ID) {
		return fmt.Errorf("id must be 1-64 letters, digits, dot, dash or underscore")
	}
	if b.Name == "" {
		b.Name = b.ID
	}
	if err := b.Scope.Validate(); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	seen := map[string]bool{}
	for i := range b.Items {
		it := &b.Items[i]
		if it.ID == "" {
			it.ID = fmt.Sprintf("item-%d", i+1)
		}
		if !idPattern.MatchString(it.ID) || seen[it.ID] {
			return fmt.Errorf("item %q: id must be unique, letters, digits, dot, dash or underscore", it.ID)
		}
		seen[it.ID] = true
		switch it.Kind {
		case "profile":
			switch it.Delivery {
			case "", "auto", "profile", "declarative":
			default:
				return fmt.Errorf("item %s: delivery is auto, declarative or profile", it.ID)
			}
			id, err := ProfileIdentifier(it.Payload)
			if err != nil {
				return fmt.Errorf("item %s: %w", it.ID, err)
			}
			if it.Identifier != "" && it.Identifier != id {
				return fmt.Errorf("item %s: identifier %q does not match the profile's PayloadIdentifier %q", it.ID, it.Identifier, id)
			}
			it.Identifier = id
		case "command":
			cmd, ok := commands.Default().Get(it.RequestType)
			if !ok {
				return fmt.Errorf("item %s: unknown command %q", it.ID, it.RequestType)
			}
			if cmd.Destructive {
				return fmt.Errorf("item %s: %s can lose data or lock someone out and cannot be part of a blueprint", it.ID, it.RequestType)
			}
			if _, _, ps := commands.Build(cmd, it.Params, commands.Options{}); len(ps) > 0 {
				return fmt.Errorf("item %s: %s", it.ID, ps[0].Error())
			}
		case "declaration":
			def, ok := schemas.Current().Declaration(it.DeclarationType)
			if !ok || (def.Kind != "configuration" && def.Kind != "management") {
				return fmt.Errorf("item %s: %q is not a declarative management configuration or management type", it.ID, it.DeclarationType)
			}
			if def.Kind == "management" && it.Predicate != "" {
				return fmt.Errorf("item %s: a management declaration has no activation, so no predicate", it.ID)
			}
			if ps := commands.Check(def.Keys, it.Declaration, ""); len(ps) > 0 {
				return fmt.Errorf("item %s: %s", it.ID, ps[0].Error())
			}
			for _, ref := range assetRefs(it.Declaration) {
				found := false
				for _, other := range b.Items {
					found = found || (other.ID == ref && other.Kind == "asset")
				}
				if !found {
					return fmt.Errorf("item %s: refers to asset %q, which is not an asset item of this blueprint", it.ID, ref)
				}
			}
		case "asset":
			def, ok := schemas.Current().Declaration(it.DeclarationType)
			if !ok || def.Kind != "asset" {
				return fmt.Errorf("item %s: %q is not a declarative management asset type", it.ID, it.DeclarationType)
			}
			if len(it.AssetData) > 0 {
				hasRef := false
				for _, k := range def.Keys {
					hasRef = hasRef || k.Key == "Reference"
				}
				if !hasRef {
					return fmt.Errorf("item %s: %s carries its values in the declaration, not as data", it.ID, it.DeclarationType)
				}
				if it.ContentType == "" {
					return fmt.Errorf("item %s: content_type is required with asset_data", it.ID)
				}
			} else if ps := commands.Check(def.Keys, it.Declaration, ""); len(ps) > 0 {
				return fmt.Errorf("item %s: %s", it.ID, ps[0].Error())
			}
		case "os_update":
			t := it.Target
			if t == "" {
				it.Target = "latest-in-major"
			} else if t != "latest" && t != "latest-in-major" {
				if _, ok := schemas.VersionNum(t); !ok {
					return fmt.Errorf("item %s: target must be latest, latest-in-major or a version such as 27.0.1", it.ID)
				}
			}
			switch it.InstallAction {
			case "", "Default", "DownloadOnly", "InstallASAP", "NotifyOnly", "InstallLater", "InstallForceRestart":
			default:
				return fmt.Errorf("item %s: install_action is Default, DownloadOnly, InstallASAP, NotifyOnly, InstallLater or InstallForceRestart", it.ID)
			}
			if it.DeadlineDays < 0 || it.DeadlineDays > 365 {
				return fmt.Errorf("item %s: deadline_days is 0 to 365", it.ID)
			}
			if it.DeadlineHour != nil && (*it.DeadlineHour < 0 || *it.DeadlineHour > 23) {
				return fmt.Errorf("item %s: deadline_hour is 0 to 23", it.ID)
			}
		default:
			return fmt.Errorf("item %s: kind must be profile, command, declaration, asset or os_update", it.ID)
		}
		switch it.Scope {
		case "", "system":
		case "user":
			if it.Kind != "declaration" && it.Kind != "asset" && it.Kind != "os_update" {
				return fmt.Errorf("item %s: only declarative items can be user-scoped", it.ID)
			}
		default:
			return fmt.Errorf("item %s: scope is system or user", it.ID)
		}
	}
	for _, name := range b.StatusItems {
		if _, ok := schemas.Current().StatusItem(name); !ok {
			return fmt.Errorf("status_items: %q is not a status item in Apple's schema", name)
		}
	}
	last := 0
	rings := append([]Ring(nil), b.Rings...)
	sort.Slice(rings, func(i, j int) bool { return rings[i].Percent < rings[j].Percent })
	for _, r := range rings {
		if r.Percent < 1 || r.Percent > 100 || r.AfterSeconds < 0 {
			return fmt.Errorf("rings: percent is 1-100 and after_seconds is not negative")
		}
		if r.Percent == last {
			return fmt.Errorf("rings: two rings end at %d percent", r.Percent)
		}
		last = r.Percent
	}
	return nil
}
