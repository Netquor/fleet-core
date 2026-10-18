package blueprints

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

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
				if err := checkAssetData(it.DeclarationType, it.ContentType, it.AssetData); err != nil {
					return fmt.Errorf("item %s: %w", it.ID, err)
				}
			} else if ps := commands.Check(def.Keys, it.Declaration, ""); len(ps) > 0 {
				return fmt.Errorf("item %s: %s", it.ID, ps[0].Error())
			}
		case "platform_sso":
			if err := validateSSO(*it); err != nil {
				return fmt.Errorf("item %s: %w", it.ID, err)
			}
			switch it.Delivery {
			case "", "auto", "declarative", "profile":
			default:
				return fmt.Errorf("item %s: delivery is auto, declarative or profile", it.ID)
			}
		case "app":
			if (it.AdamID == "") == (it.ManifestURL == "") {
				return fmt.Errorf("item %s: an app has an adam_id (App Store, licensed through Apps and Books) or a manifest_url (enterprise), not both", it.ID)
			}
			if it.AdamID != "" {
				for _, c := range it.AdamID {
					if c < '0' || c > '9' {
						return fmt.Errorf("item %s: adam_id is the App Store number of the app, digits only", it.ID)
					}
				}
				if it.VPPToken == "" {
					return fmt.Errorf("item %s: vpp_token names the stored Apps and Books token the licenses come from", it.ID)
				}
			} else if !strings.HasPrefix(it.ManifestURL, "https://") {
				return fmt.Errorf("item %s: manifest_url must be https", it.ID)
			}
			if it.BundleID == "" && !b.KeepOnLeave && it.ManifestURL != "" {
				return fmt.Errorf("item %s: bundle_id is needed to remove the app when a device leaves the scope (or set keep_on_leave)", it.ID)
			}
			switch it.AutoUpdate {
			case "", "AlwaysOn", "AlwaysOff", "StoreSettings":
			default:
				return fmt.Errorf("item %s: auto_update is AlwaysOn, AlwaysOff or StoreSettings", it.ID)
			}
			switch it.Delivery {
			case "", "auto", "declarative", "command":
			default:
				return fmt.Errorf("item %s: delivery is auto, declarative or command", it.ID)
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
			return fmt.Errorf("item %s: kind must be profile, command, declaration, asset, app, platform_sso or os_update", it.ID)
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

// checkAssetData checks the bytes behind an asset against what Apple says that asset type holds: a certificate is PEM or DER with that media type, and a credential
// asset (SCEP, ACME, identity, user name and password) is a JSON document with the keys of its credential schema.
func checkAssetData(assetType, contentType string, data []byte) error {
	if assetType == "com.apple.asset.credential.certificate" {
		if contentType != "application/pem" && contentType != "application/pkcs1" {
			return fmt.Errorf("a certificate asset is application/pem or application/pkcs1, not %s", contentType)
		}
		return nil
	}
	credType := strings.Replace(assetType, "com.apple.asset.credential.", "com.apple.credential.", 1)
	cred, ok := schemas.Current().Credential(credType)
	if !ok || credType == assetType {
		return nil
	}
	if contentType != "application/json" {
		return fmt.Errorf("a %s asset is a JSON document (application/json), not %s", assetType, contentType)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("the asset data is not a JSON object: %w", err)
	}
	if ps := commands.Check(cred.Keys, doc, ""); len(ps) > 0 {
		return fmt.Errorf("the asset data does not fit %s: %s", credType, ps[0].Error())
	}
	return nil
}
