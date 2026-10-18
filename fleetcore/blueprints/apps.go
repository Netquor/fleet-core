package blueprints

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/commands"
	"github.com/micromdm/nanomdm/fleetcore/ddm"
	"github.com/micromdm/plist"
)

const typeAppManaged = "com.apple.configuration.app.managed"

// appWant decides how an "app" item reaches one device: it gets the license first (an App Store app), then goes as a managed app declaration where the device takes it (with its
// configuration as an asset), or as the InstallApplication command.
func (e *Engine) appWant(ctx context.Context, d *Device, bp *Blueprint, it, oit Item, w *want, soonest func(time.Time), now time.Time) {
	w.hash = it.Hash()
	w.identifier = it.BundleID
	ue := d.UserEnrollment()

	// Which delivery can this device take?
	viable, whyNot := false, ""
	if e.DDM != nil && it.Delivery != "command" {
		okApp, why := declGate(d, typeAppManaged)
		okBase, whyBase := declGate(d, typeStatusSubscriptions)
		viable = okApp && okBase
		if !okApp {
			whyNot = why
		} else if !okBase {
			whyNot = whyBase
		}
	}
	if it.Delivery == "declarative" && !viable {
		if whyNot == "" {
			whyNot = "declarative management is not enabled on this server"
		}
		w.state, w.note, w.declarative = StateNA, "declarative delivery is not possible for this device: "+whyNot, false
		return
	}
	w.declarative = viable

	// An App Store app needs a license for the device. (User Enrollment has no serial number: the license is the person's, assigned through their Managed Apple Account.)
	if it.AdamID != "" && !ue {
		if e.Apps == nil {
			w.state, w.note = StateNA, "Apps and Books licensing is not configured on this server"
			return
		}
		ready, pending, err := e.Apps.EnsureLicense(ctx, it.VPPToken, it.AdamID, d.Serial, d.Platform)
		switch {
		case err != nil:
			w.state, w.note = StateNA, "no license: "+err.Error()
			soonest(now.Add(10 * time.Minute)) // licenses may be bought meanwhile
			return
		case !ready && pending:
			w.state, w.note = StateLicensing, "waiting for Apple to assign the license"
			soonest(now.Add(30 * time.Second))
			return
		}
	}

	if viable {
		id := declIdentifier(bp.ID, oit.ID)
		src := bp.ID + "/" + it.ID
		license := "Device"
		if ue {
			license = "User"
		}
		payload := map[string]any{}
		if it.AdamID != "" {
			payload["AppStoreID"] = it.AdamID
			payload["InstallBehavior"] = map[string]any{"Install": "Required", "License": map[string]any{"Assignment": license}}
		} else {
			payload["ManifestURL"] = it.ManifestURL
			payload["InstallBehavior"] = map[string]any{"Install": "Required"}
		}
		if it.BundleID != "" {
			payload["BundleID"] = it.BundleID
		}
		auto := it.AutoUpdate
		if auto == "" {
			auto = "StoreSettings"
		}
		payload["UpdateBehavior"] = map[string]any{"AutomaticAppUpdates": auto}
		var decls []ddm.Declaration
		if len(it.AppConfig) > 0 && e.BaseURL != "" {
			body, err := plist.MarshalIndent(it.AppConfig, "  ")
			if err == nil {
				sum := sha256.Sum256(body)
				key := hex.EncodeToString(sum[:6])
				w.blobs = append(w.blobs, blobSpec{key, "application/x-plist", body})
				decls = append(decls, ddm.Declaration{Identifier: id + ".config", Kind: ddm.KindAsset, Type: "com.apple.asset.data", Source: src, Payload: map[string]any{
					"Reference": map[string]any{"DataURL": strings.TrimRight(e.BaseURL, "/") + "/ddm/asset/" + key, "ContentType": "application/x-plist", "Size": int64(len(body)), "Hash-SHA-256": hex.EncodeToString(sum[:])}}})
				payload["AppConfig"] = map[string]any{"LegacyAppConfigAssetReference": id + ".config"}
			}
		}
		decls = append(decls,
			ddm.Declaration{Identifier: id, Kind: ddm.KindConfiguration, Type: typeAppManaged, Payload: payload, Source: src},
			ddm.Declaration{Identifier: id + ".act", Kind: ddm.KindActivation, Type: typeSimpleActivation, Payload: map[string]any{"StandardConfigurations": []any{id}}, Source: src})
		w.decls = decls
		w.cfgToken = primaryToken(decls)
		w.hash += "|decl|" + w.cfgToken
		return
	}

	// The command.
	var request string
	params := map[string]any{}
	switch {
	case it.AdamID != "":
		n, _ := strconv.ParseInt(it.AdamID, 10, 64)
		request = "InstallApplication"
		params["iTunesStoreID"] = n
		params["Options"] = map[string]any{"PurchaseMethod": int64(1)}
		if it.BundleID != "" {
			params["Identifier"] = it.BundleID
		}
	case d.Platform == "macOS":
		request = "InstallEnterpriseApplication"
		params["ManifestURL"] = it.ManifestURL
	default:
		request = "InstallApplication"
		params["ManifestURL"] = it.ManifestURL
	}
	params["ManagementFlags"] = int64(1)
	params["ChangeManagementState"] = "Managed"
	if d.Platform == "macOS" {
		params["InstallAsManaged"] = true
	}
	if len(it.AppConfig) > 0 {
		params["Configuration"] = it.AppConfig
	}
	cmd, _ := commandsGet(request)
	body, uuid, ps := commands.Build(cmd, params, commands.Options{Platform: d.Platform, OSVersion: d.OSVersion, UserEnrollment: ue})
	if len(ps) > 0 {
		w.state, w.note = StateNA, ps[0].Error()
		return
	}
	w.send, w.uuid = body, uuid
}
