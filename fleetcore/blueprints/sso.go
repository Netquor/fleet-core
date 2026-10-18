package blueprints

import (
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/micromdm/nanomdm/fleetcore/commands"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"github.com/micromdm/plist"
)

const typeExtensibleSSO = "com.apple.configuration.extensible-sso"

//go:embed sso_presets.json
var ssoPresetsJSON []byte

// SSOPreset is a starting point for an identity provider's single sign-on extension: the part that is the same for everyone (the extension, its team, the hosts it signs in for).
type SSOPreset struct {
	Title string `json:"title"`
	// Parameters the preset needs from the administrator, replacing {{name}} in its values.
	Parameters []string       `json:"parameters,omitempty"`
	Note       string         `json:"note,omitempty"`
	Payload    map[string]any `json:"payload"`
}

// SSOPresets lists the presets built in.
func SSOPresets() map[string]SSOPreset {
	m := map[string]SSOPreset{}
	_ = json.Unmarshal(ssoPresetsJSON, &m)
	return m
}

var placeholder = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)

func substitute(v any, params map[string]string, missing map[string]bool) any {
	switch t := v.(type) {
	case string:
		return placeholder.ReplaceAllStringFunc(t, func(m string) string {
			name := placeholder.FindStringSubmatch(m)[1]
			if val, ok := params[name]; ok {
				return val
			}
			missing[name] = true
			return m
		})
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = substitute(e, params, missing)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = substitute(e, params, missing)
		}
		return out
	}
	return v
}

// merge lays over on top of base: dictionaries merge key by key, anything else is replaced.
func merge(base, over map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if bm, ok := out[k].(map[string]any); ok {
			if om, ok := v.(map[string]any); ok {
				out[k] = merge(bm, om)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// SSOPayload makes the extensible single sign-on payload an item stands for: its preset (if any) with the parameters filled in, then the item's own settings on top.
func SSOPayload(it Item) (map[string]any, error) {
	base := map[string]any{}
	if it.Preset != "" {
		p, ok := SSOPresets()[it.Preset]
		if !ok {
			return nil, fmt.Errorf("no single sign-on preset called %q", it.Preset)
		}
		missing := map[string]bool{}
		base, _ = substitute(p.Payload, it.Parameters, missing).(map[string]any)
		if len(missing) > 0 {
			var names []string
			for n := range missing {
				names = append(names, n)
			}
			return nil, fmt.Errorf("the %s preset needs the parameters: %s", it.Preset, strings.Join(names, ", "))
		}
	}
	return merge(base, it.SSO), nil
}

func validateSSO(it Item) error {
	payload, err := SSOPayload(it)
	if err != nil {
		return err
	}
	if _, ok := payload["ExtensionIdentifier"].(string); !ok {
		return fmt.Errorf("no extension: give a preset, or sso.ExtensionIdentifier")
	}
	// The settings are written in the shape of the profile payload, which every version takes; the declaration (macOS 27) is derived from them.
	def, ok := schemas.Current().Profile("com.apple.extensiblesso")
	if !ok {
		return nil
	}
	if ps := commands.Check(def.Keys, payload, ""); len(ps) > 0 {
		return fmt.Errorf("%s", ps[0].Error())
	}
	if _, dropped := SSODeclaration(payload, "macOS"); len(dropped) > 0 {
		return fmt.Errorf("%s cannot be expressed in the declaration form; leave it out or deliver this item as a profile", strings.Join(dropped, ", "))
	}
	return nil
}

// platformSSOMap says where each flat Platform SSO setting of the profile lives in the declaration's groups.
var platformSSOMap = map[string][2]string{
	"AccountDisplayName": {"Account", "DisplayName"}, "SynchronizeProfilePicture": {"Account", "SynchronizeProfilePicture"},
	"EnableCreateUserAtLogin": {"UserCreation", "EnableAtLogin"}, "EnableCreateFirstUserDuringSetup": {"UserCreation", "EnableFirstUserDuringSetup"},
	"EnableRegistrationDuringSetup": {"UserCreation", "EnableRegistrationDuringSetup"}, "NewUserAuthenticationMethods": {"UserCreation", "NewUserAuthenticationMethods"},
	"NewUserAuthorizationMode": {"UserCreation", "NewUserAuthorizationMode"}, "TokenToUserMapping": {"UserCreation", "TokenToUserMapping"}, "TemporarySessionQuickLogin": {"UserCreation", "TemporarySessionQuickLogin"},
	"EnableAuthorization": {"Authorization", "EnableIdentityProviderAccounts"}, "UserAuthorizationMode": {"Authorization", "UserAuthorizationMode"},
	"AdministratorGroups": {"Authorization", "AdministratorGroups"}, "AdditionalGroups": {"Authorization", "AdditionalGroups"}, "AuthorizationGroups": {"Authorization", "AuthorizationGroups"},
	"AccessKeyReaderGroupIdentifier": {"AccessKey", "ReaderGroupIdentifier"}, "AllowAccessKeyExpressMode": {"AccessKey", "AllowExpressMode"},
	"FileVaultPolicy": {"Policies", "FileVault"}, "LoginPolicy": {"Policies", "Login"}, "UnlockPolicy": {"Policies", "Unlock"},
	"OfflineGracePeriod": {"Policies", "OfflineGracePeriod"}, "AuthenticationGracePeriod": {"Policies", "AuthenticationGracePeriod"}, "NonPlatformSSOAccounts": {"Policies", "NonPlatformSSOAccounts"},
	"WebLoginURLAllowList": {"WebAuthentication", "URLAllowList"}, "AllowWebLoginPasswordSync": {"WebAuthentication", "AllowPasswordSync"},
}

// platformSSOSame are settings that keep their name and place.
var platformSSOSame = map[string]bool{"AuthenticationMethod": true, "RegistrationToken": true, "UseSharedDeviceKeys": true, "LoginFrequency": true, "AllowDeviceIdentifiersInAttestation": true}

// SSODeclaration expresses the flat, profile-shaped single sign-on settings as the extensible SSO declaration (macOS 27): the extension named by its composed identifier, and the Platform
// SSO settings gathered into the groups the declaration uses. dropped lists settings the declaration has no place for.
func SSODeclaration(flat map[string]any, platform string) (decl map[string]any, dropped []string) {
	decl = map[string]any{}
	for k, v := range flat {
		switch k {
		case "ExtensionIdentifier", "TeamIdentifier", "PlatformSSO", "AuthenticationMethod", "RegistrationToken":
		default:
			decl[k] = v
		}
	}
	bundle, _ := flat["ExtensionIdentifier"].(string)
	team, _ := flat["TeamIdentifier"].(string)
	if platform == "macOS" && team != "" {
		decl["ExtensionComposedIdentifier"] = bundle + " (" + team + ")"
	} else {
		decl["ExtensionComposedIdentifier"] = bundle
	}
	pso := map[string]any{}
	// the two older top-level spellings
	for _, k := range []string{"AuthenticationMethod", "RegistrationToken"} {
		if v, ok := flat[k]; ok {
			pso[k] = v
		}
	}
	if src, ok := flat["PlatformSSO"].(map[string]any); ok {
		for k, v := range src {
			switch {
			case platformSSOSame[k]:
				pso[k] = v
			case platformSSOMap[k] != [2]string{}:
				g, name := platformSSOMap[k][0], platformSSOMap[k][1]
				group, _ := pso[g].(map[string]any)
				if group == nil {
					group = map[string]any{}
					pso[g] = group
				}
				group[name] = v
			default:
				dropped = append(dropped, "PlatformSSO."+k)
			}
		}
	}
	if len(pso) > 0 {
		decl["PlatformSSO"] = pso
	}
	return decl, dropped
}

// ssoProfile wraps the payload as a configuration profile, for devices that take it as a profile (the identifiers are derived from the item, so the profile is the same every time).
func ssoProfile(identifier string, payload map[string]any) ([]byte, error) {
	uuid := func(s string) string {
		h := sha256.Sum256([]byte(s))
		return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16]))
	}
	inner := map[string]any{"PayloadType": "com.apple.extensiblesso", "PayloadVersion": 1, "PayloadIdentifier": identifier + ".sso", "PayloadUUID": uuid(identifier + ".sso"), "PayloadDisplayName": "Single sign-on"}
	for k, v := range payload {
		inner[k] = v
	}
	return plist.MarshalIndent(map[string]any{
		"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": identifier, "PayloadUUID": uuid(identifier), "PayloadDisplayName": "Single sign-on",
		"PayloadContent": []any{inner},
	}, "  ")
}
