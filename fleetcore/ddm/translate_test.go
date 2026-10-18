package ddm

import (
	"strings"
	"testing"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

func TestTranslateNestedAndValues(t *testing.T) {
	set := schemas.Embedded()
	tr, ok := Translate("com.apple.mail.managed", map[string]any{
		"EmailAccountDescription":          "Work",
		"EmailAccountType":                 "EmailTypeIMAP",
		"IncomingMailServerHostName":       "imap.example.com",
		"IncomingMailServerPortNumber":     uint64(993),
		"IncomingMailServerAuthentication": "EmailAuthPassword",
		"IncomingPassword":                 "x",
		"SMIMESigningEnabled":              true,
		"PreventMove":                      true,
	}, "", set)
	if !ok {
		t.Fatal("no translation")
	}
	in, _ := tr.Payload["IncomingServer"].(map[string]any)
	if tr.Payload["VisibleName"] != "Work" || in["ServerType"] != "IMAP" || in["HostName"] != "imap.example.com" || in["Port"] != int64(993) || in["AuthenticationMethod"] != "Password" {
		t.Errorf("payload %v", tr.Payload)
	}
	sm, _ := tr.Payload["SMIME"].(map[string]any)
	if sg, _ := sm["Signing"].(map[string]any); sg["Enabled"] != true {
		t.Errorf("smime %v", sm)
	}
	if !strings.Contains(tr.Reasons["IncomingPassword"], "asset") || tr.Reasons["PreventMove"] == "" {
		t.Errorf("reasons %v", tr.Reasons)
	}
	if _, leaked := tr.Payload["IncomingPassword"]; leaked {
		t.Error("a password was copied into a declaration")
	}
}

func TestTranslateArrayAndRejectsBadValues(t *testing.T) {
	set := schemas.Embedded()
	tr, _ := Translate("com.apple.ldap.account", map[string]any{
		"LDAPAccountHostName": "ldap.example.com",
		"LDAPSearchSettings": []any{
			map[string]any{"LDAPSearchSettingDescription": "All", "LDAPSearchSettingSearchBase": "dc=example", "LDAPSearchSettingScope": "LDAPSearchSettingScopeSubtree"},
			map[string]any{"LDAPSearchSettingDescription": "Bad", "LDAPSearchSettingSearchBase": "dc=x", "LDAPSearchSettingScope": "Sideways"},
		},
	}, "", set)
	ss, _ := tr.Payload["SearchSettings"].([]any)
	if len(ss) != 2 {
		t.Fatalf("search settings %v untranslated %v", tr.Payload, tr.Untranslated)
	}
	if first := ss[0].(map[string]any); first["Scope"] != "Subtree" || first["SearchBase"] != "dc=example" {
		t.Errorf("first %v", first)
	}
	if bad := ss[1].(map[string]any); bad["Scope"] != nil {
		t.Errorf("a scope the declaration does not allow was delivered: %v", bad)
	}
	found := false
	for _, u := range tr.Untranslated {
		found = found || strings.Contains(u, "LDAPSearchSettingScope")
	}
	if !found {
		t.Errorf("the bad scope was not reported: %v", tr.Untranslated)
	}
}

func TestTranslateSoftwareUpdateValues(t *testing.T) {
	set := schemas.Embedded()
	tr, _ := Translate("com.apple.SoftwareUpdate", map[string]any{
		"AutomaticDownload": true, "AutomaticallyInstallMacOSUpdates": false,
		"restrict-software-update-require-admin-to-install": true, "CatalogURL": "https://x",
	}, "", set)
	au, _ := tr.Payload["AutomaticActions"].(map[string]any)
	if au["Download"] != "AlwaysOn" || au["InstallOSUpdates"] != "AlwaysOff" || tr.Payload["AllowStandardUserOSUpdates"] != false {
		t.Errorf("payload %v", tr.Payload)
	}
	if len(tr.Untranslated) != 1 || tr.Untranslated[0] != "CatalogURL" {
		t.Errorf("untranslated %v", tr.Untranslated)
	}
}

func TestTranslateRangeAndType(t *testing.T) {
	set := schemas.Embedded()
	tr, _ := Translate("com.apple.mobiledevice.passwordpolicy", map[string]any{"minLength": "eight", "maxFailedAttempts": float64(5)}, "", set)
	if tr.Payload["MaximumFailedAttempts"] != int64(5) {
		t.Errorf("payload %v", tr.Payload)
	}
	if _, ok := tr.Payload["MinimumLength"]; ok || tr.Reasons["minLength"] == "" {
		t.Errorf("a string was delivered as an integer: %v %v", tr.Payload, tr.Reasons)
	}
}

func TestTranslateAllSplitsRestrictions(t *testing.T) {
	set := schemas.Embedded()
	trs, ok := TranslateAll("com.apple.applicationaccess", map[string]any{
		"allowAssistant": false, "allowPredictiveKeyboard": false, "allowGenmoji": false, "allowMailSummary": false, "allowCamera": false,
	}, set)
	if !ok {
		t.Fatal("no translation")
	}
	got := map[string]map[string]any{}
	var unt []string
	for _, tr := range trs {
		got[tr.Declaration] = tr.Payload
		unt = append(unt, tr.Untranslated...)
	}
	if got["com.apple.configuration.siri.settings"]["Enabled"] != false || got["com.apple.configuration.keyboard.settings"]["AllowPredictiveText"] != false ||
		got["com.apple.configuration.intelligence.settings"]["AllowGenmoji"] != false {
		t.Errorf("split %v", got)
	}
	apps, _ := got["com.apple.configuration.intelligence.settings"]["Apps"].(map[string]any)
	if mail, _ := apps["Mail"].(map[string]any); mail["AllowSummary"] != false {
		t.Errorf("nested %v", apps)
	}
	if len(unt) != 1 || unt[0] != "allowCamera" {
		t.Errorf("untranslated once: %v", unt)
	}
}

// Every alias must point at keys that exist in the pinned schemas, so a schema update that renames or drops one fails here rather than silently.
func TestAliasesFollowTheSchemas(t *testing.T) {
	set := schemas.Embedded()
	for pt, table := range aliasTable() {
		prof, ok := set.Profile(pt)
		if !ok {
			t.Errorf("alias table names %s, which the schemas do not have", pt)
			continue
		}
		equiv := Equivalents()[pt]
		if len(equiv) == 0 {
			t.Errorf("%s has aliases but no declaration equivalent", pt)
		}
		for from, a := range table {
			if _, ok := resolve(prof.Keys, from); !ok {
				t.Errorf("%s: profile key %s is not in the schema", pt, from)
			}
			if a.To == "" {
				if a.Note == "" {
					t.Errorf("%s: %s has no counterpart and no reason", pt, from)
				}
				continue
			}
			if strings.Contains(from, ".") {
				continue // nested: relative to the translated parent, checked by the array test
			}
			hit := false
			for _, dt := range equiv {
				d, _ := set.Declaration(dt)
				if d == nil {
					continue
				}
				if _, ok := resolve(d.Keys, a.To); ok {
					hit = true
				}
			}
			if !hit {
				t.Errorf("%s: %s -> %s is in no equivalent declaration", pt, from, a.To)
			}
		}
	}
}

func TestCoverageReport(t *testing.T) {
	rows := Coverage(schemas.Embedded())
	if len(rows) == 0 {
		t.Fatal("empty")
	}
	for _, r := range rows {
		if r.PayloadType == "com.apple.mobiledevice.passwordpolicy" && (r.Translated < 11 || len(r.Unmapped) != 0) {
			t.Errorf("passcode coverage %+v", r)
		}
		if r.PayloadType == "com.apple.mail.managed" && r.Translated < 15 {
			t.Errorf("mail coverage %+v", r)
		}
	}
}
