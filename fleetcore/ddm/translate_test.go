package ddm

import (
	"encoding/json"
	"fmt"
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
				if a.Note == "" && !a.Ignore && !a.Lift {
					t.Errorf("%s: %s has no counterpart and no reason", pt, from)
				}
				continue
			}
			if a.Decl != "" {
				for _, dt := range strings.Split(a.Decl, ",") {
					found := false
					for _, e := range equiv {
						found = found || e == dt
					}
					if !found {
						t.Errorf("%s: %s names %s, which is not an equivalent of the payload", pt, from, dt)
					}
				}
			}
			if a.Decl != "" && (strings.Count(from, ".") == 0 || strings.HasPrefix(from, "IKEv2.") || strings.HasPrefix(from, "IPSec.") || strings.HasPrefix(from, "VPN.")) {
				// the target is a path in each named declaration
				for _, dt := range strings.Split(a.Decl, ",") {
					if d, _ := set.Declaration(dt); d == nil {
						t.Errorf("%s: %s names a declaration the schemas lack", pt, from)
					} else if _, ok := resolve(d.Keys, a.To); !ok {
						t.Errorf("%s: %s -> %s is not in %s", pt, from, a.To, dt)
					}
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

func TestTranslateCertificateToAsset(t *testing.T) {
	set := schemas.Embedded()
	pemData := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	tr, ok := Translate("com.apple.security.root", map[string]any{"PayloadUUID": "AAAA-1", "PayloadContent": pemData}, "", set)
	if !ok || len(tr.Assets) != 1 {
		t.Fatalf("%+v", tr)
	}
	a := tr.Assets[0]
	if a.ID != "cert-aaaa-1" || a.DeclarationType != "com.apple.asset.credential.certificate" || a.ContentType != "application/x-pem-file" || string(a.Data) != string(pemData) {
		t.Errorf("asset %+v", a)
	}
	if tr.Payload["CredentialAssetReference"] != "$asset:cert-aaaa-1" || tr.Declaration != "com.apple.configuration.security.certificate" {
		t.Errorf("payload %v", tr.Payload)
	}
	// an identity with a password cannot move: the asset has nowhere to put it
	tr, _ = Translate("com.apple.security.pkcs12", map[string]any{"PayloadUUID": "B", "PayloadContent": []byte{1, 2, 3}, "Password": "secret"}, "", set)
	if len(tr.Assets) != 0 || tr.Reasons["Password"] == "" || strings.Contains(fmt.Sprint(tr), "secret") {
		t.Errorf("password: %+v", tr)
	}
	tr, _ = Translate("com.apple.security.pkcs12", map[string]any{"PayloadUUID": "B", "PayloadContent": []byte{1, 2, 3}}, "", set)
	if len(tr.Assets) != 1 || tr.Assets[0].DeclarationType != "com.apple.asset.credential.identity" || tr.Assets[0].ContentType != "application/x-pkcs12" {
		t.Errorf("identity: %+v", tr)
	}
}

func TestTranslateIKEv2VPN(t *testing.T) {
	set := schemas.Embedded()
	trs, ok := TranslateAll("com.apple.vpn.managed", map[string]any{
		"VPNType": "IKEv2", "UserDefinedName": "Office",
		"IKEv2": map[string]any{
			"RemoteAddress": "vpn.example.com", "LocalIdentifier": "me", "RemoteIdentifier": "vpn.example.com",
			"AuthenticationMethod": "Certificate", "PayloadCertificateUUID": "ABC-1", "CertificateType": "ECDSA256",
			"EnablePFS": uint64(1), "DisableMOBIKE": uint64(0), "MTU": uint64(1400), "IncludeAllNetworks": uint64(1),
			"DeadPeerDetectionRate": "Medium", "SharedSecret": "s3cret",
			"IKESecurityAssociationParameters":   map[string]any{"EncryptionAlgorithm": "AES-256-GCM", "DiffieHellmanGroup": uint64(19)},
			"ChildSecurityAssociationParameters": map[string]any{"EncryptionAlgorithm": "3DES"},
		},
		"DNS": map[string]any{"ServerAddresses": []any{"10.0.0.1"}},
	}, set)
	if !ok || len(trs) != 1 || trs[0].Declaration != vpnIKEv2 {
		t.Fatalf("%+v", trs)
	}
	p := trs[0].Payload
	au, _ := p["Authentication"].(map[string]any)
	nr, _ := p["NetworkRouting"].(map[string]any)
	idle, _ := p["Idle"].(map[string]any)
	ike, _ := p["IKESecurityAssociationParameters"].(map[string]any)
	if p["VisibleName"] != "Office" || p["HostName"] != "vpn.example.com" || au["Method"] != "Certificate" || au["IdentityAssetReference"] != "$asset:cert-abc-1" ||
		au["IdentityCertificateType"] != "ECDSA256" || p["EnablePFS"] != true || p["DisableMOBIKE"] != false || p["MTU"] != int64(1400) ||
		nr["IncludeAllNetworks"] != true || idle["DeadPeerDetectionRate"] != "Medium" || ike["EncryptionAlgorithm"] != "AES-256-GCM" {
		t.Errorf("payload %v", p)
	}
	if strings.Contains(fmt.Sprint(p), "s3cret") || trs[0].Reasons["IKEv2.SharedSecret"] == "" {
		t.Errorf("secret handling: %v %v", p, trs[0].Reasons)
	}
	child, _ := p["ChildSecurityAssociationParameters"].(map[string]any)
	if child["EncryptionAlgorithm"] != nil {
		t.Errorf("3DES is not allowed by the declaration but was delivered: %v", child)
	}
	// a VPN of another kind is not forced into the IKEv2 declaration
	trs, _ = TranslateAll("com.apple.vpn.managed", map[string]any{"VPNType": "IPSec", "UserDefinedName": "x"}, set)
	for _, tr := range trs {
		if tr.Declaration == vpnIKEv2 {
			t.Error("an IPSec VPN was translated as IKEv2")
		}
	}
}

func TestCertificateReferencesFromOtherPayloads(t *testing.T) {
	tr, _ := Translate("com.apple.dnsSettings.managed", map[string]any{"DNSSettings": map[string]any{"DNSProtocol": "TLS", "ServerName": "dns.example.com", "PayloadCertificateUUID": "ID-9"}}, "", schemas.Embedded())
	ds, _ := tr.Payload["DNSSettings"].(map[string]any)
	if ds["IdentityAssetReference"] != "$asset:"+CertAssetID("ID-9") || ds["ServerName"] != "dns.example.com" {
		t.Errorf("%v", tr.Payload)
	}
}

func TestTranslateSCEPAndACMEToCredentialAssets(t *testing.T) {
	set := schemas.Embedded()
	tr, ok := Translate("com.apple.security.scep", map[string]any{"PayloadUUID": "S-1", "PayloadContent": map[string]any{
		"URL": "https://scep.example.com", "Name": "CA", "Keysize": uint64(2048), "Key Type": "RSA", "Key Usage": uint64(5), "Challenge": "abc",
		"Subject":        []any{[]any{[]any{"CN", "device"}}, []any{[]any{"O", "Example"}}},
		"SubjectAltName": map[string]any{"dNSName": "d.example.com"},
	}}, "", set)
	if !ok || len(tr.Assets) != 1 || tr.Declaration != "com.apple.asset.credential.scep" {
		t.Fatalf("%+v", tr)
	}
	var doc map[string]any
	if err := json.Unmarshal(tr.Assets[0].Data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["URL"] != "https://scep.example.com" || doc["Keysize"] != float64(2048) || doc["Key Type"] != "RSA" || doc["Challenge"] != "abc" {
		t.Errorf("doc %v", doc)
	}
	if subj, _ := doc["Subject"].([]any); len(subj) != 2 {
		t.Errorf("subject %v", doc["Subject"])
	}
	if tr.Assets[0].ID != CertAssetID("S-1") || tr.Assets[0].ContentType != "application/json" || tr.Approximate["Challenge"] == "" {
		t.Errorf("asset %+v approx %v", tr.Assets[0], tr.Approximate)
	}
	// a key size the credential does not allow is not delivered
	bad, _ := Translate("com.apple.security.scep", map[string]any{"PayloadContent": map[string]any{"URL": "https://x", "Keysize": uint64(512)}}, "", set)
	if len(bad.Assets) == 1 && strings.Contains(string(bad.Assets[0].Data), "512") || bad.Reasons["PayloadContent.Keysize"] == "" {
		t.Errorf("keysize: %+v", bad)
	}
	acme, _ := Translate("com.apple.security.acme", map[string]any{
		"PayloadUUID": "A-1", "DirectoryURL": "https://acme.example.com/dir", "ClientIdentifier": "id", "KeySize": uint64(384), "KeyType": "ECSECPrimeRandom",
		"HardwareBound": true, "Attest": true, "Subject": []any{[]any{[]any{"CN", "x"}}},
	}, "", set)
	if len(acme.Assets) != 1 || acme.Assets[0].DeclarationType != "com.apple.asset.credential.acme" || len(acme.Untranslated) != 0 {
		t.Errorf("acme %+v", acme)
	}
	// a required key that is missing is reported
	miss, _ := Translate("com.apple.security.acme", map[string]any{"DirectoryURL": "https://x"}, "", set)
	if miss.Reasons["ClientIdentifier"] == "" {
		t.Errorf("missing required: %+v", miss.Reasons)
	}
}

func TestTranslateIPSecAndPluginVPN(t *testing.T) {
	set := schemas.Embedded()
	trs, _ := TranslateAll("com.apple.vpn.managed", map[string]any{
		"VPNType": "IPSec", "UserDefinedName": "Cisco",
		"IPSec": map[string]any{"RemoteAddress": "ipsec.example.com", "AuthenticationMethod": "SharedSecret", "LocalIdentifier": "grp", "XAuthEnabled": uint64(1), "SharedSecret": []byte("x"), "XAuthName": "u"},
	}, set)
	if len(trs) != 1 || trs[0].Declaration != vpnIPSec {
		t.Fatalf("%+v", trs)
	}
	au, _ := trs[0].Payload["Authentication"].(map[string]any)
	xa, _ := au["XAuth"].(map[string]any)
	if trs[0].Payload["HostName"] != "ipsec.example.com" || au["Method"] != "SharedSecret" || au["LocalIdentifier"] != "grp" || xa["Enabled"] != true {
		t.Errorf("payload %v", trs[0].Payload)
	}
	if trs[0].Reasons["IPSec.SharedSecret"] == "" || strings.Contains(fmt.Sprint(trs[0].Payload), "SharedSecret\":") {
		t.Errorf("secrets: %v", trs[0].Reasons)
	}
	trs, _ = TranslateAll("com.apple.vpn.managed", map[string]any{
		"VPNType": "VPN", "VPNSubType": "com.vendor.vpn", "UserDefinedName": "Vendor",
		"VPN":          map[string]any{"RemoteAddress": "v.example.com", "AuthenticationMethod": "Password", "ProviderType": "packet-tunnel", "IncludeAllNetworks": uint64(0)},
		"VendorConfig": map[string]any{"Realm": "corp"},
	}, set)
	if len(trs) != 1 || trs[0].Declaration != vpnPlugin {
		t.Fatalf("%+v", trs)
	}
	p := trs[0].Payload
	pv, _ := p["Provider"].(map[string]any)
	vc, _ := p["VendorConfig"].(map[string]any)
	nr, _ := p["NetworkRouting"].(map[string]any)
	if p["SubType"] != "com.vendor.vpn" || p["HostName"] != "v.example.com" || pv["Type"] != "packet-tunnel" || vc["Realm"] != "corp" || nr["IncludeAllNetworks"] != false {
		t.Errorf("payload %v", p)
	}
}

func TestTranslateMoreRestrictions(t *testing.T) {
	set := schemas.Embedded()
	trs, _ := TranslateAll("com.apple.applicationaccess", map[string]any{
		"allowExternalIntelligenceIntegrations": false, "blockedAppBundleIDs": []any{"com.example.game"},
		"enforcedSoftwareUpdateMajorOSDeferredInstallDelay": uint64(30), "allowRapidSecurityResponseRemoval": false, "allowKeyboardShortcuts": false,
	}, set)
	got := map[string]map[string]any{}
	reasons := map[string]string{}
	for _, tr := range trs {
		got[tr.Declaration] = tr.Payload
		for k, v := range tr.Reasons {
			reasons[k] = v
		}
	}
	apps, _ := got["com.apple.configuration.app.settings"]["Allowed"].(map[string]any)
	defer_, _ := got["com.apple.configuration.softwareupdate.settings"]["Deferrals"].(map[string]any)
	rsr, _ := got["com.apple.configuration.softwareupdate.settings"]["RapidSecurityResponse"].(map[string]any)
	if got["com.apple.configuration.external-intelligence.settings"]["Enabled"] != false || fmt.Sprint(apps["DeniedApps"]) != "[com.example.game]" ||
		defer_["MajorPeriodInDays"] != int64(30) || rsr["EnableRollback"] != false {
		t.Errorf("got %v", got)
	}
	if reasons["allowKeyboardShortcuts"] == "" {
		t.Errorf("reasons %v", reasons)
	}
}

// A profile key must not be claimed by two declarations, or a setting would be delivered twice with different effects.
func TestNoKeyIsClaimedTwice(t *testing.T) {
	set := schemas.Embedded()
	prof, _ := set.Profile("com.apple.applicationaccess")
	payload := map[string]any{}
	for _, k := range prof.Keys {
		switch k.Type {
		case "boolean":
			payload[k.Key] = false
		}
	}
	owners := map[string][]string{}
	for _, dt := range Equivalents()["com.apple.applicationaccess"] {
		_, claimed, _ := translateOne("com.apple.applicationaccess", payload, dt, set)
		for k, c := range claimed {
			if c {
				owners[k] = append(owners[k], dt)
			}
		}
	}
	for k, o := range owners {
		if len(o) > 1 {
			t.Errorf("%s is taken by %v", k, o)
		}
	}
}
