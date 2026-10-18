package ddm

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

//go:embed translate_aliases.json
var aliasesJSON []byte

type alias struct {
	// To is the declaration key the setting becomes: a dotted path for a nested key, relative to the translated parent for a nested profile key.
	// Empty means the setting has no counterpart (Note says why).
	To          string         `json:"to"`
	Invert      bool           `json:"invert,omitempty"`
	Approximate bool           `json:"approximate,omitempty"`
	Note        string         `json:"note,omitempty"`
	Values      map[string]any `json:"values,omitempty"` // profile value (as text) to declaration value
	// Lift translates the keys of a nested profile dictionary as if they sat at the top (the profile wraps IKEv2 settings in an IKEv2 dictionary).
	Lift bool `json:"lift,omitempty"`
	// Ref marks a value that is the PayloadUUID of a certificate payload in the same profile; it becomes a reference to the asset that payload translates to.
	Ref bool `json:"ref,omitempty"`
	// Decl limits the alias to the declaration types listed, comma separated (a payload that several declarations replace).
	Decl string `json:"decl,omitempty"`
	// CredGroup gathers keys that make up one credential (a user name and a password) into a user name and password credential asset; CredRole says which part this key
	// is (user, password, secret for a bare secret, or same-as:<group> for a flag meaning "the password of that group"), and CredRef is where in the declaration the asset is
	// referred to. The same group name on several keys is one asset.
	CredGroup string `json:"cred_group,omitempty"`
	CredRole  string `json:"cred_role,omitempty"`
	CredRef   string `json:"cred_ref,omitempty"`
	// Ignore marks a key that only selects how the payload is translated and has nothing to carry over.
	Ignore bool `json:"ignore,omitempty"`
}

// Asset is data a translated declaration refers to by "$asset:<ID>": the caller adds it to the blueprint as an asset item.
type Asset struct {
	ID              string `json:"id"`
	DeclarationType string `json:"declaration_type"`
	ContentType     string `json:"content_type"`
	Data            []byte `json:"data"`
}

// Translation is a configuration profile payload expressed as a declaration.
type Translation struct {
	// Declaration is the declaration type the payload was translated to.
	Declaration string `json:"declaration"`
	// Payload is the declaration's payload; check it before use.
	Payload map[string]any `json:"payload"`
	// Approximate lists profile keys that were translated to the closest setting, with why.
	Approximate map[string]string `json:"approximate,omitempty"`
	// Untranslated lists profile keys that are not in Payload and need a person's decision; Reasons says why where it is known.
	Untranslated []string          `json:"untranslated,omitempty"`
	Reasons      map[string]string `json:"reasons,omitempty"`
	// Assets are what the payload referred to by value (a certificate, an identity) now lives in; Payload points at them.
	Assets []Asset `json:"assets,omitempty"`
}

// CertAssetID is the asset id a certificate payload gets, from its PayloadUUID, so other payloads of the profile can refer to it.
func CertAssetID(payloadUUID string) string { return "cert-" + strings.ToLower(payloadUUID) }

func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func aliasTable() map[string]map[string]alias {
	table := map[string]map[string]alias{}
	_ = json.Unmarshal(aliasesJSON, &table)
	return table
}

// children is what a key's value is made of: a dictionary's keys, or the keys of an array's dictionary elements.
func children(k schemas.Key) []schemas.Key {
	if k.Type == "array" && len(k.Keys) == 1 && k.Keys[0].Type == "dictionary" {
		return k.Keys[0].Keys
	}
	return k.Keys
}

func findKey(keys []schemas.Key, name string) (schemas.Key, bool) {
	for _, k := range keys {
		if k.Key == name {
			return k, true
		}
	}
	n := norm(name)
	for _, k := range keys {
		if norm(k.Key) == n {
			return k, true
		}
	}
	return schemas.Key{}, false
}

// resolve follows a dotted path through the keys.
func resolve(keys []schemas.Key, path string) (schemas.Key, bool) {
	var k schemas.Key
	for i, part := range strings.Split(path, ".") {
		var ok bool
		if k, ok = findKey(keys, part); !ok {
			return schemas.Key{}, false
		}
		if i < strings.Count(path, ".") {
			keys = children(k)
		}
	}
	return k, true
}

type credGroup struct {
	user, password string
	hasUser, hasPW bool
	secret         bool
	sameAs         string
	ref            string
	sameFlag       bool
}

type translator struct {
	creds   map[string]*credGroup
	payload map[string]any
	aliases map[string]alias
	tr      *Translation
	claimed map[string]bool // top-level profile keys the declaration has a setting for
}

func text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return fmt.Sprint(v)
}

// gather collects one part of a credential for finishCredentials.
func (t *translator) gather(a alias, val any) {
	g := t.creds[a.CredGroup]
	if g == nil {
		g = &credGroup{}
		t.creds[a.CredGroup] = g
	}
	if a.CredRef != "" {
		g.ref = a.CredRef
	}
	switch {
	case a.CredRole == "user":
		g.user, g.hasUser = text(val), true
	case a.CredRole == "password":
		g.password, g.hasPW = text(val), true
	case a.CredRole == "secret":
		g.password, g.hasPW, g.secret = text(val), true, true
	case strings.HasPrefix(a.CredRole, "same-as:"):
		if b, ok := val.(bool); ok && b {
			g.sameAs = strings.TrimPrefix(a.CredRole, "same-as:")
		}
	}
}

// finishCredentials turns each gathered credential into a user name and password asset and points the declaration at it. Only a value that was given is stored; a credential
// whose reference the declaration has no place for is reported instead of dropped.
func (t *translator) finishCredentials(payloadType string, def *schemas.Declaration, set *schemas.Set) {
	cred, haveSchema := set.Credential("com.apple.credential.usernameandpassword")
	names := make([]string, 0, len(t.creds))
	for n := range t.creds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		g := t.creds[n]
		if g.sameAs != "" && !g.hasPW {
			if o := t.creds[g.sameAs]; o != nil {
				g.password, g.hasPW = o.password, o.hasPW
			}
		}
		if !g.hasUser && !g.hasPW {
			continue
		}
		if !haveSchema || g.ref == "" {
			t.unmapped(n, "credentials are delivered as an asset, which this payload has no place to refer to")
			continue
		}
		if _, ok := resolve(def.Keys, g.ref); !ok {
			continue // the declaration this payload is being translated to has no such setting; another kind of declaration may
		}
		doc := map[string]any{"UserName": g.user}
		if g.hasPW {
			doc["Password"] = g.password
		}
		if why := checkDoc(t, doc, cred.Keys); why != "" {
			t.unmapped(n, why)
			continue
		}
		body, _ := json.Marshal(doc)
		sum := sha256.Sum256([]byte(payloadType + "\x00" + n + "\x00" + string(body)))
		id := "cred-" + strings.ToLower(n) + "-" + hex.EncodeToString(sum[:4])
		t.tr.Assets = append(t.tr.Assets, Asset{ID: id, DeclarationType: "com.apple.asset.credential.userpassword", ContentType: "application/json", Data: body})
		setPath(t.tr.Payload, g.ref, "$asset:"+id)
		if g.secret {
			t.tr.Approximate[n] = "a shared secret is stored as the password of a user name and password credential with an empty user name; confirm on a device"
		}
	}
}

// checkDoc validates a credential document against its schema and returns why it does not fit.
func checkDoc(t *translator, doc map[string]any, keys []schemas.Key) string {
	probe := &translator{aliases: map[string]alias{}, tr: &Translation{Payload: map[string]any{}, Approximate: map[string]string{}}, claimed: map[string]bool{}, creds: map[string]*credGroup{}}
	out := map[string]any{}
	probe.object(doc, keys, "", out)
	if len(probe.tr.Untranslated) > 0 {
		return probe.tr.Reasons[probe.tr.Untranslated[0]] + " (" + probe.tr.Untranslated[0] + ")"
	}
	for _, k := range keys {
		if _, ok := out[k.Key]; k.Required && !ok {
			return k.Key + " is required"
		}
	}
	return ""
}

func (t *translator) unmapped(path, why string) {
	t.tr.Untranslated = append(t.tr.Untranslated, path)
	if why != "" {
		if t.tr.Reasons == nil {
			t.tr.Reasons = map[string]string{}
		}
		t.tr.Reasons[path] = why
	}
}

func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[p] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = v
}

// object translates the keys of one profile dictionary into out. prefix is the profile path so far (with a trailing dot).
func (t *translator) object(in map[string]any, defs []schemas.Key, prefix string, out map[string]any) {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		val := in[key]
		path := prefix + key
		if prefix == "" && strings.HasPrefix(key, "Payload") {
			continue
		}
		top := prefix == ""
		a, hasAlias := t.aliases[path]
		if hasAlias && a.Decl != "" && !declIn(a.Decl, t.tr.Declaration) {
			hasAlias = false
		}
		if hasAlias && a.CredGroup != "" {
			if top {
				t.claimed[key] = true
			}
			t.gather(a, val)
			continue
		}
		if hasAlias && a.Ignore {
			t.claimed[key] = true
			continue
		}
		if hasAlias && a.Lift {
			if m, ok := val.(map[string]any); ok && prefix == "" {
				t.claimed[key] = true
				t.object(m, defs, path+".", out)
			}
			continue
		}
		var def schemas.Key
		var found bool
		target := key
		switch {
		case hasAlias && a.To == "":
			t.unmapped(path, a.Note)
			continue
		case hasAlias:
			target = a.To
			def, found = resolve(defs, a.To)
		default:
			def, found = findKey(defs, key)
			target = def.Key
		}
		if !found {
			if top {
				t.claimed[key] = false
			}
			t.unmapped(path, "")
			continue
		}
		if top {
			t.claimed[key] = true
		}
		if hasAlias {
			if a.Invert {
				if b, isBool := val.(bool); isBool {
					if !b { // allowSimple false -> complex true; allowSimple true says nothing
						setPath(out, target, true)
					}
				}
				if a.Approximate {
					t.tr.Approximate[path] = a.Note
				}
				continue
			}
			if a.Ref {
				if u, ok := val.(string); ok {
					val = "$asset:" + CertAssetID(u)
				}
			}
			if a.Values != nil {
				mapped, ok := a.Values[fmt.Sprint(val)]
				if !ok {
					t.unmapped(path, fmt.Sprintf("the value %v has no equivalent in %s", val, target))
					continue
				}
				val = mapped
			}
		}
		v, why := t.convert(val, def, path)
		if why != "" {
			t.unmapped(path, why)
			continue
		}
		if v == nil {
			continue
		}
		setPath(out, target, v)
		if hasAlias && a.Approximate {
			t.tr.Approximate[path] = a.Note
		}
	}
}

func declIn(list, decl string) bool {
	for _, d := range strings.Split(list, ",") {
		if d == decl {
			return true
		}
	}
	return false
}

func integral(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), n <= math.MaxInt64
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), n <= math.MaxInt64
	case float64:
		return int64(n), n == math.Trunc(n) && math.Abs(n) < 1<<53
	case float32:
		return int64(n), float64(n) == math.Trunc(float64(n))
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func number(v any) (float64, bool) {
	if i, ok := integral(v); ok {
		return float64(i), true
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// convert checks one profile value against the declaration key it goes to and returns the value as the declaration wants it. A reason comes back
// instead when it does not fit, so a setting is never delivered in a form the device would reject.
func (t *translator) convert(val any, def schemas.Key, path string) (any, string) {
	switch def.Type {
	case "boolean":
		b, ok := val.(bool)
		if !ok {
			return nil, fmt.Sprintf("%s is a boolean in the declaration; the profile has %T", def.Key, val)
		}
		return b, ""
	case "integer":
		i, ok := integral(val)
		if !ok {
			return nil, fmt.Sprintf("%s is an integer in the declaration; the profile has %v", def.Key, val)
		}
		if len(def.Allowed) > 0 {
			ok = false
			for _, a := range def.Allowed {
				if f, isNum := number(a); isNum && f == float64(i) {
					ok = true
				}
			}
			if !ok {
				return nil, fmt.Sprintf("%d is not one of the values %v allows", i, def.Allowed)
			}
		}
		if def.Min != nil && float64(i) < *def.Min {
			return nil, fmt.Sprintf("%d is below the minimum %v", i, *def.Min)
		}
		if def.Max != nil && float64(i) > *def.Max {
			return nil, fmt.Sprintf("%d is above the maximum %v", i, *def.Max)
		}
		return i, ""
	case "real":
		f, ok := number(val)
		if !ok {
			return nil, fmt.Sprintf("%s is a number in the declaration; the profile has %v", def.Key, val)
		}
		return f, ""
	case "string":
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Sprintf("%s is a string in the declaration; the profile has %T", def.Key, val)
		}
		if len(def.Allowed) > 0 {
			ok = false
			for _, a := range def.Allowed {
				ok = ok || fmt.Sprint(a) == s
			}
			if !ok {
				return nil, fmt.Sprintf("%q is not one of the values %v allows", s, def.Allowed)
			}
		}
		return s, ""
	case "dictionary":
		m, ok := val.(map[string]any)
		if !ok {
			return nil, fmt.Sprintf("%s is a dictionary in the declaration; the profile has %T", def.Key, val)
		}
		if len(def.Keys) == 0 { // free-form
			return m, ""
		}
		sub := map[string]any{}
		t.object(m, def.Keys, path+".", sub)
		if len(sub) == 0 {
			return nil, ""
		}
		return sub, ""
	case "array":
		arr, ok := val.([]any)
		if !ok {
			return nil, fmt.Sprintf("%s is an array in the declaration; the profile has %T", def.Key, val)
		}
		if len(def.Keys) != 1 {
			return arr, ""
		}
		var out []any
		for i, el := range arr {
			v, why := t.convert(el, def.Keys[0], path)
			if why != "" {
				t.unmapped(fmt.Sprintf("%s[%d]", path, i), why)
				continue
			}
			if v != nil {
				out = append(out, v)
			}
		}
		return out, ""
	}
	return val, "" // data, date and anything the schema leaves open
}

func (t *translator) finish() {
	sort.Strings(t.tr.Untranslated)
	if len(t.tr.Approximate) == 0 {
		t.tr.Approximate = nil
	}
}

// certificateKinds are the profile payloads that carry a certificate or identity by value; the declaration refers to an asset that holds it instead.
const (
	vpnIKEv2  = "com.apple.configuration.network.vpn.ikev2"
	vpnIPSec  = "com.apple.configuration.network.vpn.ipsec"
	vpnPlugin = "com.apple.configuration.network.vpn.vpn-plugin"
)

var certificateKinds = map[string]string{
	"com.apple.security.pem":    "com.apple.asset.credential.certificate",
	"com.apple.security.root":   "com.apple.asset.credential.certificate",
	"com.apple.security.pkcs1":  "com.apple.asset.credential.certificate",
	"com.apple.security.pkcs12": "com.apple.asset.credential.identity",
}

func bytesOf(v any) ([]byte, bool) {
	switch d := v.(type) {
	case []byte:
		return d, len(d) > 0
	case string: // JSON carries data as base64
		b, err := base64.StdEncoding.DecodeString(d)
		return b, err == nil && len(b) > 0
	}
	return nil, false
}

// certificate turns a certificate payload into an asset (the bytes) and the configuration that refers to it.
func (t *translator) certificate(payload map[string]any, assetType string, def *schemas.Declaration, set *schemas.Set) {
	data, ok := bytesOf(payload["PayloadContent"])
	if !ok {
		t.unmapped("PayloadContent", "the payload has no certificate data")
		return
	}
	uuid, _ := payload["PayloadUUID"].(string)
	id := CertAssetID(uuid)
	if uuid == "" {
		sum := sha256.Sum256(data)
		id = "cert-" + hex.EncodeToString(sum[:4])
	}
	content := "application/pkcs1"
	switch {
	case assetType == "com.apple.asset.credential.identity":
		// An identity asset is a JSON document holding the PKCS #12 data and its password.
		pw, _ := payload["Password"].(string)
		doc := map[string]any{"Password": pw, "Identity": data}
		cred, ok := set.Credential("com.apple.credential.identity")
		if !ok {
			t.unmapped("PayloadContent", "the pinned schemas do not describe com.apple.credential.identity")
			return
		}
		if why := checkDoc(t, map[string]any{"Password": pw, "Identity": data}, cred.Keys); why != "" {
			t.unmapped("PayloadContent", why)
			return
		}
		body, _ := json.Marshal(doc) // data becomes base64
		data, content = body, "application/json"
		t.claimed["Password"] = true
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")):
		content = "application/pem"
	}
	t.tr.Assets = append(t.tr.Assets, Asset{ID: id, DeclarationType: assetType, ContentType: content, Data: data})
	t.tr.Payload["CredentialAssetReference"] = "$asset:" + id
	t.claimed["PayloadContent"] = true
	if k, ok := findKey(def.Keys, "KeyIsExtractable"); ok {
		if v, ok := payload[k.Key].(bool); ok {
			t.tr.Payload[k.Key] = v
		}
	}
}

// credentialKinds are the profile payloads for an identity the device creates (SCEP, ACME): the asset's data is a JSON document with the payload's own keys.
var credentialKinds = map[string]string{
	"com.apple.security.scep": "com.apple.credential.scep",
	"com.apple.security.acme": "com.apple.credential.acme",
}

// credential builds the credential document of a SCEP or ACME payload, checked against Apple's schema for that document, as an asset.
func (t *translator) credential(payload map[string]any, credType string, set *schemas.Set) {
	cred, ok := set.Credential(credType)
	if !ok {
		t.unmapped("PayloadContent", "the pinned schemas do not describe "+credType)
		return
	}
	in := payload
	prefix := ""
	if c, ok := payload["PayloadContent"].(map[string]any); ok { // SCEP wraps its settings
		in, prefix = c, "PayloadContent."
	}
	doc := map[string]any{}
	t.object(in, cred.Keys, prefix, doc)
	for _, k := range cred.Keys {
		if _, has := doc[k.Key]; k.Required && !has {
			t.unmapped(prefix+k.Key, "required by "+credType)
		}
	}
	if len(doc) == 0 {
		return
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.unmapped("PayloadContent", err.Error())
		return
	}
	uuid, _ := payload["PayloadUUID"].(string)
	id := CertAssetID(uuid)
	if uuid == "" {
		sum := sha256.Sum256(body)
		id = "cert-" + hex.EncodeToString(sum[:4])
	}
	assetType := "com.apple.asset.credential." + credType[strings.LastIndex(credType, ".")+1:]
	t.tr.Assets = append(t.tr.Assets, Asset{ID: id, DeclarationType: assetType, ContentType: "application/json", Data: body})
	t.tr.Declaration = assetType
	t.claimed["PayloadContent"] = true
	if _, has := doc["Challenge"]; has {
		t.tr.Approximate["Challenge"] = "the challenge is stored in the asset document, which the server hosts behind the device's identity and seals at rest; prefer a dynamic challenge"
	}
}

func translateOne(payloadType string, payload map[string]any, declType string, set *schemas.Set) (*Translation, map[string]bool, bool) {
	def, ok := set.Declaration(declType)
	if !ok {
		return nil, nil, false
	}
	t := &translator{
		creds:   map[string]*credGroup{},
		aliases: aliasTable()[payloadType],
		tr:      &Translation{Declaration: declType, Payload: map[string]any{}, Approximate: map[string]string{}},
		claimed: map[string]bool{},
	}
	if ft, _ := payload["FilterType"].(string); payloadType == "com.apple.webcontent-filter" && ft != "Plugin" {
		t.claimed["FilterType"] = true
		t.unmapped("FilterType", "only plug-in content filters have a declaration; the built-in filter stays a profile")
	} else if kind, ok := certificateKinds[payloadType]; ok {
		t.certificate(payload, kind, def, set)
	} else if ct, ok := credentialKinds[payloadType]; ok {
		t.credential(payload, ct, set)
	} else {
		t.object(payload, def.Keys, "", t.tr.Payload)
		t.finishCredentials(payloadType, def, set)
	}
	t.finish()
	return t.tr, t.claimed, true
}

// Translate expresses one payload of a profile (its keys, without the Payload* base keys) as the declaration that replaces it. Keys match by the explicit table
// (translate_aliases.json, for settings Apple renamed, restructured or moved into an asset), then by name ignoring case and punctuation. Nested dictionaries and
// arrays are translated key by key and every value is checked against the declaration's schema (type, allowed values, range). A profile key with no match, or
// whose value does not fit, is reported with a reason where one is known, never guessed. declType picks among several equivalents; empty takes the first.
func Translate(payloadType string, payload map[string]any, declType string, set *schemas.Set) (*Translation, bool) {
	equiv := Equivalents()[payloadType]
	if len(equiv) == 0 {
		return nil, false
	}
	if declType == "" {
		declType = equiv[0]
	} else {
		found := false
		for _, e := range equiv {
			found = found || e == declType
		}
		if !found {
			return nil, false
		}
	}
	tr, _, ok := translateOne(payloadType, payload, declType, set)
	return tr, ok
}

// TranslateAll translates a payload that several declarations replace (restrictions are split across accessibility, Siri, intelligence and keyboard
// declarations): each profile key goes to the declaration that has a setting for it, and the keys no declaration has are reported once, on the first result.
// A payload with one equivalent gives one result.
func TranslateAll(payloadType string, payload map[string]any, set *schemas.Set) ([]*Translation, bool) {
	equiv := Equivalents()[payloadType]
	if len(equiv) == 0 {
		return nil, false
	}
	if payloadType == "com.apple.vpn.managed" {
		// The VPN declarations are one per kind; the payload says which kind it is. L2TP, PPTP, transparent proxy and always-on have no translation.
		want := map[string]string{"IKEv2": vpnIKEv2, "IPSec": vpnIPSec, "VPN": vpnPlugin}[fmt.Sprint(payload["VPNType"])]
		kept := equiv[:0:0]
		for _, e := range equiv {
			if e == want {
				kept = append(kept, e)
			}
		}
		equiv = kept
		if len(equiv) == 0 {
			equiv = Equivalents()[payloadType][:1] // report against one declaration so the reasons are returned
		}
	}
	var out []*Translation
	claimedBy := map[string]bool{}
	var all []*Translation
	var claims []map[string]bool
	for _, dt := range equiv {
		tr, claimed, ok := translateOne(payloadType, payload, dt, set)
		if !ok {
			continue
		}
		claims = append(claims, claimed)
		for k, c := range claimed {
			claimedBy[k] = claimedBy[k] || c
		}
		all = append(all, tr)
	}
	if len(all) == 0 {
		return nil, false
	}
	saved := map[string]string{} // reasons for keys no declaration took, kept for the report below
	for _, tr := range all {
		for k, why := range tr.Reasons {
			saved[k] = why
		}
	}
	for i, tr := range all {
		// Keep only problems with keys this declaration took (nested values that do not fit); a key it does not have is reported below if no declaration has it.
		var keep []string
		for _, u := range tr.Untranslated {
			root := strings.SplitN(strings.SplitN(u, ".", 2)[0], "[", 2)[0]
			if claims[i][root] {
				keep = append(keep, u)
			} else {
				delete(tr.Reasons, u)
			}
		}
		tr.Untranslated = keep
		if len(tr.Payload) > 0 || len(keep) > 0 || len(all) == 1 {
			out = append(out, tr)
		}
	}
	// A key no declaration has a setting for is reported once, on the first result.
	var orphan []string
	for k := range payload {
		if !strings.HasPrefix(k, "Payload") && !claimedBy[k] {
			orphan = append(orphan, k)
		}
	}
	sort.Strings(orphan)
	if len(orphan) > 0 {
		if len(out) == 0 {
			out = append(out, all[0])
		}
		out[0].Untranslated = append(out[0].Untranslated, orphan...)
		sort.Strings(out[0].Untranslated)
		for _, k := range orphan {
			if why := saved[k]; why != "" {
				if out[0].Reasons == nil {
					out[0].Reasons = map[string]string{}
				}
				out[0].Reasons[k] = why
			}
		}
	}
	return out, true
}

// CoverageRow says how much of one profile payload type a declaration can take, by what the schemas and the alias table say; no payload is needed.
type CoverageRow struct {
	PayloadType string   `json:"payload_type"`
	Declaration string   `json:"declaration"`
	ProfileKeys int      `json:"profile_keys"`
	Translated  int      `json:"translated"`
	Explained   int      `json:"explained"`          // no counterpart, with a reason
	Unmapped    []string `json:"unmapped,omitempty"` // profile keys nobody has looked at
	DeclOnly    []string `json:"declaration_only,omitempty"`
}

// coverageKeys lists the profile keys a payload type is judged on: its top-level keys, with the dictionaries that are translated as if lifted
// (VPN settings, URL filter parameters) replaced by their own keys, and the credential document's keys for SCEP and ACME, whose settings are the document.
func coverageKeys(set *schemas.Set, pt string, prof *schemas.Profile, decl string, table map[string]alias) []string {
	if ct, ok := credentialKinds[pt]; ok {
		if c, ok := set.Credential(ct); ok {
			var out []string
			for _, k := range c.Keys {
				out = append(out, k.Key)
			}
			return out
		}
	}
	var out []string
	for _, k := range prof.Keys {
		if strings.HasPrefix(k.Key, "Payload") {
			continue
		}
		if a, has := table[k.Key]; has && a.Lift {
			if a.Decl == "" || declIn(a.Decl, decl) {
				for _, c := range children(k) {
					out = append(out, k.Key+"."+c.Key)
				}
			}
			continue // a lifted dictionary of another kind of declaration is not this one's business
		}
		out = append(out, k.Key)
	}
	return out
}

// Coverage reports, for every payload type that has a native declaration, how many of its profile keys translate, how many have a documented reason not to,
// and which have neither (these are the ones to look at after a schema update). Keys claimed by another declaration of the same payload type count there.
func Coverage(set *schemas.Set) []CoverageRow {
	table := aliasTable()
	var rows []CoverageRow
	for _, pt := range EquivalentTypes() {
		prof, ok := set.Profile(pt)
		if !ok {
			continue
		}
		equiv := Equivalents()[pt]
		// What each declaration takes, judged from the schemas and the alias table.
		type verdict struct {
			by        string
			explained bool
		}
		verdicts := map[string]*verdict{}
		perDecl := map[string][]string{}
		for _, dt := range equiv {
			decl, ok := set.Declaration(dt)
			if !ok {
				continue
			}
			keys := coverageKeys(set, pt, prof, dt, table[pt])
			perDecl[dt] = keys
			for _, key := range keys {
				v := verdicts[key]
				if v == nil {
					v = &verdict{}
					verdicts[key] = v
				}
				a, has := table[pt][key]
				if has && a.Decl != "" && !declIn(a.Decl, dt) {
					has = false
				}
				switch {
				case has && (a.Ignore || a.Lift):
					if v.by == "" {
						v.by = dt
					}
				case has && a.To == "":
					v.explained = true
				case has:
					if _, ok := resolve(decl.Keys, a.To); ok && v.by == "" {
						v.by = dt
					}
				case certificateKinds[pt] != "" || credentialKinds[pt] != "":
					if v.by == "" {
						v.by = dt
					}
				default:
					leaf := key[strings.LastIndex(key, ".")+1:]
					if _, ok := findKey(decl.Keys, leaf); ok && v.by == "" {
						v.by = dt
					}
				}
			}
		}
		for _, dt := range equiv {
			decl, ok := set.Declaration(dt)
			if !ok {
				continue
			}
			row := CoverageRow{PayloadType: pt, Declaration: dt}
			for _, key := range perDecl[dt] {
				row.ProfileKeys++
				v := verdicts[key]
				switch {
				case v.by == dt:
					row.Translated++
				case v.by != "":
					// translated by another declaration of this payload type
				case v.explained:
					row.Explained++
				default:
					row.Unmapped = append(row.Unmapped, key)
				}
			}
			taken := map[string]bool{}
			for _, k := range prof.Keys {
				taken[norm(k.Key)] = true
			}
			for _, a := range table[pt] {
				if a.To != "" {
					taken[norm(strings.SplitN(a.To, ".", 2)[0])] = true
				}
			}
			for _, k := range decl.Keys {
				if !taken[norm(k.Key)] {
					row.DeclOnly = append(row.DeclOnly, k.Key)
				}
			}
			sort.Strings(row.Unmapped)
			rows = append(rows, row)
		}
	}
	return rows
}
