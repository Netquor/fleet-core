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
	// Decl limits the alias to one declaration type (a payload that several declarations replace).
	Decl string `json:"decl,omitempty"`
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

type translator struct {
	aliases map[string]alias
	tr      *Translation
	claimed map[string]bool // top-level profile keys the declaration has a setting for
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
		if hasAlias && a.Decl != "" && a.Decl != t.tr.Declaration {
			hasAlias = false
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
const vpnIKEv2 = "com.apple.configuration.network.vpn.ikev2"

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
func (t *translator) certificate(payload map[string]any, assetType string, def *schemas.Declaration) {
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
	content := "application/pkix-cert"
	switch {
	case assetType == "com.apple.asset.credential.identity":
		content = "application/x-pkcs12"
		if pw, _ := payload["Password"].(string); pw != "" {
			t.unmapped("Password", "an identity asset has no password field: export the identity without a password, or keep this one in a profile")
			return
		}
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")):
		content = "application/x-pem-file"
	}
	t.tr.Assets = append(t.tr.Assets, Asset{ID: id, DeclarationType: assetType, ContentType: content, Data: data})
	t.tr.Payload["CredentialAssetReference"] = "$asset:" + id
	t.tr.Approximate["PayloadContent"] = "the certificate moved to the asset " + id + " (content type " + content + ", chosen from the data; confirm on a device)"
	t.claimed["PayloadContent"] = true
	if k, ok := findKey(def.Keys, "KeyIsExtractable"); ok {
		if v, ok := payload[k.Key].(bool); ok {
			t.tr.Payload[k.Key] = v
		}
	}
}

func translateOne(payloadType string, payload map[string]any, declType string, set *schemas.Set) (*Translation, map[string]bool, bool) {
	def, ok := set.Declaration(declType)
	if !ok {
		return nil, nil, false
	}
	t := &translator{
		aliases: aliasTable()[payloadType],
		tr:      &Translation{Declaration: declType, Payload: map[string]any{}, Approximate: map[string]string{}},
		claimed: map[string]bool{},
	}
	if kind, ok := certificateKinds[payloadType]; ok {
		t.certificate(payload, kind, def)
	} else {
		t.object(payload, def.Keys, "", t.tr.Payload)
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
		// The VPN declarations are one per kind; the payload says which kind it is. Only IKEv2 is translated.
		kept := equiv[:0:0]
		for _, e := range equiv {
			if t, _ := payload["VPNType"].(string); t == "IKEv2" && e == vpnIKEv2 || t != "IKEv2" && e != vpnIKEv2 {
				kept = append(kept, e)
			}
		}
		equiv = kept
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
			for _, tr := range all {
				if why := tr.Reasons[k]; why != "" {
					if out[0].Reasons == nil {
						out[0].Reasons = map[string]string{}
					}
					out[0].Reasons[k] = why
				}
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

// Coverage reports, for every payload type that has a native declaration, how many of its profile keys translate, how many have a documented reason not to,
// and which have neither (these are the ones to look at after a schema update). Keys claimed by another declaration of the same payload type count there.
func Coverage(set *schemas.Set) []CoverageRow {
	table := aliasTable()
	var rows []CoverageRow
	types := EquivalentTypes()
	for _, pt := range types {
		prof, ok := set.Profile(pt)
		if !ok {
			continue
		}
		equiv := Equivalents()[pt]
		// A profile key counts as translated if any declaration has it.
		claimed := map[string]string{} // key -> declaration
		explained := map[string]bool{}
		for _, dt := range equiv {
			decl, ok := set.Declaration(dt)
			if !ok {
				continue
			}
			for _, k := range prof.Keys {
				if _, isCert := certificateKinds[pt]; isCert && k.Key == "PayloadContent" {
					claimed[k.Key] = dt
				} else if _, isCert := certificateKinds[pt]; isCert && k.Key == "Password" {
					explained[k.Key] = true
				} else if a, has := table[pt][k.Key]; has {
					if a.To == "" {
						explained[k.Key] = true
					} else if _, ok := resolve(decl.Keys, a.To); ok && claimed[k.Key] == "" {
						claimed[k.Key] = dt
					}
				} else if _, ok := findKey(decl.Keys, k.Key); ok && claimed[k.Key] == "" {
					claimed[k.Key] = dt
				}
			}
		}
		for _, dt := range equiv {
			decl, ok := set.Declaration(dt)
			if !ok {
				continue
			}
			row := CoverageRow{PayloadType: pt, Declaration: dt}
			for _, k := range prof.Keys {
				if strings.HasPrefix(k.Key, "Payload") {
					continue
				}
				row.ProfileKeys++
				switch {
				case claimed[k.Key] == dt:
					row.Translated++
				case claimed[k.Key] != "":
					// translated by another declaration of this payload type
				case explained[k.Key]:
					row.Explained++
				default:
					row.Unmapped = append(row.Unmapped, k.Key)
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
