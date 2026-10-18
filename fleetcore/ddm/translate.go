package ddm

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

//go:embed translate_aliases.json
var aliasesJSON []byte

type alias struct {
	To          string `json:"to"`
	Invert      bool   `json:"invert,omitempty"`
	Approximate bool   `json:"approximate,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Translation is a configuration profile payload expressed as a declaration.
type Translation struct {
	// Declaration is the declaration type the payload was translated to.
	Declaration string `json:"declaration"`
	// Payload is the declaration's payload; check it before use.
	Payload map[string]any `json:"payload"`
	// Approximate lists profile keys that were translated to the closest setting, with why.
	Approximate map[string]string `json:"approximate,omitempty"`
	// Untranslated lists profile keys with no counterpart found: they are not in Payload and need a person's decision.
	Untranslated []string `json:"untranslated,omitempty"`
}

func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Translate expresses one payload of a profile (its keys, without the Payload* base keys) as the declaration that replaces it. Keys match by the explicit table
// (translate_aliases.json, for settings Apple renamed), then by name ignoring case and punctuation; a profile key with neither is reported, never guessed.
// declType picks among several equivalents; empty takes the first.
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
	def, ok := set.Declaration(declType)
	if !ok {
		return nil, false
	}
	table := map[string]map[string]alias{}
	_ = json.Unmarshal(aliasesJSON, &table)
	aliases := table[payloadType]
	byNorm := map[string]string{}
	for _, k := range def.Keys {
		byNorm[norm(k.Key)] = k.Key
	}
	tr := &Translation{Declaration: declType, Payload: map[string]any{}, Approximate: map[string]string{}}
	for key, val := range payload {
		if strings.HasPrefix(key, "Payload") {
			continue
		}
		if a, ok := aliases[key]; ok {
			if b, isBool := val.(bool); isBool && a.Invert {
				if !b { // allowSimple false -> complex true; allowSimple true says nothing
					tr.Payload[a.To] = true
				}
			} else if !a.Invert {
				tr.Payload[a.To] = val
			}
			if a.Approximate {
				tr.Approximate[key] = a.Note
			}
			continue
		}
		if to, ok := byNorm[norm(key)]; ok {
			tr.Payload[to] = val
			continue
		}
		tr.Untranslated = append(tr.Untranslated, key)
	}
	sort.Strings(tr.Untranslated)
	if len(tr.Approximate) == 0 {
		tr.Approximate = nil
	}
	return tr, true
}
