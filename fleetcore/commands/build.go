package commands

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"github.com/micromdm/plist"
)

// Problem is one thing wrong with a request, at a path into its params ("Queries[1]", "ReturnToService.Enabled").
type Problem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (p Problem) Error() string {
	if p.Path == "" {
		return p.Message
	}
	return p.Path + ": " + p.Message
}

// Options tune Build.
type Options struct {
	// Platform (macOS, iOS, tvOS, visionOS, watchOS), if known, rejects commands and keys that do not exist there.
	Platform string
	// OSVersion, if known with Platform, rejects commands Apple has removed by that version and keys it has removed.
	OSVersion string
	// CommandUUID to use; empty makes a random one.
	CommandUUID string
}

// Build checks params against the command's schema and, if they are valid, returns the command plist for a device and its CommandUUID.
// Types follow JSON: numbers for integers and reals, base64 strings for data, RFC 3339 strings for dates.
func Build(c *Command, params map[string]any, o Options) (plistXML []byte, uuid string, problems []Problem) {
	if o.Platform != "" {
		if info, ok := c.OS[schemas.SchemaOS(o.Platform)]; ok && info.UnsupportedOn(o.OSVersion) {
			msg := c.RequestType + " does not exist on " + o.Platform
			if info.Removed != "" && info.Removed != "n/a" && o.OSVersion != "" {
				msg = c.RequestType + " was removed in " + o.Platform + " " + info.Removed + "; use a declarative management configuration instead"
			}
			problems = append(problems, Problem{Message: msg})
		}
	}
	body, ps := convertDict(c.Keys, params, "", o.Platform)
	problems = append(problems, ps...)
	if len(problems) > 0 {
		return nil, "", problems
	}
	uuid = o.CommandUUID
	if uuid == "" {
		uuid = newUUID()
	}
	cmd := map[string]any{"RequestType": c.RequestType}
	for k, v := range body {
		cmd[k] = v
	}
	out, err := plist.MarshalIndent(map[string]any{"CommandUUID": uuid, "Command": cmd}, "  ")
	if err != nil {
		return nil, "", []Problem{{Message: "cannot encode the command: " + err.Error()}}
	}
	return out, uuid, nil
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]))
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func isWildcard(k string) bool { return k == "ANY" || strings.HasPrefix(k, "ANY ") }

// convertDict validates a dictionary against its keys and returns it converted for the plist.
func convertDict(keys []Key, in map[string]any, path, platform string) (map[string]any, []Problem) {
	var problems []Problem
	out := make(map[string]any, len(in))
	var wild *Key
	known := make(map[string]*Key, len(keys))
	for i := range keys {
		if isWildcard(keys[i].Key) {
			wild = &keys[i]
			continue
		}
		known[keys[i].Key] = &keys[i]
	}
	for _, k := range keys {
		if k.Required && !isWildcard(k.Key) {
			if _, ok := in[k.Key]; !ok {
				problems = append(problems, Problem{Path: join(path, k.Key), Message: "is required"})
			}
		}
	}
	for name, v := range in {
		p := join(path, name)
		k, ok := known[name]
		if !ok {
			switch {
			case wild != nil:
				k = wild
			case len(keys) == 0:
				// A dictionary the schema does not describe: take it as given.
				out[name] = loose(v)
				continue
			default:
				problems = append(problems, Problem{Path: p, Message: "is not a key of this command"})
				continue
			}
		}
		if platform != "" {
			if info, has := k.OS[schemas.SchemaOS(platform)]; has && info.Introduced == "n/a" {
				problems = append(problems, Problem{Path: p, Message: "does not exist on " + platform})
				continue
			}
		}
		cv, ps := convertValue(k, v, p, platform)
		problems = append(problems, ps...)
		if len(ps) == 0 {
			out[name] = cv
		}
	}
	return out, problems
}

func convertValue(k *Key, v any, path, platform string) (any, []Problem) {
	bad := func(msg string) (any, []Problem) { return nil, []Problem{{Path: path, Message: msg}} }
	var out any
	switch k.Type {
	case "string":
		s, ok := v.(string)
		if !ok {
			return bad("must be a string")
		}
		if k.Format != "" {
			if re, err := regexp.Compile(k.Format); err == nil && !re.MatchString(s) {
				return bad("does not match the format " + k.Format)
			}
		}
		out = s
	case "boolean":
		b, ok := v.(bool)
		if !ok {
			return bad("must be true or false")
		}
		out = b
	case "integer":
		n, ok := asInt(v)
		if !ok {
			return bad("must be an integer")
		}
		if msg := checkRange(k, float64(n)); msg != "" {
			return bad(msg)
		}
		out = n
	case "real":
		f, ok := asFloat(v)
		if !ok {
			return bad("must be a number")
		}
		if msg := checkRange(k, f); msg != "" {
			return bad(msg)
		}
		out = f
	case "data":
		s, ok := v.(string)
		if !ok {
			return bad("must be a base64 string")
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return bad("is not valid base64")
		}
		out = b
	case "date":
		s, ok := v.(string)
		if !ok {
			return bad("must be an RFC 3339 date string")
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return bad("is not an RFC 3339 date")
		}
		out = t.UTC()
	case "dictionary":
		m, ok := v.(map[string]any)
		if !ok {
			return bad("must be an object")
		}
		if k.Recursive {
			return loose(m), nil
		}
		return convertDict(k.Keys, m, path, platform)
	case "array":
		arr, ok := v.([]any)
		if !ok {
			return bad("must be an array")
		}
		return convertArray(k, arr, path, platform)
	default: // any
		return loose(v), nil
	}
	if len(k.Allowed) > 0 && !allowed(k.Allowed, out) {
		return bad(fmt.Sprintf("must be one of %s", listAllowed(k.Allowed)))
	}
	return out, nil
}

// Apple describes an array by its element: one sub-key is the element's schema. Several sub-keys are alternative shapes of a dictionary (the Settings command): each element must be an object,
// and what is inside is left to the device.
func convertArray(k *Key, arr []any, path, platform string) (any, []Problem) {
	var problems []Problem
	out := make([]any, 0, len(arr))
	for i, e := range arr {
		p := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case len(k.Keys) == 1:
			el := k.Keys[0]
			if el.Type != "dictionary" {
				el.Keys = nil // sub-keys of a scalar element only document its values
			}
			cv, ps := convertValue(&el, e, p, platform)
			problems = append(problems, ps...)
			out = append(out, cv)
		case len(k.Keys) > 1:
			if _, ok := e.(map[string]any); !ok {
				problems = append(problems, Problem{Path: p, Message: "must be an object"})
				continue
			}
			out = append(out, loose(e))
		default:
			out = append(out, loose(e))
		}
	}
	return out, problems
}

// loose converts JSON values that no schema describes: whole numbers become integers.
func loose(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = loose(e)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, e := range t {
			a[i] = loose(e)
		}
		return a
	case json.Number:
		if n, ok := asInt(t); ok {
			return n
		}
		f, _ := t.Float64()
		return f
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1<<53 {
			return int64(t)
		}
	}
	return v
}

func asInt(v any) (int64, bool) {
	switch t := v.(type) {
	case json.Number:
		n, err := t.Int64()
		return n, err == nil
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1<<53 {
			return int64(t), true
		}
	case int:
		return int64(t), true
	case int64:
		return t, true
	}
	return 0, false
}

func asFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return 0, false
}

func checkRange(k *Key, f float64) string {
	if k.Min != nil && f < *k.Min {
		return fmt.Sprintf("must be at least %v", *k.Min)
	}
	if k.Max != nil && f > *k.Max {
		return fmt.Sprintf("must be at most %v", *k.Max)
	}
	return ""
}

func allowed(list []any, v any) bool {
	for _, a := range list {
		switch x := v.(type) {
		case int64:
			if n, ok := asInt(a); ok && n == x {
				return true
			}
		case float64:
			if f, ok := asFloat(a); ok && f == x {
				return true
			}
		default:
			if fmt.Sprint(a) == fmt.Sprint(v) {
				return true
			}
		}
	}
	return false
}

func listAllowed(list []any) string {
	parts := make([]string, len(list))
	for i, a := range list {
		parts[i] = fmt.Sprint(a)
	}
	return strings.Join(parts, ", ")
}
