package blueprints

import (
	"fmt"
	"strings"

	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Rule selects devices. A rule is either a combination (all, any, not) or a test of one field. An empty rule matches every device.
//
//	{"all":[{"field":"platform","op":"eq","value":"macOS"},{"field":"os_version","op":"gte","value":"14.0"}]}
//	{"field":"group","op":"eq","value":"Engineering"}
//
// Fields: platform, model, serial, name, os_version, dep_name, enroll_type, tag, group. Ops: eq, ne, in, nin, prefix, and gte/gt/lte/lt for os_version.
// For tag and group, eq means "has" and ne "does not have".
type Rule struct {
	All   []Rule `bson:"all,omitempty" json:"all,omitempty"`
	Any   []Rule `bson:"any,omitempty" json:"any,omitempty"`
	Not   *Rule  `bson:"not,omitempty" json:"not,omitempty"`
	Field string `bson:"field,omitempty" json:"field,omitempty"`
	Op    string `bson:"op,omitempty" json:"op,omitempty"`
	Value any    `bson:"value,omitempty" json:"value,omitempty"`
}

// GroupLookup resolves group names for rules; nil means no dynamic groups.
type GroupLookup func(name string) (*Group, bool)

// Env is what a rule needs to be made concrete: the groups it names and the newest shipping OS releases, for os_version "latest" (the newest release of the platform) and
// "latest-in-major" (the newest release of the device's own major version, for hardware that cannot move up).
type Env struct {
	Groups   GroupLookup
	Releases *osreleases.Catalog
}

var scalarFields = map[string]string{
	"platform": "platform", "model": "model", "serial": "serial", "name": "name", "dep_name": "dep_name", "enroll_type": "enroll_type",
}

func versionNum(v string) (int64, bool) { return schemas.VersionNum(v) }

// Validate reports a rule that cannot be evaluated.
func (r Rule) Validate() error { return r.validate(0) }

func (r Rule) validate(depth int) error {
	if depth > 8 {
		return fmt.Errorf("rule is nested too deeply")
	}
	set := 0
	if len(r.All) > 0 {
		set++
	}
	if len(r.Any) > 0 {
		set++
	}
	if r.Not != nil {
		set++
	}
	if r.Field != "" {
		set++
	}
	if set > 1 {
		return fmt.Errorf("a rule is one of all, any, not or a field test")
	}
	for _, c := range append(append([]Rule{}, r.All...), r.Any...) {
		if err := c.validate(depth + 1); err != nil {
			return err
		}
	}
	if r.Not != nil {
		return r.Not.validate(depth + 1)
	}
	if r.Field == "" {
		return nil
	}
	_, scalar := scalarFields[r.Field]
	switch {
	case scalar:
		switch r.Op {
		case "eq", "ne", "prefix":
			if _, ok := r.Value.(string); !ok {
				return fmt.Errorf("%s %s needs a string", r.Field, r.Op)
			}
		case "in", "nin":
			if _, ok := strList(r.Value); !ok {
				return fmt.Errorf("%s %s needs a list of strings", r.Field, r.Op)
			}
		default:
			return fmt.Errorf("%s does not support %q", r.Field, r.Op)
		}
	case r.Field == "tag" || r.Field == "group":
		switch r.Op {
		case "eq", "ne":
			if _, ok := r.Value.(string); !ok {
				return fmt.Errorf("%s %s needs a string", r.Field, r.Op)
			}
		case "in", "nin":
			if _, ok := strList(r.Value); !ok {
				return fmt.Errorf("%s %s needs a list of strings", r.Field, r.Op)
			}
		default:
			return fmt.Errorf("%s does not support %q", r.Field, r.Op)
		}
	case r.Field == "os_version":
		switch r.Op {
		case "eq", "ne", "gte", "gt", "lte", "lt":
			s, ok := r.Value.(string)
			if !ok {
				return fmt.Errorf("os_version needs a version string")
			}
			if s == "latest" || s == "latest-in-major" {
				return nil
			}
			if _, ok := versionNum(s); !ok {
				return fmt.Errorf("%q is not a version (like 14.2 or 15.0.1)", s)
			}
		default:
			return fmt.Errorf("os_version does not support %q", r.Op)
		}
	default:
		return fmt.Errorf("unknown field %q", r.Field)
	}
	return nil
}

func strList(v any) ([]string, bool) {
	switch t := v.(type) {
	case []string:
		return t, true
	case []any:
		out := make([]string, len(t))
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out[i] = s
		}
		return out, true
	case bson.A:
		return strList([]any(t))
	}
	return nil, false
}

// Expand replaces group tests with what they mean: a static group is a membership test on the device's groups, a dynamic group is its own rule (so a group can be defined in terms of others).
func (r Rule) Expand(env Env) (Rule, error) { return r.expand(env, 0) }

func (r Rule) expand(env Env, depth int) (Rule, error) {
	if depth > 8 {
		return r, fmt.Errorf("groups refer to each other too deeply")
	}
	out := Rule{Field: r.Field, Op: r.Op, Value: r.Value}
	for _, c := range r.All {
		e, err := c.expand(env, depth+1)
		if err != nil {
			return r, err
		}
		out.All = append(out.All, e)
	}
	for _, c := range r.Any {
		e, err := c.expand(env, depth+1)
		if err != nil {
			return r, err
		}
		out.Any = append(out.Any, e)
	}
	if r.Not != nil {
		e, err := r.Not.expand(env, depth+1)
		if err != nil {
			return r, err
		}
		out.Not = &e
	}
	if r.Field == "os_version" {
		if v, _ := r.Value.(string); v == "latest" || v == "latest-in-major" {
			return expandLatest(r, v, env)
		}
	}
	if r.Field != "group" {
		return out, nil
	}
	names, _ := strList(r.Value)
	if s, ok := r.Value.(string); ok {
		names = []string{s}
	}
	var alts []Rule
	for _, n := range names {
		g, ok := (*Group)(nil), false
		if env.Groups != nil {
			g, ok = env.Groups(n)
		}
		if ok && g.Rule != nil {
			e, err := g.Rule.expand(env, depth+1)
			if err != nil {
				return r, err
			}
			alts = append(alts, e)
		} else {
			// Static (or unknown, which then matches nobody): membership in the device's group list.
			alts = append(alts, Rule{Field: "member", Op: "eq", Value: n})
		}
	}
	var res Rule
	if len(alts) == 1 {
		res = alts[0]
	} else {
		res = Rule{Any: alts}
	}
	if r.Op == "ne" || r.Op == "nin" {
		return Rule{Not: &res}, nil
	}
	return res, nil
}

// Match tests a device. The rule must be expanded (no group tests).
func (r Rule) Match(d *Device) bool {
	switch {
	case len(r.All) > 0:
		for _, c := range r.All {
			if !c.Match(d) {
				return false
			}
		}
		return true
	case len(r.Any) > 0:
		for _, c := range r.Any {
			if c.Match(d) {
				return true
			}
		}
		return false
	case r.Not != nil:
		return !r.Not.Match(d)
	case r.Field == "":
		return true
	}
	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	switch r.Field {
	case "tag", "member":
		list := d.Tags
		if r.Field == "member" {
			list = d.Groups
		}
		return listTest(r, list, has)
	case "os_version":
		want, _ := versionNum(fmt.Sprint(r.Value))
		have := d.OSNum
		switch r.Op {
		case "eq":
			return have == want
		case "ne":
			return have != want
		case "gte":
			return have >= want
		case "gt":
			return have > want
		case "lte":
			return have <= want
		case "lt":
			return have < want
		}
		return false
	}
	var have string
	switch r.Field {
	case "platform":
		have = d.Platform
	case "model":
		have = d.Model
	case "serial":
		have = d.Serial
	case "name":
		have = d.Name
	case "dep_name":
		have = d.DEPName
	case "enroll_type":
		have = d.EnrollType
	}
	switch r.Op {
	case "eq":
		return have == fmt.Sprint(r.Value)
	case "ne":
		return have != fmt.Sprint(r.Value)
	case "prefix":
		return strings.HasPrefix(have, fmt.Sprint(r.Value))
	case "in", "nin":
		l, _ := strList(r.Value)
		return has(l, have) == (r.Op == "in")
	}
	return false
}

func listTest(r Rule, list []string, has func([]string, string) bool) bool {
	switch r.Op {
	case "eq":
		return has(list, fmt.Sprint(r.Value))
	case "ne":
		return !has(list, fmt.Sprint(r.Value))
	case "in", "nin":
		l, _ := strList(r.Value)
		any := false
		for _, v := range l {
			any = any || has(list, v)
		}
		return any == (r.Op == "in")
	}
	return false
}

// Filter compiles an expanded rule to a MongoDB filter on device documents, so "which devices does this hit" is an indexed query, not a scan in the application.
func (r Rule) Filter() bson.D {
	switch {
	case len(r.All) > 0:
		a := make(bson.A, len(r.All))
		for i, c := range r.All {
			a[i] = c.Filter()
		}
		return bson.D{{Key: "$and", Value: a}}
	case len(r.Any) > 0:
		a := make(bson.A, len(r.Any))
		for i, c := range r.Any {
			a[i] = c.Filter()
		}
		return bson.D{{Key: "$or", Value: a}}
	case r.Not != nil:
		return bson.D{{Key: "$nor", Value: bson.A{r.Not.Filter()}}}
	case r.Field == "":
		return bson.D{}
	}
	field := r.Field
	switch field {
	case "tag":
		field = "tags"
	case "member":
		field = "groups"
	case "os_version":
		field = "os_num"
	}
	if f, ok := scalarFields[r.Field]; ok {
		field = f
	}
	var val any = r.Value
	if r.Field == "os_version" {
		val, _ = versionNum(fmt.Sprint(r.Value))
	}
	switch r.Op {
	case "eq":
		return bson.D{{Key: field, Value: val}}
	case "ne":
		return bson.D{{Key: field, Value: bson.D{{Key: "$ne", Value: val}}}}
	case "gte", "gt", "lte", "lt":
		return bson.D{{Key: field, Value: bson.D{{Key: "$" + r.Op, Value: val}}}}
	case "prefix":
		return bson.D{{Key: field, Value: bson.D{{Key: "$regex", Value: "^" + regexpQuote(fmt.Sprint(r.Value))}}}}
	case "in", "nin":
		l, _ := strList(r.Value)
		op := "$in"
		if r.Op == "nin" {
			op = "$nin"
		}
		return bson.D{{Key: field, Value: bson.D{{Key: op, Value: l}}}}
	}
	return bson.D{{Key: "_id", Value: nil}} // unreachable for a validated rule: matches nothing
}

func regexpQuote(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

var releasePlatforms = []string{"macOS", "iOS", "iPadOS", "tvOS", "watchOS", "visionOS"}

// expandLatest turns "os_version <op> latest" into concrete tests per platform (and per major version for latest-in-major).
func expandLatest(r Rule, which string, env Env) (Rule, error) {
	if env.Releases == nil {
		return r, fmt.Errorf("os_version %q needs the Apple releases feed, which is not available", which)
	}
	test := func(op, version string) Rule { return Rule{Field: "os_version", Op: op, Value: version} }
	var alts []Rule
	for _, p := range releasePlatforms {
		plat := Rule{Field: "platform", Op: "eq", Value: p}
		if which == "latest" {
			if rel, ok := env.Releases.Latest(p); ok {
				alts = append(alts, Rule{All: []Rule{plat, test(r.Op, rel.Version)}})
			}
			continue
		}
		for _, m := range env.Releases.Majors(p) {
			rel, ok := env.Releases.LatestInMajor(p, m)
			if !ok {
				continue
			}
			alts = append(alts, Rule{All: []Rule{plat, test("gte", fmt.Sprintf("%d.0", m)), test("lt", fmt.Sprintf("%d.0", m+1)), test(r.Op, rel.Version)}})
		}
	}
	if len(alts) == 0 {
		return Rule{Field: "serial", Op: "in", Value: []string{}}, nil // matches nothing
	}
	return Rule{Any: alts}, nil
}
