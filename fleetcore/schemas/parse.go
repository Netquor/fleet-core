package schemas

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func mapOf(n *yaml.Node) map[string]*yaml.Node {
	n = resolve(n)
	out := map[string]*yaml.Node{}
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i+1]
	}
	return out
}

func str(n *yaml.Node) string {
	if n = resolve(n); n == nil {
		return ""
	}
	return n.Value
}

func val(n *yaml.Node) any {
	if n = resolve(n); n == nil {
		return nil
	}
	var v any
	_ = n.Decode(&v)
	return v
}

func boolPtr(n *yaml.Node) *bool {
	switch str(n) {
	case "true":
		t := true
		return &t
	case "false":
		f := false
		return &f
	}
	return nil
}

func strList(n *yaml.Node) []string {
	n = resolve(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, e := range n.Content {
		out = append(out, str(e))
	}
	return out
}

func osOf(n *yaml.Node) map[string]OSInfo {
	out := map[string]OSInfo{}
	for name, v := range mapOf(n) {
		m := mapOf(v)
		o := OSInfo{Introduced: str(m["introduced"]), Deprecated: str(m["deprecated"]), Removed: str(m["removed"]),
			Supervised: str(m["supervised"]) == "true", RequiresDEP: str(m["requiresdep"]) == "true",
			DeviceChannel: boolPtr(m["devicechannel"]), UserChannel: boolPtr(m["userchannel"])}
		if ue := mapOf(m["userenrollment"]); ue != nil {
			o.UserEnrollment = str(ue["mode"])
		}
		o.AllowedEnrollments = strList(m["allowed-enrollments"])
		o.AllowedScopes = strList(m["allowed-scopes"])
		out[name] = o
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func keyOf(n *yaml.Node, enclosing map[*yaml.Node]bool) Key {
	m := mapOf(n)
	k := Key{Key: str(m["key"]), Type: strings.Trim(str(m["type"]), "<>"), Required: str(m["presence"]) == "required", Content: str(m["content"]), Format: str(m["format"]), OS: osOf(m["supportedOS"])}
	if k.Type == "" {
		k.Type = "any"
	}
	if d := m["default"]; d != nil {
		k.Default = val(d)
	}
	if rl := resolve(m["rangelist"]); rl != nil && rl.Kind == yaml.SequenceNode {
		for _, e := range rl.Content {
			k.Allowed = append(k.Allowed, val(e))
		}
	}
	if r := mapOf(m["range"]); len(r) > 0 {
		num := func(n *yaml.Node) *float64 {
			switch x := val(n).(type) {
			case int:
				f := float64(x)
				return &f
			case float64:
				return &x
			}
			return nil
		}
		k.Min, k.Max = num(r["min"]), num(r["max"])
	}
	if sk := m["subkeys"]; sk != nil {
		list := resolve(sk)
		if enclosing[list] {
			k.Recursive = true
		} else if list.Kind == yaml.SequenceNode {
			inner := map[*yaml.Node]bool{list: true}
			for e := range enclosing {
				inner[e] = true
			}
			for _, e := range list.Content {
				k.Keys = append(k.Keys, keyOf(e, inner))
			}
		}
	}
	return k
}

func keysOf(n *yaml.Node) []Key {
	pk := resolve(n)
	if pk == nil || pk.Kind != yaml.SequenceNode {
		return nil
	}
	var out []Key
	for _, e := range pk.Content {
		out = append(out, keyOf(e, map[*yaml.Node]bool{pk: true}))
	}
	return out
}

func parseDoc(data []byte) (top map[string]*yaml.Node, payload map[string]*yaml.Node, err error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, err
	}
	if len(root.Content) == 0 {
		return nil, nil, nil
	}
	top = mapOf(root.Content[0])
	return top, mapOf(top["payload"]), nil
}

// Add parses one definition file from mdm/commands or mdm/profiles into the set.
func (s *Set) Add(kind string, data []byte) error {
	top, payload, err := parseDoc(data)
	if err != nil || top == nil {
		return err
	}
	switch kind {
	case "commands":
		if rt := str(payload["requesttype"]); rt != "" {
			s.Commands = append(s.Commands, &Command{RequestType: rt, Title: str(top["title"]), Description: str(top["description"]), Content: str(payload["content"]), OS: osOf(payload["supportedOS"]), Keys: keysOf(top["payloadkeys"])})
		}
	case "configuration", "activation", "asset", "management":
		if dt := str(payload["declarationtype"]); dt != "" {
			s.Declarations = append(s.Declarations, &Declaration{Type: dt, Kind: kind, Title: str(top["title"]), Description: str(top["description"]), Apply: str(payload["apply"]), OS: osOf(payload["supportedOS"]), Keys: keysOf(top["payloadkeys"])})
		}
	case "credential":
		if ct := str(payload["credentialtype"]); ct != "" {
			s.Credentials = append(s.Credentials, &Credential{Type: ct, Title: str(top["title"]), Description: str(top["description"]), OS: osOf(payload["supportedOS"]), Keys: keysOf(top["payloadkeys"])})
		}
	case "status":
		if n := str(payload["statusitemtype"]); n != "" {
			s.StatusItems = append(s.StatusItems, &StatusItem{Name: n, Title: str(top["title"]), Description: str(top["description"]), OS: osOf(payload["supportedOS"])})
		}
	case "profiles":
		if pt := str(payload["payloadtype"]); pt != "" {
			s.Profiles = append(s.Profiles, &Profile{PayloadType: pt, Title: str(top["title"]), Description: str(top["description"]), OS: osOf(payload["supportedOS"]), Keys: keysOf(top["payloadkeys"])})
		}
	}
	return nil
}

// ParseDir reads a checkout of apple/device-management.
func ParseDir(root, ref string) (*Set, error) {
	s := &Set{Ref: ref, FetchedAt: nowFunc()}
	for _, d := range []struct{ kind, dir string }{
		{"commands", "mdm/commands"}, {"profiles", "mdm/profiles"},
		{"configuration", "declarative/declarations/configurations"}, {"activation", "declarative/declarations/activations"},
		{"asset", "declarative/declarations/assets"}, {"credential", "declarative/declarations/assets/credentials"}, {"management", "declarative/declarations/management"}, {"status", "declarative/status"},
	} {
		entries, err := os.ReadDir(path.Join(root, d.dir))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			b, err := os.ReadFile(path.Join(root, d.dir, e.Name()))
			if err != nil {
				return nil, err
			}
			if err := s.Add(d.kind, b); err != nil {
				return nil, fmt.Errorf("%s/%s: %w", d.dir, e.Name(), err)
			}
		}
	}
	s.index()
	return s, nil
}

// ParseTarGz reads the repository archive GitHub serves for a ref.
func ParseTarGz(r io.Reader, ref string) (*Set, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	s := &Set{Ref: ref, FetchedAt: nowFunc()}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		kind := ""
		for marker, k := range map[string]string{
			"/mdm/commands/": "commands", "/mdm/profiles/": "profiles",
			"/declarative/declarations/configurations/": "configuration", "/declarative/declarations/activations/": "activation",
			"/declarative/declarations/assets/": "asset", "/declarative/declarations/assets/credentials/": "credential", "/declarative/declarations/management/": "management", "/declarative/status/": "status",
		} {
			if strings.Contains(h.Name, marker) && !strings.Contains(strings.SplitN(h.Name, marker, 2)[1], "/") {
				kind = k
			}
		}
		if kind == "" || !strings.HasSuffix(h.Name, ".yaml") {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 8<<20))
		if err != nil {
			return nil, err
		}
		if err := s.Add(kind, b); err != nil {
			return nil, fmt.Errorf("%s: %w", h.Name, err)
		}
	}
	s.index()
	return s, nil
}
