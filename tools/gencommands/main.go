// gencommands turns Apple's MDM command definitions (github.com/apple/device-management, mdm/commands/*.yaml) into fleetcore/commands/commands.json,
// which the JSON command API embeds. Run it to move to a newer Apple release:
//
//	go run ./tools/gencommands -ref release                      (downloads the repository)
//	go run ./tools/gencommands -dir /path/to/device-management   (an existing checkout)
package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type osInfo struct {
	Introduced  string `json:"introduced,omitempty"`
	Deprecated  string `json:"deprecated,omitempty"`
	Removed     string `json:"removed,omitempty"`
	Supervised  bool   `json:"supervised,omitempty"`
	RequiresDEP bool   `json:"requires_dep,omitempty"`
}

type key struct {
	Key      string            `json:"key"`
	Type     string            `json:"type"`
	Required bool              `json:"required,omitempty"`
	Default  any               `json:"default,omitempty"`
	Allowed  []any             `json:"allowed,omitempty"`
	Min      *float64          `json:"min,omitempty"`
	Max      *float64          `json:"max,omitempty"`
	Format   string            `json:"format,omitempty"`
	Content  string            `json:"content,omitempty"`
	OS       map[string]osInfo `json:"os,omitempty"`
	Keys     []key             `json:"keys,omitempty"`
	// Recursive: the sub-keys repeat an enclosing level and are not checked.
	Recursive bool `json:"recursive,omitempty"`
}

type command struct {
	RequestType string            `json:"request_type"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Content     string            `json:"content,omitempty"`
	OS          map[string]osInfo `json:"os,omitempty"`
	Keys        []key             `json:"keys,omitempty"`
}

type file struct {
	Ref      string    `json:"ref"`
	Commands []command `json:"commands"`
}

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
	n = resolve(n)
	if n == nil {
		return ""
	}
	return n.Value
}

func val(n *yaml.Node) any {
	n = resolve(n)
	if n == nil {
		return nil
	}
	var v any
	_ = n.Decode(&v)
	return v
}

func osOf(n *yaml.Node) map[string]osInfo {
	out := map[string]osInfo{}
	for name, v := range mapOf(n) {
		m := mapOf(v)
		o := osInfo{Introduced: str(m["introduced"]), Deprecated: str(m["deprecated"]), Removed: str(m["removed"])}
		o.Supervised = str(m["supervised"]) == "true"
		o.RequiresDEP = str(m["requiresdep"]) == "true"
		out[name] = o
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func keyOf(n *yaml.Node, enclosing map[*yaml.Node]bool) key {
	m := mapOf(n)
	k := key{Key: str(m["key"]), Type: strings.Trim(str(m["type"]), "<>"), Required: str(m["presence"]) == "required", Content: str(m["content"]), Format: str(m["format"]), OS: osOf(m["supportedOS"])}
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
		for name, dst := range map[string]**float64{"min": &k.Min, "max": &k.Max} {
			if x, ok := val(r[name]).(int); ok {
				f := float64(x)
				*dst = &f
			} else if x, ok := val(r[name]).(float64); ok {
				*dst = &x
			}
		}
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

func parse(data []byte) (*command, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if len(root.Content) == 0 {
		return nil, nil
	}
	top := mapOf(root.Content[0])
	payload := mapOf(top["payload"])
	c := &command{RequestType: str(payload["requesttype"]), Title: str(top["title"]), Description: str(top["description"]), Content: str(payload["content"]), OS: osOf(payload["supportedOS"])}
	if c.RequestType == "" {
		return nil, nil
	}
	if pk := resolve(top["payloadkeys"]); pk != nil && pk.Kind == yaml.SequenceNode {
		for _, e := range pk.Content {
			c.Keys = append(c.Keys, keyOf(e, map[*yaml.Node]bool{pk: true}))
		}
	}
	return c, nil
}

func main() {
	dir := flag.String("dir", "", "checkout of apple/device-management")
	ref := flag.String("ref", "release", "git ref to download when -dir is not given")
	out := flag.String("out", "fleetcore/commands/commands.json", "output file")
	flag.Parse()

	f := file{Ref: *ref}
	add := func(name string, data []byte) {
		c, err := parse(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			os.Exit(1)
		}
		if c != nil {
			f.Commands = append(f.Commands, *c)
		}
	}
	if *dir != "" {
		entries, err := os.ReadDir(path.Join(*dir, "mdm/commands"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".yaml") {
				b, _ := os.ReadFile(path.Join(*dir, "mdm/commands", e.Name()))
				add(e.Name(), b)
			}
		}
	} else {
		resp, err := http.Get("https://codeload.github.com/apple/device-management/tar.gz/" + *ref)
		if err != nil || resp.StatusCode != 200 {
			fmt.Fprintln(os.Stderr, "download failed", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if strings.Contains(h.Name, "/mdm/commands/") && strings.HasSuffix(h.Name, ".yaml") {
				b, _ := io.ReadAll(tr)
				add(h.Name, b)
			}
		}
	}
	sort.Slice(f.Commands, func(i, j int) bool { return f.Commands[i].RequestType < f.Commands[j].RequestType })
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%d commands -> %s (%d bytes)\n", len(f.Commands), *out, len(b))
}
