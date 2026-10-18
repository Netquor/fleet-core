package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/micromdm/plist"
)

func req(t *testing.T, typ, params string, o Options) ([]byte, string, []Problem) {
	t.Helper()
	cmd, ok := Default().Get(typ)
	if !ok {
		t.Fatalf("no command %s", typ)
	}
	var p map[string]any
	d := json.NewDecoder(strings.NewReader(params))
	d.UseNumber()
	if err := d.Decode(&p); err != nil {
		t.Fatal(err)
	}
	return cmd.Build(p, o)
}

func TestCatalog(t *testing.T) {
	c := Default()
	if len(c.Commands) < 60 {
		t.Fatalf("only %d commands", len(c.Commands))
	}
	for _, name := range []string{"DeviceInformation", "InstallProfile", "InstallApplication", "EraseDevice", "Settings", "ScheduleOSUpdate"} {
		if _, ok := c.Get(name); !ok {
			t.Errorf("%s missing", name)
		}
	}
	if cmd, _ := c.Get("EraseDevice"); !cmd.Destructive {
		t.Error("EraseDevice is not marked destructive")
	}
}

func TestBuildValid(t *testing.T) {
	out, uuid, ps := req(t, "DeviceInformation", `{"Queries":["SerialNumber","OSVersion"]}`, Options{CommandUUID: "ABC"})
	if len(ps) > 0 || uuid != "ABC" {
		t.Fatalf("%v %s", ps, uuid)
	}
	var back struct {
		CommandUUID string
		Command     struct {
			RequestType string
			Queries     []string
		}
	}
	if err := plist.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back.CommandUUID != "ABC" || back.Command.RequestType != "DeviceInformation" || len(back.Command.Queries) != 2 {
		t.Errorf("%+v", back)
	}
	// data becomes <data>, integers stay integers
	out, _, ps = req(t, "InstallProfile", `{"Payload":"aGVsbG8="}`, Options{})
	if len(ps) > 0 || !strings.Contains(string(out), "<data>") {
		t.Errorf("%v\n%s", ps, out)
	}
	if _, uuid, _ := req(t, "RestartDevice", `{}`, Options{}); len(uuid) != 36 {
		t.Errorf("generated uuid %q", uuid)
	}
}

func TestBuildProblems(t *testing.T) {
	cases := []struct{ typ, params, want string }{
		{"DeviceInformation", `{}`, "Queries: is required"},
		{"DeviceInformation", `{"Queries":"SerialNumber"}`, "must be an array"},
		{"DeviceInformation", `{"Queries":[1]}`, "Queries[0]: must be a string"},
		{"DeviceInformation", `{"Queries":["X"],"Bogus":1}`, "Bogus: is not a key"},
		{"InstallProfile", `{"Payload":"not base64!"}`, "not valid base64"},
		{"InstallProfile", `{"Payload":5}`, "must be a base64 string"},
		{"RestartDevice", `{"NotifyUser":"yes"}`, "must be true or false"},
	}
	for _, c := range cases {
		_, _, ps := req(t, c.typ, c.params, Options{})
		var got []string
		for _, p := range ps {
			got = append(got, p.Error())
		}
		if !strings.Contains(strings.Join(got, "|"), c.want) {
			t.Errorf("%s %s: got %v, want %q", c.typ, c.params, got, c.want)
		}
	}
}

func TestPlatformAndAllowedValues(t *testing.T) {
	// A command that does not exist on a platform.
	for _, c := range Default().Commands {
		if info, ok := c.OS["macOS"]; ok && info.Introduced == "n/a" {
			if _, _, ps := c.Build(map[string]any{}, Options{Platform: "macOS"}); len(ps) == 0 {
				t.Errorf("%s accepted on macOS", c.RequestType)
			}
			break
		}
	}
	// A value outside the allowed list.
	checked := false
	for _, c := range Default().Commands {
		for _, k := range c.Keys {
			if k.Type == "string" && len(k.Allowed) > 0 && !k.Required {
				_, _, ps := c.Build(map[string]any{k.Key: "definitely-not-allowed"}, Options{})
				found := false
				for _, p := range ps {
					found = found || strings.Contains(p.Message, "must be one of")
				}
				if !found {
					t.Errorf("%s.%s took a disallowed value: %v", c.RequestType, k.Key, ps)
				}
				checked = true
			}
		}
	}
	if !checked {
		t.Error("no key with allowed values found")
	}
}

// Every command must build from the empty request or say what is missing (nothing may panic, whatever the schema holds).
func TestEveryCommandBuilds(t *testing.T) {
	for _, c := range Default().Commands {
		out, _, ps := c.Build(map[string]any{}, Options{})
		if len(ps) == 0 && !strings.Contains(string(out), c.RequestType) {
			t.Errorf("%s: %s", c.RequestType, out)
		}
		for _, p := range ps {
			if !strings.Contains(p.Message, "required") {
				t.Errorf("%s: %v", c.RequestType, p)
			}
		}
	}
}
