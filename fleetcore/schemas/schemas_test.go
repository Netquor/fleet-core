package schemas

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedSnapshot(t *testing.T) {
	s := Embedded()
	if len(s.Commands) < 60 || len(s.Profiles) < 100 {
		t.Fatalf("%d commands, %d profiles", len(s.Commands), len(s.Profiles))
	}
	c, ok := s.Command("ScheduleOSUpdate")
	if !ok {
		t.Fatal("no ScheduleOSUpdate")
	}
	info := c.OS["macOS"]
	if info.Removed == "" || !info.UnsupportedOn("27.0") || info.UnsupportedOn("15.0") || !info.DeprecatedOn("26.1") {
		t.Errorf("ScheduleOSUpdate on macOS: %+v", info)
	}
	if p, ok := s.Profile("com.apple.applicationaccess"); !ok || len(p.Keys) < 50 {
		t.Errorf("restrictions payload: %v", ok)
	}
}

func TestVersionNum(t *testing.T) {
	for in, want := range map[string]int64{"15": 15000000, "15.1": 15001000, "15.1.1": 15001001, "10.15.4": 10015004} {
		if got, ok := VersionNum(in); !ok || got != want {
			t.Errorf("%s: %d %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "a.b", "1.2.3.4", "1.1000"} {
		if _, ok := VersionNum(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func archive(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestParseTarGz(t *testing.T) {
	data := archive(t, map[string]string{
		"dm-abc/mdm/commands/x.yaml": "title: X\npayload:\n  requesttype: DoThing\n  supportedOS:\n    macOS:\n      introduced: '12.0'\n    iOS:\n      introduced: n/a\npayloadkeys:\n- key: Level\n  type: <integer>\n  presence: required\n  range:\n    min: 1\n    max: 3\n",
		"dm-abc/mdm/profiles/y.yaml": "title: Y\npayload:\n  payloadtype: com.example.y\n  supportedOS:\n    macOS:\n      introduced: '12.0'\n",
		"dm-abc/README.md":           "ignored",
	})
	s, err := ParseTarGz(bytes.NewReader(data), "abc")
	if err != nil {
		t.Fatal(err)
	}
	c, ok := s.Command("DoThing")
	if !ok || len(c.Keys) != 1 || !c.Keys[0].Required || *c.Keys[0].Max != 3 || !c.OS["iOS"].Unsupported() {
		t.Fatalf("%+v", c)
	}
	if _, ok := s.Profile("com.example.y"); !ok {
		t.Error("profile missing")
	}
}

func TestRefresherSwitchesAndRefusesShrunkenRelease(t *testing.T) {
	old := Current()
	defer Use(old)
	base := &Set{Ref: "old"}
	for i := 0; i < 10; i++ {
		base.Commands = append(base.Commands, &Command{RequestType: fmt.Sprintf("C%d", i)})
		base.Profiles = append(base.Profiles, &Profile{PayloadType: fmt.Sprintf("p.%d", i)})
	}
	Use(base)

	files := map[string]string{}
	for i := 0; i < 10; i++ {
		files[fmt.Sprintf("r/mdm/commands/c%d.yaml", i)] = fmt.Sprintf("title: t\npayload:\n  requesttype: C%d\n", i)
		files[fmt.Sprintf("r/mdm/profiles/p%d.yaml", i)] = fmt.Sprintf("title: t\npayload:\n  payloadtype: p.%d\n", i)
	}
	files["r/mdm/commands/new.yaml"] = "title: New\npayload:\n  requesttype: BrandNewCommand\n"
	good := archive(t, files)
	tiny := archive(t, map[string]string{"r/mdm/commands/a.yaml": "title: t\npayload:\n  requesttype: Only\n"})
	serve := good
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sha":"` + strings.Repeat("a", 40) + `"}`))
	}))
	defer api.Close()
	dl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(serve) }))
	defer dl.Close()

	r := &Refresher{Ref: "release", APIBase: api.URL, DownloadBase: dl.URL}
	s, changed, err := r.Check(context.Background())
	if err != nil || !changed || s.Ref != strings.Repeat("a", 40) {
		t.Fatalf("%v %v %+v", err, changed, s)
	}
	if _, ok := Current().Command("BrandNewCommand"); !ok {
		t.Error("the new command is not available after a refresh")
	}
	// Same release again: nothing to do.
	if _, changed, _ := r.Check(context.Background()); changed {
		t.Error("changed with the same ref")
	}
	// A new ref that lost most definitions is refused.
	api.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sha":"` + strings.Repeat("b", 40) + `"}`))
	})
	serve = tiny
	if _, changed, err := r.Check(context.Background()); changed || err == nil {
		t.Errorf("a shrunken release was accepted: %v %v", changed, err)
	}
	if _, ok := Current().Command("BrandNewCommand"); !ok {
		t.Error("the good set was lost")
	}
}

func TestCredentialDocumentsAreInTheSnapshot(t *testing.T) {
	set := Embedded()
	for _, ct := range []string{"com.apple.credential.scep", "com.apple.credential.acme"} {
		c, ok := set.Credential(ct)
		if !ok || len(c.Keys) == 0 {
			t.Errorf("%s missing from the snapshot", ct)
		}
	}
}
