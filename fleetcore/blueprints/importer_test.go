package blueprints

import (
	"strings"
	"testing"
)

func TestParseCSVRecognizesCommonHeaders(t *testing.T) {
	rows, err := ParseCSV(strings.NewReader("Computer Name,Serial Number,Site,Assigned To\nkim-mbp,c02abc,\"Chicago; Engineering\",kim@example.com\n,C02DEF,,\n"), nil, "jamf")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Serial != "c02abc" || rows[0].Name != "kim-mbp" || len(rows[0].Groups) != 2 || rows[0].Groups[1] != "Engineering" || rows[0].User != "kim@example.com" || rows[0].Source != "jamf" {
		t.Errorf("%+v", rows)
	}
	if _, err := ParseCSV(strings.NewReader("Name,Owner\nx,y\n"), nil, ""); err == nil {
		t.Error("a file with no serial column was accepted")
	}
	rows, err = ParseCSV(strings.NewReader("Asset,Tag\nC02XYZ,eng\n"), map[string]string{"serial": "Asset", "tags": "Tag"}, "")
	if err != nil || len(rows) != 1 || rows[0].Serial != "C02XYZ" || rows[0].Tags[0] != "eng" {
		t.Errorf("columns=: %+v %v", rows, err)
	}
	if _, err := ParseCSV(strings.NewReader("a,b\n1,2\n"), map[string]string{"serial": "Nope"}, ""); err == nil {
		t.Error("a column that is not there was accepted")
	}
}

func TestImportAppliesAtEnrollmentAndToEnrolledDevices(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	_ = f.store.PutGroup(ctx, Group{ID: "chicago", Name: "Chicago"})
	_ = f.store.PutGroup(ctx, Group{ID: "dyn", Name: "Dynamic", Rule: &Rule{Field: "platform", Op: "eq", Value: "macOS"}})
	// a device that enrolled already
	f.device("OLD", "macOS", "15.0")
	res, err := f.store.Import(ctx, []Expected{
		{Serial: "sold", Name: "old-name", Groups: []string{"chicago"}, Tags: []string{"eng"}, Source: "jamf"},
		{Serial: "c02new", Name: "new-name", Groups: []string{"chicago", "emea"}, Tags: []string{"eng"}},
		{Serial: "c02dyn", Groups: []string{"dyn"}},
		{Serial: ""},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 2 || res.AlreadyEnrolled != 1 || len(res.Rejected) != 2 || len(res.GroupsCreated) != 1 || res.GroupsCreated[0] != "emea" {
		t.Errorf("%+v", res)
	}
	old, _ := f.store.GetDevice(ctx, "OLD")
	if old.Name != "old-name" || len(old.Groups) != 1 || old.Groups[0] != "chicago" || old.Tags[0] != "eng" {
		t.Errorf("the enrolled device was not updated: %+v", old)
	}
	// a device that enrolls later gets what was recorded, in uppercase serial form
	if err := f.store.UpsertDevice(ctx, DeviceUpdate{ID: "n1", UDID: "n1", Serial: "C02NEW", Platform: "macOS", OSVersion: "15.0"}, f.now); err != nil {
		t.Fatal(err)
	}
	n, _ := f.store.GetDevice(ctx, "n1")
	if n.Name != "new-name" || len(n.Groups) != 2 || n.Tags[0] != "eng" {
		t.Errorf("the new device did not get its imported settings: %+v", n)
	}
	// a name the device reports is not overwritten later by the import record
	if err := f.store.UpsertDevice(ctx, DeviceUpdate{ID: "n1", Name: "set-by-person"}, f.now); err != nil {
		t.Fatal(err)
	}
	n, _ = f.store.GetDevice(ctx, "n1")
	if n.Name != "set-by-person" {
		t.Errorf("name %q", n.Name)
	}
}
