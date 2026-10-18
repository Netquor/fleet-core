package ddm

import (
	"testing"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

// Apple's schemas are the authority. These are the minimums they gave when this was written; if Apple's definitions change them, this fails and the documentation needs the new numbers.
func TestSupportMinimums(t *testing.T) {
	want := map[string]struct{ base, legacy, enforce, settings, status string }{
		"iOS and iPadOS": {"15.0", "15.0", "17.0", "18.0", "17.0"},
		"macOS":          {"13.0", "13.0", "14.0", "15.0", "14.0"},
		"tvOS":           {"16.0", "16.0", "18.4", "18.4", "18.4"},
		"visionOS":       {"1.1", "1.1", "26.0", "26.0", "26.0"},
		"watchOS":        {"10.0", "10.0", "n/a", "n/a", "n/a"},
	}
	for _, p := range Support(schemas.Embedded()) {
		w, ok := want[p.Platform]
		if !ok {
			t.Errorf("unexpected platform %s", p.Platform)
			continue
		}
		got := struct{ base, legacy, enforce, settings, status string }{p.Base, p.LegacyProfiles, p.SoftwareUpdate.Enforcement, p.SoftwareUpdate.Settings, p.SoftwareUpdate.StatusItems}
		if got != w {
			t.Errorf("%s: got %+v, want %+v", p.Platform, got, w)
		}
		if p.Configurations == 0 {
			t.Errorf("%s has no configuration types", p.Platform)
		}
	}
	// macOS software update enforcement is for supervised Macs only; the MDM commands are gone in 27.
	for _, p := range Support(schemas.Embedded()) {
		if p.Platform == "macOS" {
			if len(p.SoftwareUpdate.EnforcementEnrolled) != 1 || p.SoftwareUpdate.EnforcementEnrolled[0] != "supervised" || p.SoftwareUpdate.CommandsRemovedIn != "27.0" {
				t.Errorf("macOS: %+v", p.SoftwareUpdate)
			}
		}
	}
	if rows := SupportFor(schemas.Embedded(), "iPadOS"); len(rows) < 30 {
		t.Errorf("only %d declaration types for iPadOS", len(rows))
	}
}
