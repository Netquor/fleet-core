package ddm

import (
	"sort"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
)

// PlatformSupport says, for one platform, from which OS version each part of declarative management is available and to which enrollments. It is read from Apple's schemas in use,
// so it changes when Apple's definitions do.
type PlatformSupport struct {
	Platform string `json:"platform"`
	// Base is the first OS version that takes declarative management at all (the status channel and activations).
	Base string `json:"base"`
	// LegacyProfiles is the first version that can take a configuration profile as a declaration.
	LegacyProfiles string `json:"legacy_profiles"`
	// SoftwareUpdate: enforcement of a specific OS version, update settings, and the status items that follow an update. "n/a" where the platform has none.
	SoftwareUpdate SoftwareUpdateSupport `json:"software_update"`
	// Configurations is how many configuration types the platform has.
	Configurations int `json:"configurations"`
	// Enrollments a baseline declaration allows on this platform.
	Enrollments []string `json:"base_enrollments"`
}

// SoftwareUpdateSupport is the software-update part of a PlatformSupport.
type SoftwareUpdateSupport struct {
	Enforcement         string   `json:"enforcement"`
	EnforcementEnrolled []string `json:"enforcement_enrollments,omitempty"`
	Settings            string   `json:"settings"`
	StatusItems         string   `json:"status_items"`
	// CommandsRemovedIn is the version that removes the MDM software-update commands, so a device at or past it can only be updated declaratively.
	CommandsRemovedIn string `json:"mdm_commands_removed_in,omitempty"`
}

// Row is one declaration type on one platform.
type Row struct {
	Type        string   `json:"type"`
	Kind        string   `json:"kind"`
	Introduced  string   `json:"introduced"`
	Enrollments []string `json:"enrollments,omitempty"`
	Apply       string   `json:"apply,omitempty"`
}

// Support builds the per-platform summary. iPadOS shares iOS (Apple's schemas list them together).
func Support(set *schemas.Set) []PlatformSupport {
	intro := func(declType, os string) (string, []string) {
		if d, ok := set.Declaration(declType); ok {
			if i, ok := d.OS[os]; ok {
				return i.Introduced, i.AllowedEnrollments
			}
		}
		return "n/a", nil
	}
	cmdRemoved := func(os string) string {
		for _, rt := range []string{"ScheduleOSUpdate", "AvailableOSUpdates", "OSUpdateStatus"} {
			if c, ok := set.Command(rt); ok {
				if i, ok := c.OS[os]; ok && i.Removed != "" && i.Removed != "n/a" {
					return i.Removed
				}
			}
		}
		return ""
	}
	var out []PlatformSupport
	for _, os := range []string{"iOS", "macOS", "tvOS", "visionOS", "watchOS"} {
		base, enr := intro("com.apple.configuration.management.status-subscriptions", os)
		legacy, _ := intro("com.apple.configuration.legacy", os)
		enf, enfEnr := intro("com.apple.configuration.softwareupdate.enforcement.specific", os)
		settings, _ := intro("com.apple.configuration.softwareupdate.settings", os)
		status := "n/a"
		if s, ok := set.StatusItem("softwareupdate.install-state"); ok {
			if i, ok := s.OS[os]; ok {
				status = i.Introduced
			}
		}
		n := 0
		for _, d := range set.Declarations {
			if d.Kind == KindConfiguration {
				if i, ok := d.OS[os]; ok && i.Introduced != "n/a" {
					n++
				}
			}
		}
		name := os
		if os == "iOS" {
			name = "iOS and iPadOS"
		}
		out = append(out, PlatformSupport{Platform: name, Base: base, LegacyProfiles: legacy, Configurations: n, Enrollments: enr,
			SoftwareUpdate: SoftwareUpdateSupport{Enforcement: enf, EnforcementEnrolled: enfEnr, Settings: settings, StatusItems: status, CommandsRemovedIn: cmdRemoved(os)}})
	}
	return out
}

// SupportFor lists every declaration type available on a platform, with the first OS version and the enrollments that take it.
func SupportFor(set *schemas.Set, platform string) []Row {
	os := schemas.SchemaOS(platform)
	var out []Row
	for _, d := range set.Declarations {
		if i, ok := d.OS[os]; ok && i.Introduced != "n/a" && i.Introduced != "" {
			out = append(out, Row{Type: d.Type, Kind: d.Kind, Introduced: i.Introduced, Enrollments: i.AllowedEnrollments, Apply: d.Apply})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}
