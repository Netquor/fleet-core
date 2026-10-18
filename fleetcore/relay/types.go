package relay

import (
	"sort"
	"strings"
)

// EventType describes one kind of event.
type EventType struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Key         string   `json:"key"`  // what Event.Key is
	Data        []string `json:"data"` // the fields of Event.Data
}

// Catalog lists every event the relay can publish.
var Catalog = []EventType{
	{"enrollment.created", "An enrollment (device or user channel) was created.", "enrollment ID", []string{"enrollment", "type"}},
	{"enrollment.checkout", "An enrollment checked out or was disabled.", "enrollment ID", []string{"enrollment"}},
	{"device.enrolled", "A device appeared in the inventory.", "device ID", []string{"device", "serial", "platform", "model"}},
	{"device.os_changed", "A device reported a different OS version.", "device ID", []string{"device", "os_version"}},
	{"device.renamed", "A device's name changed.", "device ID", []string{"device", "name"}},
	{"device.supervision_changed", "A device's supervision state became known or changed.", "device ID", []string{"device", "supervised"}},
	{"device.membership_changed", "A device's static groups or tags changed.", "device ID", []string{"device", "groups", "tags"}},
	{"device.deactivated", "A device checked out of management.", "device ID", []string{"device"}},
	{"device.lost_mode_changed", "Lost Mode was turned on or off for a device.", "device ID", []string{"device", "enabled"}},
	{"device.certificate_associated", "A device identity certificate was associated with an enrollment.", "enrollment ID", []string{"enrollment"}},
	{"command.queued", "A command was queued for an enrollment.", "enrollment ID", []string{"enrollment", "command_uuid"}},
	{"command.result", "An enrollment answered a command.", "enrollment ID", []string{"enrollment", "command_uuid", "status"}},
	{"application.state", "A blueprint item changed state on a device.", "device ID", []string{"device", "blueprint", "item", "state"}},
	{"blueprint.saved", "A blueprint was created or changed.", "blueprint ID", []string{"blueprint"}},
	{"blueprint.deleted", "A blueprint was deleted.", "blueprint ID", []string{"blueprint"}},
	{"blueprint.revision", "A blueprint revision was recorded.", "blueprint ID", []string{"blueprint", "revision"}},
	{"group.saved", "A group was created or changed.", "group ID", []string{"group"}},
	{"group.deleted", "A group was deleted.", "group ID", []string{"group"}},
	{"vault.access", "A device secret was stored, revealed or removed (the secret is never in the event).", "device ID", []string{"device", "kind", "action", "who", "reason"}},
	{"dep.device.assigned", "Apple assigned a device to this server.", "serial number", []string{"serial"}},
	{"dep.device.removed", "Apple took a device back.", "serial number", []string{"serial"}},
	{"os.release.published", "A new OS release became known.", "platform|version", []string{"platform", "version"}},
	{"schema.updated", "A new snapshot of Apple's device-management definitions was adopted.", "snapshot ref", []string{"ref"}},
	{"applicability.changed", "A platform applicability override changed.", "override ID", []string{"id"}},
	{"test", "A test event sent from the API.", "subscription ID", []string{"subscription"}},
}

// Match reports whether a type is selected by patterns: empty selects everything; "*" everything; "command.*" a prefix; otherwise an exact type.
func Match(patterns []string, typ string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		switch {
		case p == "*" || p == typ:
			return true
		case strings.HasSuffix(p, ".*") && strings.HasPrefix(typ, strings.TrimSuffix(p, "*")):
			return true
		}
	}
	return false
}

// ValidPatterns reports a pattern that selects no known type.
func ValidPatterns(patterns []string) (bad string) {
	for _, p := range patterns {
		hit := false
		for _, t := range Catalog {
			if Match([]string{p}, t.Type) {
				hit = true
				break
			}
		}
		if !hit {
			return p
		}
	}
	return ""
}

// SplitList splits a comma-separated list.
func SplitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
