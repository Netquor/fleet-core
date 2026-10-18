package relay

import (
	"strings"
	"time"
)

// watched are the collections the change stream follows.
var watched = []string{"enrollments", "enrollment_queue", "cert_auth_associations", "bp_devices", "bp_applied", "bp_blueprints", "bp_revisions", "bp_groups", "vault_audit", "dep_devices", "os_releases", "schema_sets", "applicability"}

func idTail(c *changed) string {
	if k, ok := c.DocumentKey.ID.(string); ok {
		return k[strings.LastIndex(k, "\x1f")+1:]
	}
	return ""
}

// mapChange turns a change into the events it means (a device update can mean several). Only identifiers and states leave the database here; sealed or secret fields are never read.
func (r *Relay) mapChange(c *changed) []Event {
	at := time.Unix(int64(c.At.T), 0).UTC()
	var out []Event
	add := func(typ, key string, data map[string]any) {
		if key == "" {
			return
		}
		out = append(out, Event{Type: typ, Key: key, Data: data, At: at, Origin: r.origin()})
	}
	insert := c.Operation == "insert"
	update := c.Operation == "update" || c.Operation == "replace"
	del := c.Operation == "delete"
	changedField := func(f string) (any, bool) { v, ok := c.Description.Updated[f]; return v, ok }
	switch c.NS.Coll {
	case "enrollments":
		id := str(c.Full, "id")
		if insert {
			add("enrollment.created", id, map[string]any{"enrollment": id, "type": str(c.Full, "type")})
		} else if en, ok := changedField("enabled"); update && ok {
			if b, isBool := en.(bool); isBool && !b {
				add("enrollment.checkout", id, map[string]any{"enrollment": id})
			}
		}
	case "cert_auth_associations":
		if insert {
			add("device.certificate_associated", str(c.Full, "id"), map[string]any{"enrollment": str(c.Full, "id")})
		}
	case "enrollment_queue":
		id, uuid := str(c.Full, "id"), str(c.Full, "command_uuid")
		if insert {
			add("command.queued", id, map[string]any{"enrollment": id, "command_uuid": uuid})
		} else if st, ok := changedField("status"); update && ok {
			if s, isStr := st.(string); isStr && s != "" {
				add("command.result", id, map[string]any{"enrollment": id, "command_uuid": uuid, "status": s})
			}
		}
	case "bp_devices":
		id := str(c.Full, "id")
		if insert {
			add("device.enrolled", id, map[string]any{"device": id, "serial": str(c.Full, "serial"), "platform": str(c.Full, "platform"), "model": str(c.Full, "model")})
			break
		}
		if !update {
			break
		}
		if _, ok := changedField("os_version"); ok {
			add("device.os_changed", id, map[string]any{"device": id, "os_version": str(c.Full, "os_version")})
		}
		if _, ok := changedField("name"); ok {
			add("device.renamed", id, map[string]any{"device": id, "name": str(c.Full, "name")})
		}
		if _, ok := changedField("supervised"); ok {
			sup, _ := c.Full["supervised"].(bool)
			add("device.supervision_changed", id, map[string]any{"device": id, "supervised": sup})
		}
		_, g := changedField("groups")
		_, t := changedField("tags")
		if g || t {
			add("device.membership_changed", id, map[string]any{"device": id, "groups": c.Full["groups"], "tags": c.Full["tags"]})
		}
		if v, ok := changedField("active"); ok {
			if b, isBool := v.(bool); isBool && !b {
				add("device.deactivated", id, map[string]any{"device": id})
			}
		}
		if _, ok := changedField("lost_mode"); ok {
			add("device.lost_mode_changed", id, map[string]any{"device": id, "enabled": c.Full["lost_mode"] != nil})
		}
	case "bp_applied":
		dev := str(c.Full, "device")
		if _, changedState := changedField("state"); insert || (update && changedState) {
			add("application.state", dev, map[string]any{"device": dev, "blueprint": str(c.Full, "blueprint"), "item": str(c.Full, "item"), "state": str(c.Full, "state")})
		}
	case "bp_blueprints":
		id := str(c.Full, "id")
		if id == "" {
			id = idTail(c)
		}
		if del {
			add("blueprint.deleted", id, map[string]any{"blueprint": id})
		} else if insert || update {
			add("blueprint.saved", id, map[string]any{"blueprint": id})
		}
	case "bp_revisions":
		if insert {
			bp := str(c.Full, "blueprint")
			add("blueprint.revision", bp, map[string]any{"blueprint": bp, "revision": c.Full["revision"]})
		}
	case "bp_groups":
		id := str(c.Full, "id")
		if id == "" {
			id = idTail(c)
		}
		if del {
			add("group.deleted", id, map[string]any{"group": id})
		} else if insert || update {
			add("group.saved", id, map[string]any{"group": id})
		}
	case "vault_audit":
		if insert {
			d := str(c.Full, "device")
			add("vault.access", d, map[string]any{"device": d, "kind": str(c.Full, "kind"), "action": str(c.Full, "action"), "who": str(c.Full, "who"), "reason": str(c.Full, "reason")})
		}
	case "dep_devices":
		serial := str(c.Full, "serial_number")
		if serial == "" {
			serial = str(c.Full, "serial")
		}
		if serial == "" {
			serial = idTail(c)
		}
		if insert {
			add("dep.device.assigned", serial, map[string]any{"serial": serial})
		} else if del {
			add("dep.device.removed", serial, map[string]any{"serial": serial})
		}
	case "os_releases":
		if insert {
			p, v := str(c.Full, "platform"), str(c.Full, "version")
			add("os.release.published", p+"|"+v, map[string]any{"platform": p, "version": v})
		}
	case "schema_sets":
		if insert || update {
			ref := str(c.Full, "ref")
			if ref == "" {
				ref = idTail(c)
			}
			add("schema.updated", ref, map[string]any{"ref": ref})
		}
	case "applicability":
		id := idTail(c)
		if insert || update || del {
			add("applicability.changed", id, map[string]any{"id": id})
		}
	}
	return out
}
