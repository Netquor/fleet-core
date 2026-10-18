package blueprints

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/micromdm/nanomdm/fleetcore/commands"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Prepare checks a blueprint and fills in what can be worked out: the profile identifiers, item IDs, defaults. Call it before saving.
func (b *Blueprint) Prepare() error {
	if !idPattern.MatchString(b.ID) {
		return fmt.Errorf("id must be 1-64 letters, digits, dot, dash or underscore")
	}
	if b.Name == "" {
		b.Name = b.ID
	}
	if err := b.Scope.Validate(); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	seen := map[string]bool{}
	for i := range b.Items {
		it := &b.Items[i]
		if it.ID == "" {
			it.ID = fmt.Sprintf("item-%d", i+1)
		}
		if !idPattern.MatchString(it.ID) || seen[it.ID] {
			return fmt.Errorf("item %q: id must be unique, letters, digits, dot, dash or underscore", it.ID)
		}
		seen[it.ID] = true
		switch it.Kind {
		case "profile":
			id, err := ProfileIdentifier(it.Payload)
			if err != nil {
				return fmt.Errorf("item %s: %w", it.ID, err)
			}
			if it.Identifier != "" && it.Identifier != id {
				return fmt.Errorf("item %s: identifier %q does not match the profile's PayloadIdentifier %q", it.ID, it.Identifier, id)
			}
			it.Identifier = id
		case "command":
			cmd, ok := commands.Default().Get(it.RequestType)
			if !ok {
				return fmt.Errorf("item %s: unknown command %q", it.ID, it.RequestType)
			}
			if cmd.Destructive {
				return fmt.Errorf("item %s: %s can lose data or lock someone out and cannot be part of a blueprint", it.ID, it.RequestType)
			}
			if _, _, ps := commands.Build(cmd, it.Params, commands.Options{}); len(ps) > 0 {
				return fmt.Errorf("item %s: %s", it.ID, ps[0].Error())
			}
		default:
			return fmt.Errorf("item %s: kind must be profile or command", it.ID)
		}
	}
	last := 0
	rings := append([]Ring(nil), b.Rings...)
	sort.Slice(rings, func(i, j int) bool { return rings[i].Percent < rings[j].Percent })
	for _, r := range rings {
		if r.Percent < 1 || r.Percent > 100 || r.AfterSeconds < 0 {
			return fmt.Errorf("rings: percent is 1-100 and after_seconds is not negative")
		}
		if r.Percent == last {
			return fmt.Errorf("rings: two rings end at %d percent", r.Percent)
		}
		last = r.Percent
	}
	return nil
}
