package tenantlint

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"
)

// Monitor checks, while code runs, what the source check can only guess at: every command a tenant's store sends to a shared collection must carry the tenant in its filter (or in the _id
// key) and every document it inserts must carry the tenant. It cannot stop a command, but a test that attaches it fails on the first one that would have crossed a tenant, in any code path
// the tests reach, including filters built at run time.
//
//	m := tenantlint.NewMonitor("acme", "os_releases", "schema_sets")   // collections that are global by design
//	client, _ := mongo.Connect(options.Client().ApplyURI(uri).SetMonitor(m.CommandMonitor()))
//	... run the code ...
//	if v := m.Violations(); len(v) > 0 { t.Fatal(v) }
type Monitor struct {
	tenant string
	global map[string]bool
	mu     sync.Mutex
	bad    []string
	seen   int
	off    bool
}

// Stop ends the checking (a test that goes on to look into the database directly).
func (m *Monitor) Stop() {
	m.mu.Lock()
	m.off = true
	m.mu.Unlock()
}

// NewMonitor returns a monitor for a tenant. global names collections that hold no tenant data.
func NewMonitor(tenant string, global ...string) *Monitor {
	m := &Monitor{tenant: tenant, global: map[string]bool{}}
	for _, g := range global {
		m.global[g] = true
	}
	return m
}

// CommandMonitor is the driver hook.
func (m *Monitor) CommandMonitor() *event.CommandMonitor {
	return &event.CommandMonitor{Started: func(_ context.Context, e *event.CommandStartedEvent) { m.check(e) }}
}

// Violations returns what was found.
func (m *Monitor) Violations() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.bad...)
}

// Checked is how many commands on tenant collections were looked at (a monitor that saw none proved nothing).
func (m *Monitor) Checked() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen
}

func (m *Monitor) fail(e *event.CommandStartedEvent, why string) {
	m.mu.Lock()
	m.bad = append(m.bad, fmt.Sprintf("%s on %s: %s", e.CommandName, collectionOf(e), why))
	m.mu.Unlock()
}

func collectionOf(e *event.CommandStartedEvent) string {
	if v, err := e.Command.LookupErr(e.CommandName); err == nil {
		if s, ok := v.StringValueOK(); ok {
			return s
		}
	}
	return "?"
}

// scoped reports whether a filter (a document) is limited to the tenant: it has t equal to the tenant, or an _id that carries the tenant, at its top level or in an $and.
func (m *Monitor) scoped(f bson.Raw) bool {
	if len(f) == 0 {
		return false
	}
	elems, err := f.Elements()
	if err != nil {
		return false
	}
	prefix := m.tenant + "\x1f"
	for _, el := range elems {
		k, v := el.Key(), el.Value()
		switch k {
		case "t":
			if s, ok := v.StringValueOK(); ok && s == m.tenant {
				return true
			}
		case "_id":
			if s, ok := v.StringValueOK(); ok && strings.HasPrefix(s, prefix) {
				return true
			}
			if d, ok := v.DocumentOK(); ok { // {$in: [...]}
				if in, err := d.LookupErr("$in"); err == nil {
					if arr, ok := in.ArrayOK(); ok {
						vals, _ := arr.Values()
						all := len(vals) > 0
						for _, x := range vals {
							if s, ok := x.StringValueOK(); !ok || !strings.HasPrefix(s, prefix) {
								all = false
							}
						}
						if all {
							return true
						}
					}
				}
			}
		case "$and":
			if arr, ok := v.ArrayOK(); ok {
				vals, _ := arr.Values()
				for _, x := range vals {
					if d, ok := x.DocumentOK(); ok && m.scoped(d) {
						return true
					}
				}
			}
		}
	}
	return false
}

var controlCommands = map[string]bool{
	"hello": true, "isMaster": true, "ismaster": true, "ping": true, "endSessions": true, "commitTransaction": true, "abortTransaction": true, "getMore": true, "killCursors": true,
	"saslStart": true, "saslContinue": true, "listIndexes": true, "createIndexes": true, "listCollections": true, "buildInfo": true, "replSetGetStatus": true, "dropDatabase": true,
	"drop": true, "create": true, "collMod": true, "dbStats": true, "listDatabases": true, "serverStatus": true, "connectionStatus": true, "hostInfo": true, "getParameter": true, "dropIndexes": true,
}

func (m *Monitor) check(e *event.CommandStartedEvent) {
	if controlCommands[e.CommandName] {
		return
	}
	m.mu.Lock()
	off := m.off
	m.mu.Unlock()
	if off {
		return
	}
	coll := collectionOf(e)
	if m.global[coll] {
		return
	}
	m.mu.Lock()
	m.seen++
	m.mu.Unlock()
	cmd := e.Command
	doc := func(key string) bson.Raw {
		if v, err := cmd.LookupErr(key); err == nil {
			if d, ok := v.DocumentOK(); ok {
				return d
			}
		}
		return nil
	}
	list := func(key, inner string) []bson.Raw {
		var out []bson.Raw
		if v, err := cmd.LookupErr(key); err == nil {
			if arr, ok := v.ArrayOK(); ok {
				vals, _ := arr.Values()
				for _, x := range vals {
					if d, ok := x.DocumentOK(); ok {
						if inner == "" {
							out = append(out, d)
						} else if q, err := d.LookupErr(inner); err == nil {
							if qd, ok := q.DocumentOK(); ok {
								out = append(out, qd)
							} else {
								out = append(out, nil)
							}
						} else {
							out = append(out, nil)
						}
					}
				}
			}
		}
		return out
	}
	switch e.CommandName {
	case "find":
		if !m.scoped(doc("filter")) {
			m.fail(e, "filter is not scoped to the tenant")
		}
	case "distinct":
		if !m.scoped(doc("query")) {
			m.fail(e, "query is not scoped to the tenant")
		}
	case "findAndModify", "findandmodify":
		if !m.scoped(doc("query")) {
			m.fail(e, "query is not scoped to the tenant")
		}
	case "update":
		for _, q := range list("updates", "q") {
			if !m.scoped(q) {
				m.fail(e, "an update's filter is not scoped to the tenant")
			}
		}
	case "delete":
		for _, q := range list("deletes", "q") {
			if !m.scoped(q) {
				m.fail(e, "a delete's filter is not scoped to the tenant")
			}
		}
	case "insert":
		for _, d := range list("documents", "") {
			if t, err := d.LookupErr("t"); err != nil {
				if id, err := d.LookupErr("_id"); err != nil || !isTenantID(id, m.tenant) {
					m.fail(e, "an inserted document does not carry the tenant")
				}
			} else if s, ok := t.StringValueOK(); !ok || s != m.tenant {
				m.fail(e, "an inserted document carries another tenant")
			}
		}
	case "aggregate":
		// the first $match must be scoped (an aggregation that starts with anything else reads every tenant)
		v, err := cmd.LookupErr("pipeline")
		if err != nil {
			return
		}
		arr, ok := v.ArrayOK()
		if !ok {
			return
		}
		vals, _ := arr.Values()
		if len(vals) == 0 {
			m.fail(e, "an empty pipeline reads every tenant")
			return
		}
		first, _ := vals[0].DocumentOK()
		match, err := first.LookupErr("$match")
		md, ok := match.DocumentOK()
		if err != nil || !ok || !m.scoped(md) {
			m.fail(e, "the pipeline does not begin with a $match scoped to the tenant")
		}
	default:
		m.fail(e, "a command the tenant check does not know")
	}
}

func isTenantID(v bson.RawValue, tenant string) bool {
	s, ok := v.StringValueOK()
	return ok && strings.HasPrefix(s, tenant+"\x1f")
}
