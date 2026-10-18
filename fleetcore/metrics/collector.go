package metrics

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/fleetcore/relay"
	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"github.com/prometheus/client_golang/prometheus"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// DB reads what the database holds when Prometheus scrapes. The result is kept for Interval (default 15 seconds) so frequent scrapes or several Prometheus servers do not repeat the
// queries; each collector is timed and its failure is a metric of its own.
type DB struct {
	Database *mongo.Database
	Tenant   string
	// Releases is the OS release catalog, used to say which devices are behind.
	Releases *osreleases.Catalog
	// Relay is the event store, if events are on.
	Relay *relay.Store
	// Interval between database reads (default 15 seconds); Timeout for each collector (default 10 seconds).
	Interval, Timeout time.Duration
	Now               func() time.Time

	mu      sync.Mutex
	cached  []prometheus.Metric
	meta    []prometheus.Metric
	fetched time.Time
	running bool
}

func (d *DB) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Describe sends nothing: the metrics vary with the data (an unchecked collector).
func (d *DB) Describe(chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector.
func (d *DB) Collect(ch chan<- prometheus.Metric) {
	iv := d.Interval
	if iv == 0 {
		iv = 15 * time.Second
	}
	d.mu.Lock()
	if d.now().Sub(d.fetched) >= iv && !d.running {
		d.running = true
		d.mu.Unlock()
		ms, meta := d.gather()
		d.mu.Lock()
		d.cached, d.meta, d.fetched, d.running = ms, meta, d.now(), false
	}
	all := append(append([]prometheus.Metric(nil), d.cached...), d.meta...)
	d.mu.Unlock()
	for _, m := range all {
		ch <- m
	}
}

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc("fleetcore_"+name, help, labels, nil)
}

type gatherer struct {
	d  *DB
	ms []prometheus.Metric
}

func (g *gatherer) gauge(name, help string, v float64, labels []string, values ...string) {
	g.ms = append(g.ms, prometheus.MustNewConstMetric(desc(name, help, labels...), prometheus.GaugeValue, v, values...))
}

// scope adds the tenant to a filter.
func (d *DB) scope(f bson.D) bson.D {
	if d.Tenant == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: d.Tenant}}, f...)
}

func (d *DB) count(ctx context.Context, coll string, f bson.D) (float64, error) {
	n, err := d.Database.Collection(coll).CountDocuments(ctx, d.scope(f))
	return float64(n), err
}

// group runs an aggregation over the tenant's documents: $match, $group by the given fields, counting.
func (d *DB) group(ctx context.Context, coll string, match bson.D, by ...string) ([]bson.M, error) {
	id := bson.D{}
	for _, f := range by {
		id = append(id, bson.E{Key: strings.ReplaceAll(f, ".", "_"), Value: "$" + f})
	}
	cur, err := d.Database.Collection(coll).Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: d.scope(match)}},
		{{Key: "$group", Value: bson.D{{Key: "_id", Value: id}, {Key: "n", Value: bson.D{{Key: "$sum", Value: 1}}}}}},
	})
	if err != nil {
		return nil, err
	}
	var rows []bson.M
	return rows, cur.All(ctx, &rows)
}

func lab(row bson.M, field string) string {
	var raw any
	switch id := row["_id"].(type) {
	case bson.M:
		raw = id[field]
	case bson.D:
		for _, e := range id {
			if e.Key == field {
				raw = e.Value
			}
		}
	}
	switch v := raw.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return fmt.Sprint(v)
	default:
		return fmt.Sprint(v)
	}
}

func num(row bson.M) float64 {
	switch n := row["n"].(type) {
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	}
	return 0
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// gather runs every collector and returns the metrics and the bookkeeping about the run.
func (d *DB) gather() (ms, meta []prometheus.Metric) {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	g := &gatherer{d: d}
	collectors := []struct {
		name string
		run  func(context.Context, *gatherer) error
	}{
		{"enrollments", enrollments}, {"devices", devices}, {"os_currency", osCurrency}, {"reconcile_queue", reconcileQueue}, {"command_queue", commandQueue},
		{"blueprints", blueprintsC}, {"declarations", declarationsC}, {"dep", depC}, {"vpp", vppC}, {"vault", vaultC}, {"identity", identityC}, {"certificates", certificates},
		{"events", eventsC}, {"feeds", feedsC}, {"mongodb", mongoC},
	}
	for _, c := range collectors {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		start := time.Now()
		err := c.run(ctx, g)
		cancel()
		ok := 1.0
		if err != nil {
			ok = 0
		}
		meta = append(meta,
			prometheus.MustNewConstMetric(desc("scrape_collector_duration_seconds", "How long a database collector took on its last run.", "collector"), prometheus.GaugeValue, time.Since(start).Seconds(), c.name),
			prometheus.MustNewConstMetric(desc("scrape_collector_success", "1 if a database collector's last run succeeded, 0 if it failed or timed out.", "collector"), prometheus.GaugeValue, ok, c.name),
		)
	}
	meta = append(meta, prometheus.MustNewConstMetric(desc("scrape_last_refresh_timestamp_seconds", "When the database collectors last ran (Unix time)."), prometheus.GaugeValue, float64(time.Now().Unix())))
	return g.ms, meta
}

func enrollments(ctx context.Context, g *gatherer) error {
	rows, err := g.d.group(ctx, "enrollments", bson.D{}, "type", "enabled")
	if err != nil {
		return err
	}
	for _, r := range rows {
		g.gauge("enrollments", "Enrollments by type and whether they are enabled (not checked out).", num(r), []string{"type", "enabled"}, or(lab(r, "type"), "unknown"), or(lab(r, "enabled"), "false"))
	}
	return nil
}

func devices(ctx context.Context, g *gatherer) error {
	d := g.d
	rows, err := d.group(ctx, "bp_devices", bson.D{}, "platform", "active", "supervised", "enroll_type")
	if err != nil {
		return err
	}
	for _, r := range rows {
		g.gauge("devices", "Devices in the inventory by platform, whether they are active, supervised (unknown if not yet learned) and enrollment type.", num(r),
			[]string{"platform", "active", "supervised", "enroll_type"}, or(lab(r, "platform"), "unknown"), or(lab(r, "active"), "false"), or(lab(r, "supervised"), "unknown"), or(lab(r, "enroll_type"), "unknown"))
	}
	// how a device came to be managed, and whether it waits in Setup Assistant
	if n, err := d.count(ctx, "bp_devices", bson.D{{Key: "active", Value: true}, {Key: "dep_name", Value: bson.D{{Key: "$exists", Value: true}, {Key: "$ne", Value: ""}}}}); err == nil {
		g.gauge("devices_by_dep", "Active devices that Apple Business Manager assigned to this server.", n, nil)
	}
	if n, err := d.count(ctx, "bp_devices", bson.D{{Key: "awaiting", Value: true}}); err == nil {
		g.gauge("devices_awaiting_setup", "Devices held in Setup Assistant waiting for their configuration.", n, nil)
	}
	if n, err := d.count(ctx, "bp_devices", bson.D{{Key: "lost_mode", Value: bson.D{{Key: "$exists", Value: true}, {Key: "$ne", Value: nil}}}}); err == nil {
		g.gauge("devices_lost_mode", "Devices in Lost Mode.", n, nil)
	}
	// how long since active devices were seen
	now := d.now()
	for _, age := range []struct {
		label string
		d     time.Duration
	}{{"1d", 24 * time.Hour}, {"7d", 7 * 24 * time.Hour}, {"30d", 30 * 24 * time.Hour}, {"90d", 90 * 24 * time.Hour}} {
		n, err := d.count(ctx, "bp_devices", bson.D{{Key: "active", Value: true}, {Key: "last_seen", Value: bson.D{{Key: "$lt", Value: now.Add(-age.d)}}}})
		if err != nil {
			return err
		}
		g.gauge("devices_not_seen", "Active devices not seen for longer than the period.", n, []string{"period"}, age.label)
	}
	// the OS versions in use (the largest 60 per run; the rest as "other")
	vrows, err := d.group(ctx, "bp_devices", bson.D{{Key: "active", Value: true}}, "platform", "os_version")
	if err != nil {
		return err
	}
	sort.Slice(vrows, func(i, j int) bool { return num(vrows[i]) > num(vrows[j]) })
	other := map[string]float64{}
	for i, r := range vrows {
		if i < 60 {
			g.gauge("devices_by_os_version", "Active devices by platform and OS version.", num(r), []string{"platform", "os_version"}, or(lab(r, "platform"), "unknown"), or(lab(r, "os_version"), "unknown"))
		} else {
			other[or(lab(r, "platform"), "unknown")] += num(r)
		}
	}
	for p, n := range other {
		g.gauge("devices_by_os_version", "Active devices by platform and OS version.", n, []string{"platform", "os_version"}, p, "other")
	}
	return nil
}

func osCurrency(ctx context.Context, g *gatherer) error {
	if g.d.Releases == nil {
		return nil
	}
	rows, err := g.d.group(ctx, "bp_devices", bson.D{{Key: "active", Value: true}}, "platform", "os_version")
	if err != nil {
		return err
	}
	type key struct{ platform, state string }
	counts := map[key]float64{}
	for _, r := range rows {
		p, v := lab(r, "platform"), lab(r, "os_version")
		st, ok := g.d.Releases.Compare(p, v)
		state := "unknown"
		switch {
		case !ok:
		case st.BehindMinor:
			state = "behind_in_major"
		case st.NewMajor:
			state = "current_in_major_newer_major_exists"
		default:
			state = "current"
		}
		counts[key{or(p, "unknown"), state}] += num(r)
	}
	for k, n := range counts {
		g.gauge("devices_os_currency", "Active devices by platform and how current their OS is: current, behind_in_major (an update exists in their own major version), current_in_major_newer_major_exists, unknown.", n, []string{"platform", "state"}, k.platform, k.state)
	}
	for _, p := range []string{"macOS", "iOS", "iPadOS", "tvOS", "watchOS", "visionOS"} {
		if r, ok := g.d.Releases.Latest(p); ok {
			g.gauge("os_latest_release_timestamp_seconds", "When the newest known release of a platform was published (Unix time).", float64(r.PublishedAt.Unix()), []string{"platform", "version"}, p, r.Version)
		}
	}
	return nil
}

func reconcileQueue(ctx context.Context, g *gatherer) error {
	d := g.d
	now := d.now()
	due, err := d.count(ctx, "bp_devices", bson.D{{Key: "active", Value: true}, {Key: "reconcile_at", Value: bson.D{{Key: "$lte", Value: now}}}})
	if err != nil {
		return err
	}
	g.gauge("reconcile_queue_due", "Devices waiting to be reconciled with their blueprints now.", due, nil)
	var oldest struct {
		At time.Time `bson:"reconcile_at"`
	}
	err = d.Database.Collection("bp_devices").FindOne(ctx, d.scope(bson.D{{Key: "active", Value: true}, {Key: "reconcile_at", Value: bson.D{{Key: "$lte", Value: now}}}}),
		options.FindOne().SetSort(bson.D{{Key: "reconcile_at", Value: 1}}).SetProjection(bson.D{{Key: "reconcile_at", Value: 1}})).Decode(&oldest)
	age := 0.0
	if err == nil {
		age = now.Sub(oldest.At).Seconds()
	} else if err != mongo.ErrNoDocuments {
		return err
	}
	g.gauge("reconcile_queue_oldest_due_age_seconds", "How long the longest-waiting due device has waited (0 when none).", age, nil)
	leased, err := d.count(ctx, "bp_devices", bson.D{{Key: "lease_until", Value: bson.D{{Key: "$gt", Value: now}}}})
	if err != nil {
		return err
	}
	g.gauge("reconcile_leased", "Devices being reconciled right now (leased to a worker).", leased, nil)
	return nil
}

func commandQueue(ctx context.Context, g *gatherer) error {
	d := g.d
	now := d.now()
	rows, err := d.group(ctx, "enrollment_queue", bson.D{{Key: "active", Value: true}}, "status")
	if err != nil {
		return err
	}
	for _, r := range rows {
		g.gauge("command_queue", "Active queue entries by status (Queued is not yet answered).", num(r), []string{"status"}, or(lab(r, "status"), "Queued"))
	}
	var oldest struct {
		At time.Time `bson:"created_at"`
	}
	err = d.Database.Collection("enrollment_queue").FindOne(ctx, d.scope(bson.D{{Key: "active", Value: true}, {Key: "status", Value: nil}}),
		options.FindOne().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetProjection(bson.D{{Key: "created_at", Value: 1}})).Decode(&oldest)
	age := 0.0
	if err == nil {
		age = now.Sub(oldest.At).Seconds()
	} else if err != mongo.ErrNoDocuments {
		return err
	}
	g.gauge("command_queue_oldest_unanswered_age_seconds", "Age of the oldest queued command no device has answered (0 when none).", age, nil)
	stuck, err := d.count(ctx, "enrollment_queue", bson.D{{Key: "active", Value: true}, {Key: "not_now_tally", Value: bson.D{{Key: "$gte", Value: 5}}}})
	if err != nil {
		return err
	}
	g.gauge("command_queue_not_now_repeated", "Queue entries a device has answered NotNow five or more times.", stuck, nil)
	types, err := d.group(ctx, "commands", bson.D{}, "request_type")
	if err != nil {
		return err
	}
	for _, r := range types {
		g.gauge("commands_stored", "Commands in the history by request type.", num(r), []string{"request_type"}, or(lab(r, "request_type"), "unknown"))
	}
	return nil
}

func blueprintsC(ctx context.Context, g *gatherer) error {
	d := g.d
	rows, err := d.group(ctx, "bp_blueprints", bson.D{}, "enabled")
	if err != nil {
		return err
	}
	for _, r := range rows {
		g.gauge("blueprints", "Blueprints by whether they are enabled.", num(r), []string{"enabled"}, or(lab(r, "enabled"), "false"))
	}
	n, err := d.count(ctx, "bp_groups", bson.D{{Key: "rule", Value: bson.D{{Key: "$exists", Value: true}}}})
	if err != nil {
		return err
	}
	g.gauge("groups", "Groups by kind.", n, []string{"kind"}, "dynamic")
	total, err := d.count(ctx, "bp_groups", bson.D{})
	if err != nil {
		return err
	}
	g.gauge("groups", "Groups by kind.", total-n, []string{"kind"}, "static")
	apps, err := d.group(ctx, "bp_applied", bson.D{}, "kind", "delivery", "state")
	if err != nil {
		return err
	}
	for _, r := range apps {
		g.gauge("blueprint_applications", "What blueprints put on devices, by item kind, how it is delivered and its state (pending, applied, failed, removing, not_applicable).", num(r),
			[]string{"kind", "delivery", "state"}, or(lab(r, "kind"), "unknown"), or(lab(r, "delivery"), "none"), or(lab(r, "state"), "unknown"))
	}
	retries, err := d.count(ctx, "bp_applied", bson.D{{Key: "state", Value: "failed"}, {Key: "attempts", Value: bson.D{{Key: "$gte", Value: 5}}}})
	if err != nil {
		return err
	}
	g.gauge("blueprint_applications_given_up", "Failed applications that used up their retries.", retries, nil)
	return nil
}

func declarationsC(ctx context.Context, g *gatherer) error {
	d := g.d
	n, err := d.count(ctx, "ddm_declarations", bson.D{})
	if err != nil {
		return err
	}
	g.gauge("ddm_declarations", "Declarations stored for devices.", n, nil)
	dv, err := d.count(ctx, "ddm_devices", bson.D{})
	if err != nil {
		return err
	}
	g.gauge("ddm_devices", "Devices using declarative management.", dv, nil)
	st, err := d.count(ctx, "ddm_status", bson.D{})
	if err != nil {
		return err
	}
	g.gauge("ddm_status_reports", "Devices that have reported declarative status.", st, nil)
	return nil
}

func depC(ctx context.Context, g *gatherer) error {
	rows, err := g.d.group(ctx, "dep_devices", bson.D{}, "dep")
	if err != nil {
		return err
	}
	for _, r := range rows {
		g.gauge("dep_devices", "Devices Apple Business Manager assigned, by DEP name.", num(r), []string{"dep"}, or(lab(r, "dep"), "unknown"))
	}
	n, err := g.d.count(ctx, "dep_names", bson.D{})
	if err != nil {
		return err
	}
	g.gauge("dep_names", "Configured DEP names.", n, nil)
	return nil
}

func vppC(ctx context.Context, g *gatherer) error {
	n, err := g.d.count(ctx, "vpp_tokens", bson.D{})
	if err != nil {
		return err
	}
	g.gauge("vpp_tokens", "Stored Apps and Books content tokens.", n, nil)
	l, err := g.d.count(ctx, "vpp_licenses", bson.D{})
	if err != nil {
		return err
	}
	g.gauge("vpp_licenses", "Recorded app license assignments.", l, nil)
	return nil
}

func vaultC(ctx context.Context, g *gatherer) error {
	rows, err := g.d.group(ctx, "vault_secrets", bson.D{}, "kind")
	if err != nil {
		return err
	}
	for _, r := range rows {
		g.gauge("vault_secrets", "Stored device secrets by kind (versions included).", num(r), []string{"kind"}, or(lab(r, "kind"), "unknown"))
	}
	audit, err := g.d.group(ctx, "vault_audit", bson.D{{Key: "at", Value: bson.D{{Key: "$gte", Value: g.d.now().Add(-24 * time.Hour)}}}}, "action")
	if err != nil {
		return err
	}
	for _, r := range audit {
		g.gauge("vault_access_24h", "Vault accesses in the last 24 hours by action (store, reveal...).", num(r), []string{"action"}, or(lab(r, "action"), "unknown"))
	}
	return nil
}

func identityC(ctx context.Context, g *gatherer) error {
	d := g.d
	now := d.now()
	active, err := d.count(ctx, "pki_certs", bson.D{{Key: "revoked", Value: false}, {Key: "not_after", Value: bson.D{{Key: "$gt", Value: now}}}})
	if err != nil {
		return err
	}
	g.gauge("identity_certificates", "Device identity certificates by state.", active, []string{"state"}, "valid")
	for _, w := range []struct {
		label string
		d     time.Duration
	}{{"7d", 7 * 24 * time.Hour}, {"30d", 30 * 24 * time.Hour}, {"90d", 90 * 24 * time.Hour}} {
		n, err := d.count(ctx, "pki_certs", bson.D{{Key: "revoked", Value: false}, {Key: "not_after", Value: bson.D{{Key: "$gt", Value: now}, {Key: "$lte", Value: now.Add(w.d)}}}})
		if err != nil {
			return err
		}
		g.gauge("identity_certificates_expiring", "Valid device identity certificates that expire within the period.", n, []string{"within"}, w.label)
	}
	expired, err := d.count(ctx, "pki_certs", bson.D{{Key: "revoked", Value: false}, {Key: "not_after", Value: bson.D{{Key: "$lte", Value: now}}}})
	if err != nil {
		return err
	}
	g.gauge("identity_certificates", "Device identity certificates by state.", expired, []string{"state"}, "expired")
	rev, err := d.count(ctx, "pki_certs", bson.D{{Key: "revoked", Value: true}})
	if err != nil {
		return err
	}
	g.gauge("identity_certificates", "Device identity certificates by state.", rev, []string{"state"}, "revoked")
	ua, err := d.count(ctx, "ua_tokens", bson.D{{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}}})
	if err != nil {
		return err
	}
	g.gauge("user_auth_tokens", "Network and mobile user sessions holding an AuthToken.", ua, nil)
	acct, err := d.count(ctx, "acme_accounts", bson.D{})
	if err != nil {
		return err
	}
	g.gauge("acme_accounts", "ACME accounts (each key pair counts twice: by id and by thumbprint).", acct, nil)
	return nil
}

func certExpiry(g *gatherer, kind, name string, notAfter time.Time) {
	g.gauge("certificate_expiry_timestamp_seconds", "When a certificate or token the server depends on expires (Unix time). Alert on it a few weeks ahead.", float64(notAfter.Unix()), []string{"kind", "name"}, kind, name)
	g.gauge("certificate_expires_in_seconds", "Seconds until a certificate or token the server depends on expires (negative once expired).", time.Until(notAfter).Seconds(), []string{"kind", "name"}, kind, name)
}

func parseCert(p string) *x509.Certificate {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil
	}
	return c
}

func certificates(ctx context.Context, g *gatherer) error {
	d := g.d
	var ca struct {
		Cert string `bson:"cert_pem"`
	}
	if err := d.Database.Collection("pki_ca").FindOne(ctx, d.scope(bson.D{}), options.FindOne().SetProjection(bson.D{{Key: "cert_pem", Value: 1}})).Decode(&ca); err == nil {
		if c := parseCert(ca.Cert); c != nil {
			certExpiry(g, "device_identity_ca", c.Subject.CommonName, c.NotAfter)
		}
	}
	cur, err := d.Database.Collection("push_certs").Find(ctx, d.scope(bson.D{}), options.Find().SetProjection(bson.D{{Key: "cert_pem", Value: 1}, {Key: "topic", Value: 1}}))
	if err != nil {
		return err
	}
	var pcs []struct {
		Topic string `bson:"topic"`
		Cert  string `bson:"cert_pem"`
	}
	if err := cur.All(ctx, &pcs); err != nil {
		return err
	}
	for _, p := range pcs {
		if c := parseCert(p.Cert); c != nil {
			certExpiry(g, "apns_push_certificate", or(p.Topic, c.Subject.CommonName), c.NotAfter)
		}
	}
	cur, err = d.Database.Collection("dep_names").Find(ctx, d.scope(bson.D{}), options.Find().SetProjection(bson.D{{Key: "name", Value: 1}, {Key: "tokens.expiry", Value: 1}}))
	if err != nil {
		return err
	}
	var deps []struct {
		Name   string `bson:"name"`
		Tokens *struct {
			Expiry time.Time `bson:"expiry"`
		} `bson:"tokens"`
	}
	if err := cur.All(ctx, &deps); err != nil {
		return err
	}
	for _, dn := range deps {
		if dn.Tokens != nil && !dn.Tokens.Expiry.IsZero() {
			certExpiry(g, "dep_access_token", dn.Name, dn.Tokens.Expiry)
		}
	}
	cur, err = d.Database.Collection("vpp_tokens").Find(ctx, d.scope(bson.D{}), options.Find().SetProjection(bson.D{{Key: "name", Value: 1}, {Key: "expires", Value: 1}}))
	if err != nil {
		return err
	}
	var vpps []struct {
		Name    string    `bson:"name"`
		Expires time.Time `bson:"expires"`
	}
	if err := cur.All(ctx, &vpps); err != nil {
		return err
	}
	for _, v := range vpps {
		if !v.Expires.IsZero() {
			certExpiry(g, "vpp_content_token", v.Name, v.Expires)
		}
	}
	return nil
}

func eventsC(ctx context.Context, g *gatherer) error {
	if g.d.Relay == nil {
		return nil
	}
	last, err := g.d.Relay.LastSeq(ctx)
	if err != nil {
		return err
	}
	g.gauge("event_log_last_sequence", "The newest event sequence number.", float64(last), nil)
	n, err := g.d.count(ctx, "relay_events", bson.D{})
	if err != nil {
		return err
	}
	g.gauge("event_log_events", "Events kept in the log (they expire after seven days).", n, nil)
	var first struct {
		At time.Time `bson:"at"`
	}
	err = g.d.Database.Collection("relay_events").FindOne(ctx, g.d.scope(bson.D{}), options.FindOne().SetSort(bson.D{{Key: "seq", Value: 1}}).SetProjection(bson.D{{Key: "at", Value: 1}})).Decode(&first)
	age := 0.0
	if err == nil {
		age = g.d.now().Sub(first.At).Seconds()
	}
	g.gauge("event_log_oldest_age_seconds", "Age of the oldest event in the log.", age, nil)
	subs, err := g.d.Relay.Subscriptions(ctx)
	if err != nil {
		return err
	}
	states := map[string]float64{"active": 0, "failing": 0, "paused": 0, "disabled": 0}
	for _, s := range subs {
		switch {
		case s.PausedReason != "":
			states["paused"]++
		case !s.Enabled:
			states["disabled"]++
		case s.Failures > 0:
			states["failing"]++
		default:
			states["active"]++
		}
		g.gauge("event_subscription_delivered_total", "Events delivered to a subscription since it was made.", float64(s.Delivered), []string{"subscription", "name"}, s.ID, s.Name)
		g.gauge("event_subscription_consecutive_failures", "Failed deliveries in a row for a subscription.", float64(s.Failures), []string{"subscription", "name"}, s.ID, s.Name)
	}
	for st, n := range states {
		g.gauge("event_subscriptions", "Event subscriptions by state.", n, []string{"state"}, st)
	}
	return nil
}

func feedsC(ctx context.Context, g *gatherer) error {
	set := schemas.Current()
	g.gauge("schema_snapshot_timestamp_seconds", "When the Apple device-management definitions in use were fetched (Unix time).", float64(set.FetchedAt.Unix()), []string{"ref"}, set.Ref)
	g.gauge("schema_definitions", "Definitions in the snapshot by kind.", float64(len(set.Commands)), []string{"kind"}, "commands")
	g.gauge("schema_definitions", "Definitions in the snapshot by kind.", float64(len(set.Profiles)), []string{"kind"}, "profile_payloads")
	g.gauge("schema_definitions", "Definitions in the snapshot by kind.", float64(len(set.Declarations)), []string{"kind"}, "declarations")
	g.gauge("schema_definitions", "Definitions in the snapshot by kind.", float64(len(set.StatusItems)), []string{"kind"}, "status_items")
	if g.d.Releases != nil {
		if u := g.d.Releases.UpdatedAt(); !u.IsZero() {
			g.gauge("os_releases_refresh_timestamp_seconds", "When the OS release catalog was last refreshed (Unix time).", float64(u.Unix()), nil)
		}
		per := map[string]float64{}
		for _, r := range g.d.Releases.All() {
			per[r.Platform]++
		}
		for p, n := range per {
			g.gauge("os_releases_known", "Shipping OS releases known, by platform.", n, []string{"platform"}, p)
		}
	}
	return nil
}

func mongoC(ctx context.Context, g *gatherer) error {
	start := time.Now()
	if err := g.d.Database.Client().Ping(ctx, nil); err != nil {
		return err
	}
	g.gauge("mongodb_ping_seconds", "Round trip to MongoDB.", time.Since(start).Seconds(), nil)
	var st bson.M
	// database-wide figures would tell one tenant about the others when tenants share the database
	if g.d.Tenant != "" {
		return nil
	}
	if err := g.d.Database.RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&st); err == nil {
		for _, f := range []struct{ key, name, help string }{
			{"dataSize", "mongodb_data_bytes", "Size of the data in the database."}, {"storageSize", "mongodb_storage_bytes", "Storage allocated to the database."},
			{"indexSize", "mongodb_index_bytes", "Size of the database's indexes."}, {"objects", "mongodb_objects", "Documents in the database."}, {"collections", "mongodb_collections", "Collections in the database."},
		} {
			switch v := st[f.key].(type) {
			case int32:
				g.gauge(f.name, f.help, float64(v), nil)
			case int64:
				g.gauge(f.name, f.help, float64(v), nil)
			case float64:
				g.gauge(f.name, f.help, v, nil)
			}
		}
	}
	return nil
}
