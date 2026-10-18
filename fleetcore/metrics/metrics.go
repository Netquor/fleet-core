// Package metrics exposes fleetcore's state and behavior in the Prometheus text format at /metrics.
//
// Two kinds of metric. Counters, gauges and histograms of what the process does (HTTP requests by route, MDM check-ins by type, pushes, reconcile runs, event deliveries) are updated as it
// happens. Gauges of what the database holds (enrollments, devices by platform and OS, who is out of date, queue depths and ages, blueprint application states, certificate
// expiries, vault access) are read from MongoDB when Prometheus scrapes, at most once per refresh interval, each collector timed and its failure reported, so a slow query shows up
// as a metric instead of a slow scrape.
package metrics

import (
	"context"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/relay"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/push"
	"github.com/micromdm/nanomdm/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the registry and the instruments updated as the process works.
type Metrics struct {
	Registry *prometheus.Registry

	httpRequests *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec
	httpInFlight prometheus.Gauge
	httpBytes    *prometheus.CounterVec
	adminAuth    *prometheus.CounterVec

	checkins      *prometheus.CounterVec
	checkinTime   *prometheus.HistogramVec
	reports       *prometheus.CounterVec
	pushes        *prometheus.CounterVec
	pushTime      prometheus.Histogram
	reconciles    *prometheus.CounterVec
	reconcileTime prometheus.Histogram
	userAuth      *prometheus.CounterVec

	relayEvents  *prometheus.CounterVec
	relayPublish *prometheus.CounterVec
	relayPubTime *prometheus.HistogramVec
	relayDeliver *prometheus.CounterVec
	relayDelTime prometheus.Histogram
	relaySubLag  *prometheus.GaugeVec
}

var latency = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}

// New makes the registry with Go runtime and process collectors, build information and the instruments.
func New(version string) *Metrics {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	f := func(name, help string, labels ...string) *prometheus.CounterVec {
		c := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "fleetcore", Name: name, Help: help}, labels)
		r.MustRegister(c)
		return c
	}
	h := func(name, help string, labels ...string) *prometheus.HistogramVec {
		c := prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "fleetcore", Name: name, Help: help, Buckets: latency}, labels)
		r.MustRegister(c)
		return c
	}
	m := &Metrics{Registry: r}
	m.httpRequests = f("http_requests_total", "HTTP requests by route, method and status code.", "route", "method", "code")
	m.httpDuration = h("http_request_duration_seconds", "HTTP request duration by route and method.", "route", "method")
	m.httpBytes = f("http_response_bytes_total", "Bytes written in HTTP responses by route.", "route")
	m.httpInFlight = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "fleetcore", Name: "http_in_flight_requests", Help: "HTTP requests being served now."})
	r.MustRegister(m.httpInFlight)
	m.adminAuth = f("admin_auth_total", "Management API authentication attempts by result (ok, denied) and what was used (key, certificate, none).", "result", "method")
	m.checkins = f("mdm_messages_total", "MDM check-in and command messages by type and result (ok, error).", "type", "result")
	m.checkinTime = h("mdm_message_duration_seconds", "Time to process an MDM message by type.", "type")
	m.reports = f("mdm_command_reports_total", "Command reports from devices by status (Acknowledged, Error, NotNow, CommandFormatError, Idle).", "status")
	m.pushes = f("push_notifications_total", "APNs pushes by result (sent, failed).", "result")
	m.pushTime = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "fleetcore", Name: "push_batch_duration_seconds", Help: "Time to send one batch of pushes.", Buckets: latency})
	r.MustRegister(m.pushTime)
	m.reconciles = f("blueprint_reconciles_total", "Blueprint reconcile runs by result (ok, error).", "result")
	m.reconcileTime = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "fleetcore", Name: "blueprint_reconcile_duration_seconds", Help: "Time to reconcile one device.", Buckets: latency})
	r.MustRegister(m.reconcileTime)
	m.userAuth = f("user_authenticate_total", "UserAuthenticate handshakes by result (challenge, accepted, rejected, error).", "result")
	m.relayEvents = f("events_produced_total", "Events produced from database changes by type.", "type")
	m.relayPublish = f("event_sink_publishes_total", "Events handed to a sink (nats, webhook) by sink and result.", "sink", "result")
	m.relayPubTime = h("event_sink_publish_duration_seconds", "Time a sink took to accept an event.", "sink")
	m.relayDeliver = f("event_deliveries_total", "Subscription deliveries by result and HTTP status class.", "result", "status")
	m.relayDelTime = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "fleetcore", Name: "event_delivery_duration_seconds", Help: "Time a subscription endpoint took to answer.", Buckets: latency})
	r.MustRegister(m.relayDelTime)
	m.relaySubLag = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "fleetcore", Name: "event_subscription_lag_events", Help: "How many events a subscription is behind the log."}, []string{"subscription"})
	r.MustRegister(m.relaySubLag)
	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "fleetcore", Name: "build_info", Help: "Build information; the value is always 1."}, []string{"version", "go_version"})
	info.WithLabelValues(version, runtime.Version()).Set(1)
	start := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "fleetcore", Name: "start_time_seconds", Help: "When the process started (Unix time)."})
	start.Set(float64(time.Now().Unix()))
	r.MustRegister(info, start)
	return m
}

// Handler serves the registry (Prometheus text, or OpenMetrics when asked for).
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{EnableOpenMetrics: true})
}

// ---- HTTP ----

var (
	uuidish = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	// literal path words kept in a route label; everything else in a path is an identifier and becomes {}
	words = map[string]bool{
		"v1": true, "mdm": true, "checkin": true, "enroll": true, "ade": true, "byod": true, "scep": true, "acme": true, "ca.pem": true, "healthz": true, "version": true, "metrics": true,
		".well-known": true, "com.apple.remotemanagement": true, "ddm": true, "profile": true, "asset": true,
		"directory": true, "new-nonce": true, "new-account": true, "new-order": true, "authz": true, "challenge": true, "order": true, "finalize": true, "cert": true,
		"dep": true, "tokens": true, "config": true, "tokenpki": true, "assigner": true, "names": true, "devices": true, "sync": true, "proxy": true, "profiles": true,
		"commands": true, "types": true, "enrollments": true, "queue": true, "migration": true, "push": true, "enqueue": true, "pushcert": true,
		"blueprints": true, "revisions": true, "rollback": true, "preview": true, "status": true, "groups": true, "dep-devices": true, "tags": true, "query": true, "import": true, "expected": true,
		"applicability": true, "check": true, "schemas": true, "refresh": true, "coverage": true, "translate": true, "support": true, "os-releases": true, "latest": true,
		"secrets": true, "reveal": true, "audit": true, "apps": true, "lost-mode": true, "locate": true, "play-sound": true, "activation-lock": true, "bypass-code": true,
		"filevault": true, "rotate": true, "recovery-lock": true, "firmware-password": true,
		"vpp": true, "assets": true, "assignments": true, "assign": true, "unassign": true,
		"events": true, "stream": true, "event-subscriptions": true, "resume": true, "replay": true, "test": true, "deliveries": true,
	}
)

// Route turns a request path into a label with a bounded set of values: known words are kept and identifiers become {}.
func Route(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) == 1 && segs[0] == "" {
		return "/"
	}
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		if words[s] {
			out = append(out, s)
		} else {
			out = append(out, "{}")
		}
		if len(out) == 6 {
			break
		}
	}
	// collapse runs of identifiers (a file path under /ddm/profile/, a long proxy path) into one
	var collapsed []string
	for _, s := range out {
		if s == "{}" && len(collapsed) > 0 && collapsed[len(collapsed)-1] == "{}" {
			continue
		}
		collapsed = append(collapsed, s)
	}
	return "/" + strings.Join(collapsed, "/")
}

type recorder struct {
	http.ResponseWriter
	code  int
	bytes int
}

func (r *recorder) WriteHeader(c int) {
	if r.code == 0 {
		r.code = c
	}
	r.ResponseWriter.WriteHeader(c)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = 200
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Flush keeps streaming responses (the event stream) working through the wrapper.
func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware counts and times every request by route, method and status.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.httpInFlight.Inc()
		defer m.httpInFlight.Dec()
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.code == 0 {
			rec.code = 200
		}
		route := Route(r.URL.Path)
		if route == "/metrics" {
			return // scrapes would only count themselves
		}
		m.httpRequests.WithLabelValues(route, r.Method, strconv.Itoa(rec.code)).Inc()
		m.httpDuration.WithLabelValues(route, r.Method).Observe(time.Since(start).Seconds())
		m.httpBytes.WithLabelValues(route).Add(float64(rec.bytes))
	})
}

// AdminAuth counts a management API authentication attempt.
func (m *Metrics) AdminAuth(ok bool, method string) {
	res := "denied"
	if ok {
		res = "ok"
	}
	m.adminAuth.WithLabelValues(res, method).Inc()
}

// ---- MDM ----

type counted struct {
	service.CheckinAndCommandService
	m *Metrics
}

func (c counted) observe(typ string, start time.Time, err error) {
	res := "ok"
	if err != nil {
		res = "error"
	}
	c.m.checkins.WithLabelValues(typ, res).Inc()
	c.m.checkinTime.WithLabelValues(typ).Observe(time.Since(start).Seconds())
}

// WrapService counts and times each MDM message by type.
func (m *Metrics) WrapService(s service.CheckinAndCommandService) service.CheckinAndCommandService {
	return counted{s, m}
}

func (c counted) Authenticate(r *mdm.Request, x *mdm.Authenticate) error {
	t := time.Now()
	err := c.CheckinAndCommandService.Authenticate(r, x)
	c.observe("Authenticate", t, err)
	return err
}

func (c counted) TokenUpdate(r *mdm.Request, x *mdm.TokenUpdate) error {
	t := time.Now()
	err := c.CheckinAndCommandService.TokenUpdate(r, x)
	c.observe("TokenUpdate", t, err)
	return err
}

func (c counted) CheckOut(r *mdm.Request, x *mdm.CheckOut) error {
	t := time.Now()
	err := c.CheckinAndCommandService.CheckOut(r, x)
	c.observe("CheckOut", t, err)
	return err
}

func (c counted) SetBootstrapToken(r *mdm.Request, x *mdm.SetBootstrapToken) error {
	t := time.Now()
	err := c.CheckinAndCommandService.SetBootstrapToken(r, x)
	c.observe("SetBootstrapToken", t, err)
	return err
}

func (c counted) GetBootstrapToken(r *mdm.Request, x *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	t := time.Now()
	out, err := c.CheckinAndCommandService.GetBootstrapToken(r, x)
	c.observe("GetBootstrapToken", t, err)
	return out, err
}

func (c counted) UserAuthenticate(r *mdm.Request, x *mdm.UserAuthenticate) ([]byte, error) {
	t := time.Now()
	out, err := c.CheckinAndCommandService.UserAuthenticate(r, x)
	c.observe("UserAuthenticate", t, err)
	return out, err
}

func (c counted) CommandAndReportResults(r *mdm.Request, x *mdm.CommandResults) (*mdm.Command, error) {
	t := time.Now()
	out, err := c.CheckinAndCommandService.CommandAndReportResults(r, x)
	c.observe("CommandAndReportResults", t, err)
	c.m.reports.WithLabelValues(x.Status).Inc()
	return out, err
}

// ---- push ----

type pushed struct {
	push.Pusher
	m *Metrics
}

// WrapPusher counts the pushes sent and the ones that failed.
func (m *Metrics) WrapPusher(p push.Pusher) push.Pusher { return pushed{p, m} }

func (p pushed) Push(ctx context.Context, ids []string) (map[string]*push.Response, error) {
	start := time.Now()
	res, err := p.Pusher.Push(ctx, ids)
	p.m.pushTime.Observe(time.Since(start).Seconds())
	for _, id := range ids {
		if r, ok := res[id]; ok && r != nil && r.Err == nil {
			p.m.pushes.WithLabelValues("sent").Inc()
		} else {
			p.m.pushes.WithLabelValues("failed").Inc()
		}
	}
	if err != nil && len(res) == 0 {
		return res, err
	}
	return res, err
}

// ---- the blueprint engine, the relay, UserAuthenticate ----

// Reconciled records one reconcile run (the blueprints engine calls it).
func (m *Metrics) Reconciled(d time.Duration, err error) {
	res := "ok"
	if err != nil {
		res = "error"
	}
	m.reconciles.WithLabelValues(res).Inc()
	m.reconcileTime.Observe(d.Seconds())
}

// UserAuth records the outcome of a UserAuthenticate step.
func (m *Metrics) UserAuth(result string) { m.userAuth.WithLabelValues(result).Inc() }

// RelayHooks connects the event relay to the metrics.
func (m *Metrics) RelayHooks() relay.Hooks {
	return relay.Hooks{
		Event: func(typ string) { m.relayEvents.WithLabelValues(typ).Inc() },
		Publish: func(sink, typ string, ok bool, d time.Duration) {
			res := "ok"
			if !ok {
				res = "error"
			}
			m.relayPublish.WithLabelValues(sink, res).Inc()
			m.relayPubTime.WithLabelValues(sink).Observe(d.Seconds())
		},
		Delivery: func(sub string, ok bool, status int, d time.Duration) {
			res := "ok"
			if !ok {
				res = "error"
			}
			class := "none"
			if status > 0 {
				class = strconv.Itoa(status/100) + "xx"
			}
			m.relayDeliver.WithLabelValues(res, class).Inc()
			m.relayDelTime.Observe(d.Seconds())
		},
		Lag: func(sub string, behind int64) { m.relaySubLag.WithLabelValues(sub).Set(float64(behind)) },
	}
}
