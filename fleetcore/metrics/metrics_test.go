package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/osreleases"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestRouteLabelsAreBounded(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/devices/ABC-123/lost-mode":   "/v1/devices/{}/lost-mode",
		"/v1/devices":                     "/v1/devices",
		"/v1/blueprints/wifi/revisions":   "/v1/blueprints/{}/revisions",
		"/ddm/profile/some-long-key-0001": "/ddm/profile/{}",
		"/acme/order/xyz":                 "/acme/order/{}",
		"/mdm":                            "/mdm",
		"/v1/dep/proxy/myabm/account":     "/v1/dep/proxy/{}",
		"/random/attacker/chosen/path/that/never/ends/and/on/on": "/{}",
		"/": "/",
	} {
		if got := Route(in); got != want {
			t.Errorf("Route(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeSvc struct{ mdmErr error }

func (f fakeSvc) Authenticate(*mdm.Request, *mdm.Authenticate) error { return f.mdmErr }
func (f fakeSvc) TokenUpdate(*mdm.Request, *mdm.TokenUpdate) error   { return nil }
func (f fakeSvc) CheckOut(*mdm.Request, *mdm.CheckOut) error         { return nil }
func (f fakeSvc) UserAuthenticate(*mdm.Request, *mdm.UserAuthenticate) ([]byte, error) {
	return nil, nil
}
func (f fakeSvc) SetBootstrapToken(*mdm.Request, *mdm.SetBootstrapToken) error { return nil }
func (f fakeSvc) GetBootstrapToken(*mdm.Request, *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	return nil, nil
}
func (f fakeSvc) DeclarativeManagement(*mdm.Request, *mdm.DeclarativeManagement) ([]byte, error) {
	return nil, nil
}
func (f fakeSvc) GetToken(*mdm.Request, *mdm.GetToken) (*mdm.GetTokenResponse, error) {
	return nil, nil
}
func (f fakeSvc) CommandAndReportResults(*mdm.Request, *mdm.CommandResults) (*mdm.Command, error) {
	return nil, nil
}

func TestInstruments(t *testing.T) {
	m := New("test")
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/devices") {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte("hello"))
	}))
	for _, p := range []string{"/healthz", "/v1/devices/X", "/v1/devices/Y", "/metrics"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
	}
	if n := testutil.ToFloat64(m.httpRequests.WithLabelValues("/v1/devices/{}", "GET", "404")); n != 2 {
		t.Errorf("devices 404s: %v", n)
	}
	if n := testutil.ToFloat64(m.httpRequests.WithLabelValues("/healthz", "GET", "200")); n != 1 {
		t.Errorf("healthz: %v", n)
	}
	if n := testutil.ToFloat64(m.httpBytes.WithLabelValues("/healthz")); n != 5 {
		t.Errorf("bytes: %v", n)
	}
	if testutil.CollectAndCount(m.httpRequests) != 2 {
		t.Error("the scrape itself was counted")
	}
	m.AdminAuth(true, "key")
	m.AdminAuth(false, "none")
	if testutil.ToFloat64(m.adminAuth.WithLabelValues("denied", "none")) != 1 {
		t.Error("admin auth")
	}
	m.Reconciled(time.Millisecond, nil)
	m.Reconciled(time.Millisecond, context.Canceled)
	if testutil.ToFloat64(m.reconciles.WithLabelValues("error")) != 1 {
		t.Error("reconcile")
	}
	svc := m.WrapService(fakeSvc{mdmErr: context.Canceled})
	_ = svc.Authenticate(nil, &mdm.Authenticate{})
	_ = svc.TokenUpdate(nil, &mdm.TokenUpdate{})
	_, _ = svc.CommandAndReportResults(nil, &mdm.CommandResults{Status: "Acknowledged"})
	if testutil.ToFloat64(m.checkins.WithLabelValues("Authenticate", "error")) != 1 || testutil.ToFloat64(m.checkins.WithLabelValues("TokenUpdate", "ok")) != 1 ||
		testutil.ToFloat64(m.reports.WithLabelValues("Acknowledged")) != 1 {
		t.Error("mdm messages")
	}
	hooks := m.RelayHooks()
	hooks.Event("command.result")
	hooks.Publish("nats", "command.result", false, time.Millisecond)
	hooks.Delivery("sub_1", true, 204, time.Millisecond)
	hooks.Lag("sub_1", 7)
	if testutil.ToFloat64(m.relayEvents.WithLabelValues("command.result")) != 1 || testutil.ToFloat64(m.relayPublish.WithLabelValues("nats", "error")) != 1 ||
		testutil.ToFloat64(m.relayDeliver.WithLabelValues("ok", "2xx")) != 1 || testutil.ToFloat64(m.relaySubLag.WithLabelValues("sub_1")) != 7 {
		t.Error("relay hooks")
	}
}

func TestDatabaseCollectors(t *testing.T) {
	uri := os.Getenv("NANOMDM_MONGODB_STORAGE_TEST_URI")
	if uri == "" {
		t.Skip("NANOMDM_MONGODB_STORAGE_TEST_URI not set")
	}
	ctx := context.Background()
	mc, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Disconnect(ctx)
	db := mc.Database("fleetcore_metrics_test")
	_ = db.Drop(ctx)
	defer db.Drop(context.Background())
	now := time.Now().UTC()
	ins := func(coll string, docs ...bson.D) {
		for _, d := range docs {
			if _, err := db.Collection(coll).InsertOne(ctx, append(bson.D{{Key: "t", Value: "acme"}}, d...)); err != nil {
				t.Fatal(err)
			}
		}
	}
	ins("enrollments", bson.D{{Key: "id", Value: "E1"}, {Key: "type", Value: "Device"}, {Key: "enabled", Value: true}}, bson.D{{Key: "id", Value: "E2"}, {Key: "type", Value: "User"}, {Key: "enabled", Value: false}})
	_, _ = db.Collection("enrollments").InsertOne(ctx, bson.D{{Key: "t", Value: "other"}, {Key: "id", Value: "X"}, {Key: "type", Value: "Device"}, {Key: "enabled", Value: true}}) // another tenant
	ins("bp_devices",
		bson.D{{Key: "id", Value: "D1"}, {Key: "platform", Value: "macOS"}, {Key: "os_version", Value: "15.0"}, {Key: "active", Value: true}, {Key: "supervised", Value: true}, {Key: "last_seen", Value: now}, {Key: "reconcile_at", Value: now.Add(-time.Hour)}},
		bson.D{{Key: "id", Value: "D2"}, {Key: "platform", Value: "iOS"}, {Key: "os_version", Value: "17.0"}, {Key: "active", Value: true}, {Key: "last_seen", Value: now.Add(-48 * time.Hour)}, {Key: "reconcile_at", Value: now.Add(time.Hour)}, {Key: "dep_name", Value: "abm"}},
	)
	ins("enrollment_queue", bson.D{{Key: "id", Value: "E1"}, {Key: "command_uuid", Value: "C1"}, {Key: "active", Value: true}, {Key: "created_at", Value: now.Add(-time.Minute)}})
	ins("bp_applied", bson.D{{Key: "device", Value: "D1"}, {Key: "kind", Value: "profile"}, {Key: "delivery", Value: "profile"}, {Key: "state", Value: "failed"}, {Key: "attempts", Value: 5}})
	cat := &osreleases.Catalog{}
	cat.Replace([]osreleases.Release{{Platform: "macOS", Version: "15.1", Major: 15, Num: 15_001_000, PublishedAt: now}})

	d := &DB{Database: db, Tenant: "acme", Releases: cat, Interval: time.Hour}
	ms, meta := d.gather()
	got := map[string]float64{}
	for _, m := range append(ms, meta...) {
		var pm = new(dtoMetric)
		if err := pm.read(m); err != nil {
			t.Fatal(err)
		}
		got[pm.key()] = pm.value
	}
	check := func(key string, want float64) {
		t.Helper()
		if got[key] != want {
			t.Errorf("%s = %v, want %v", key, got[key], want)
		}
	}
	check(`fleetcore_enrollments{enabled=true,type=Device}`, 1)
	check(`fleetcore_enrollments{enabled=false,type=User}`, 1)
	check(`fleetcore_devices_by_dep{}`, 1)
	check(`fleetcore_devices_not_seen{period=1d}`, 1)
	check(`fleetcore_devices_not_seen{period=7d}`, 0)
	check(`fleetcore_reconcile_queue_due{}`, 1)
	check(`fleetcore_command_queue{status=Queued}`, 1)
	check(`fleetcore_blueprint_applications_given_up{}`, 1)
	check(`fleetcore_devices_os_currency{platform=macOS,state=behind_in_major}`, 1)
	check(`fleetcore_scrape_collector_success{collector=devices}`, 1)
	for k := range got {
		if strings.Contains(k, "scrape_collector_success") && got[k] != 1 {
			t.Errorf("%s failed", k)
		}
	}
	if got[`fleetcore_command_queue_oldest_unanswered_age_seconds{}`] < 50 {
		t.Errorf("oldest unanswered: %v", got[`fleetcore_command_queue_oldest_unanswered_age_seconds{}`])
	}
}
