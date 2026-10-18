package osreleases

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const feed = `<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Xcode 27.1 (27A9275)</title><pubDate>Thu, 15 Oct 2026 13:00:00 PDT</pubDate></item>
<item><title>iOS 27.2 beta 4 (24B5110a)</title><pubDate>Tue, 13 Oct 2026 10:00:00 PDT</pubDate></item>
<item><title>macOS 27.2 beta 4 (26B5112a)</title><pubDate>Tue, 13 Oct 2026 10:00:00 PDT</pubDate></item>
<item><title>macOS 27.0.1 (26A434)</title><pubDate>Mon, 12 Oct 2026 10:00:00 PDT</pubDate></item>
<item><title>iOS 27.0.1 (24A446)</title><pubDate>Mon, 12 Oct 2026 10:00:00 PDT</pubDate></item>
<item><title>iPadOS 26.7.1 (23H30)</title><pubDate>Fri, 09 Oct 2026 10:00:00 PDT</pubDate></item>
<item><title>macOS 26.6.2 (25G83)</title><pubDate>Fri, 02 Oct 2026 10:00:00 PDT</pubDate></item>
<item><title>iOS 18.7.10 (22H374)</title><pubDate>Fri, 02 Oct 2026 10:00:00 PDT</pubDate></item>
<item><title>iOS 28.0 RC (25A1)</title><pubDate>Fri, 02 Oct 2026 10:00:00 PDT</pubDate></item>
<item><title>TestFlight Update</title><pubDate>Wed, 14 Oct 2026 14:00:00 PDT</pubDate></item>
</channel></rss>`

func TestParseSkipsBetasAndNonOS(t *testing.T) {
	rs, err := Parse(strings.NewReader(feed))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 5 {
		t.Fatalf("%d releases: %+v", len(rs), rs)
	}
	for _, r := range rs {
		if strings.Contains(r.Version, "beta") || r.PublishedAt.IsZero() {
			t.Errorf("%+v", r)
		}
	}
}

func TestCatalog(t *testing.T) {
	rs, _ := Parse(strings.NewReader(feed))
	var c Catalog
	c.Replace(rs)
	if l, _ := c.Latest("macOS"); l.Version != "27.0.1" {
		t.Errorf("latest macOS %s", l.Version)
	}
	if l, _ := c.LatestInMajor("macOS", 26); l.Version != "26.6.2" {
		t.Errorf("latest macOS 26 %s", l.Version)
	}
	if l, _ := c.Latest("iPadOS"); l.Version != "26.7.1" { // Apple listed an iPadOS release; it is used before falling back to iOS
		t.Errorf("latest iPadOS %s", l.Version)
	}
	st, ok := c.Compare("macOS", "26.5")
	if !ok || !st.BehindMinor || !st.NewMajor || st.Target.Version != "26.6.2" {
		t.Errorf("%+v", st)
	}
	st, _ = c.Compare("macOS", "26.6.2")
	if !st.Current || !st.NewMajor || st.BehindMinor {
		t.Errorf("%+v", st)
	}
	if _, ok := c.Compare("macOS", "banana"); ok {
		t.Error("garbage version accepted")
	}
}

func TestRefresher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(feed)) }))
	defer srv.Close()
	var c Catalog
	changed := 0
	r := &Refresher{Catalog: &c, URL: srv.URL, OnChange: func([]Release) { changed++ }}
	if n, err := r.Check(context.Background()); err != nil || n != 5 {
		t.Fatalf("%d %v", n, err)
	}
	if n, _ := r.Check(context.Background()); n != 0 || changed != 1 {
		t.Errorf("second check added %d, changed %d", n, changed)
	}
}

// Against the real feed when asked for: OSRELEASES_LIVE=1 go test ./fleetcore/osreleases
func TestLiveFeed(t *testing.T) {
	if os.Getenv("OSRELEASES_LIVE") == "" {
		t.Skip("OSRELEASES_LIVE not set")
	}
	var c Catalog
	r := &Refresher{Catalog: &c}
	n, err := r.Check(context.Background())
	if err != nil || n == 0 {
		t.Fatalf("%d %v", n, err)
	}
	for _, p := range []string{"macOS", "iOS", "iPadOS", "visionOS"} {
		l, ok := c.Latest(p)
		t.Logf("%s latest %s (%s)", p, l.Version, l.Build)
		if !ok {
			t.Errorf("no %s", p)
		}
	}
}

const gdmf = `{"PublicAssetSets":{
 "iOS":[{"ProductVersion":"27.0.1","Build":"24A446","PostingDate":"2026-10-12","ExpirationDate":"2027-01-16","SupportedDevices":["iPhone16,1","iPhone17,1"]},
        {"ProductVersion":"27.0.1","Build":"24A9999","PostingDate":"2026-09-28","ExpirationDate":"2027-01-16","SupportedDevices":["iPhone19,2"]},
        {"ProductVersion":"26.7.1","Build":"23H30","PostingDate":"2026-10-09","ExpirationDate":"2027-01-16","SupportedDevices":["iPhone12,1","iPhone16,1"]}],
 "macOS":[{"ProductVersion":"27.0.1","Build":"26A434","PostingDate":"2026-10-12","ExpirationDate":"2027-01-16","SupportedDevices":["J314sAP"]}]},
 "AssetSets":{"iOS":[{"ProductVersion":"27.0","Build":"24A6437","PostingDate":"2026-09-14","ExpirationDate":"2027-01-16","SupportedDevices":["iPhone16,1"]}]}}`

func TestGDMFSetsAvailabilityAndHardware(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(gdmf)) }))
	defer srv.Close()
	var c Catalog
	r := &Refresher{Catalog: &c, GDMFURL: srv.URL}
	if n, err := r.CheckGDMF(context.Background()); err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
	if !c.Available("iOS", "27.0.1") || c.Available("iOS", "27.9") || !c.Available("iPadOS", "27.0.1") {
		t.Error("availability")
	}
	// An old iPhone that Apple's hardware list stops at 26 is moved to the newest it supports, not the newest there is.
	if b, ok := c.BestFor("iOS", "iPhone12,1", 0); !ok || b.Version != "26.7.1" {
		t.Errorf("best for iPhone12,1: %+v", b)
	}
	if b, ok := c.BestFor("iOS", "iPhone16,1", 0); !ok || b.Version != "27.0.1" {
		t.Errorf("best for iPhone16,1: %+v", b)
	}
	if b, ok := c.BestFor("iOS", "iPhone16,1", 26); !ok || b.Version != "26.7.1" {
		t.Errorf("best in 26: %+v", b)
	}
	// The same version listed twice for different hardware is one release with both lists.
	if b, ok := c.BestFor("iOS", "iPhone19,2", 0); !ok || b.Version != "27.0.1" {
		t.Errorf("best for iPhone19,2 (listed only in a separate entry): %+v", b)
	}
	// macOS lists board IDs, so hardware is not judged.
	if b, ok := c.BestFor("macOS", "Mac15,6", 0); !ok || b.Version != "27.0.1" {
		t.Errorf("best for a Mac: %+v", b)
	}
}

// Against the real service when asked for: OSRELEASES_LIVE=1 go test ./fleetcore/osreleases
func TestLiveGDMF(t *testing.T) {
	if os.Getenv("OSRELEASES_LIVE") == "" {
		t.Skip("OSRELEASES_LIVE not set")
	}
	var c Catalog
	r := &Refresher{Catalog: &c}
	if n, err := r.CheckGDMF(context.Background()); err != nil || n == 0 {
		t.Fatalf("%d %v", n, err)
	}
	b, ok := c.BestFor("iOS", "iPhone16,1", 0)
	t.Logf("best for iPhone16,1: %s (%s)", b.Version, b.Build)
	if !ok {
		t.Error("no release for a current iPhone")
	}
}
