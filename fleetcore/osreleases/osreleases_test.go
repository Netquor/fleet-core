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
