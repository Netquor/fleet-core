// Package osreleases knows the latest shipping version of each Apple operating system, from Apple's public releases feed
// (https://developer.apple.com/news/releases/rss/releases.rss). Betas and release candidates are ignored. It is what lets the server tell which devices are out of date,
// per platform and per major version (a Mac that cannot run the newest major is judged against the newest release of the major it can run).
package osreleases

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/schemas"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// FeedURL is Apple's releases feed.
const FeedURL = "https://developer.apple.com/news/releases/rss/releases.rss"

// Release is one shipping OS release.
type Release struct {
	Platform    string    `bson:"platform" json:"platform"` // macOS, iOS, iPadOS, tvOS, watchOS, visionOS
	Version     string    `bson:"version" json:"version"`
	Build       string    `bson:"build" json:"build"`
	Major       int       `bson:"major" json:"major"`
	Num         int64     `bson:"num" json:"-"`
	PublishedAt time.Time `bson:"published_at" json:"published_at"`
	// ExpiresAt, Devices and Source come from Apple's GDMF service (Source "gdmf"): when Apple stops offering the release, and the hardware it supports
	// (model identifiers for iOS, iPadOS and visionOS; board IDs for macOS). The RSS feed (Source "rss") has neither.
	ExpiresAt time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	Devices   []string  `bson:"devices,omitempty" json:"-"`
	Source    string    `bson:"source,omitempty" json:"source,omitempty"`
}

var title = regexp.MustCompile(`^(macOS|iOS|iPadOS|tvOS|watchOS|visionOS)\s+(\d+(?:\.\d+){1,2})\s+\(([0-9A-Za-z]+)\)$`)

// Parse reads the feed and returns the shipping releases (anything whose title carries beta, RC, release candidate or GM is skipped).
func Parse(r io.Reader) ([]Release, error) {
	var feed struct {
		Items []struct {
			Title   string `xml:"title"`
			PubDate string `xml:"pubDate"`
		} `xml:"channel>item"`
	}
	if err := xml.NewDecoder(r).Decode(&feed); err != nil {
		return nil, err
	}
	var out []Release
	for _, it := range feed.Items {
		t := strings.TrimSpace(it.Title)
		low := strings.ToLower(t)
		if strings.Contains(low, "beta") || strings.Contains(low, "release candidate") || strings.Contains(low, " rc") || strings.Contains(low, "gm seed") || strings.Contains(low, " seed") {
			continue
		}
		m := title.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		num, ok := schemas.VersionNum(m[2])
		if !ok {
			continue
		}
		rel := Release{Platform: m[1], Version: m[2], Build: m[3], Num: num, Major: int(num / 1_000_000), PublishedAt: parseDate(it.PubDate)}
		out = append(out, rel)
	}
	return out, nil
}

// parseDate reads the feed's dates, whose zone is an abbreviation Go does not resolve (PDT, PST).
func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	zones := map[string]string{" PDT": " -0700", " PST": " -0800", " EDT": " -0400", " EST": " -0500", " GMT": " +0000", " UTC": " +0000"}
	for abbr, off := range zones {
		if strings.HasSuffix(s, abbr) {
			s = strings.TrimSuffix(s, abbr) + off
			break
		}
	}
	for _, layout := range []string{"Mon, 02 Jan 2006 15:04:05 -0700", time.RFC1123Z} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// Catalog answers "what is the newest" questions over a set of releases. It is safe for concurrent use.
type Catalog struct {
	mu       sync.RWMutex
	releases []Release
	updated  time.Time
	// available is what Apple's GDMF service offers right now (platform|version). Apple only enforces an update that GDMF lists.
	available   map[string]bool
	gdmfLoaded  bool
	gdmfUpdated time.Time
}

func availKey(platform, version string) string {
	if platform == "iPadOS" {
		platform = "iOS"
	}
	return platform + "|" + version
}

// SetAvailable records what GDMF offers now.
func (c *Catalog) SetAvailable(rs []Release) {
	m := make(map[string]bool, len(rs))
	for _, r := range rs {
		m[availKey(r.Platform, r.Version)] = true
	}
	c.mu.Lock()
	c.available, c.gdmfLoaded, c.gdmfUpdated = m, true, time.Now().UTC()
	c.mu.Unlock()
}

// Available reports whether Apple currently offers the release. Until GDMF has been read once, releases known from the feed count as available.
func (c *Catalog) Available(platform, version string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.gdmfLoaded {
		return true
	}
	return c.available[availKey(platform, version)]
}

// BestFor is the newest release a device can be moved to: offered by Apple now, and (where Apple lists supported hardware as model identifiers) supporting the device's model.
// major > 0 restricts it to that major version. For macOS Apple lists board IDs, which a model identifier cannot be matched to, so hardware is not judged there.
func (c *Catalog) BestFor(platform, model string, major int) (Release, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.find(platform, func(r Release) bool {
		if major > 0 && r.Major != major {
			return false
		}
		if c.gdmfLoaded && !c.available[availKey(r.Platform, r.Version)] {
			return false
		}
		if platform != "macOS" && model != "" && len(r.Devices) > 0 {
			ok := false
			for _, d := range r.Devices {
				if d == model {
					ok = true
					break
				}
			}
			return ok
		}
		return true
	})
}

// Replace swaps in a new set of releases.
func (c *Catalog) Replace(rs []Release) {
	rs = append([]Release(nil), rs...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].Num > rs[j].Num })
	c.mu.Lock()
	c.releases, c.updated = rs, time.Now().UTC()
	c.mu.Unlock()
}

// Latest is the newest release for a platform; iPadOS and iOS share versions, so either name finds the same ones.
func (c *Catalog) Latest(platform string) (Release, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.find(platform, func(r Release) bool { return true })
}

// find returns the newest release of the platform that passes keep. iPadOS falls back to iOS when Apple has not listed an iPadOS release that fits.
func (c *Catalog) find(platform string, keep func(Release) bool) (Release, bool) {
	for _, p := range []string{platform, fallback(platform)} {
		if p == "" {
			continue
		}
		for _, r := range c.releases {
			if r.Platform == p && keep(r) {
				return r, true
			}
		}
	}
	return Release{}, false
}

func fallback(platform string) string {
	if platform == "iPadOS" {
		return "iOS"
	}
	return ""
}

// LatestInMajor is the newest release of one major version (macOS 26.x), what a device that cannot move up should reach.
func (c *Catalog) LatestInMajor(platform string, major int) (Release, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.find(platform, func(r Release) bool { return r.Major == major })
}

// Majors lists the major versions that have a shipping release for the platform, newest first.
func (c *Catalog) Majors(platform string) []int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	seen := map[int]bool{}
	var out []int
	for _, r := range c.releases {
		if (r.Platform == platform || r.Platform == fallback(platform)) && !seen[r.Major] {
			seen[r.Major] = true
			out = append(out, r.Major)
		}
	}
	return out
}

// All returns every known release, newest first.
func (c *Catalog) All() []Release {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Release(nil), c.releases...)
}

// UpdatedAt is when the catalog last changed.
func (c *Catalog) UpdatedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.updated
}

// Status compares a device with the catalog.
type Status struct {
	Current     bool     `json:"current"`            // already on the newest release of its major
	BehindMinor bool     `json:"behind_in_major"`    // an update exists in the device's own major version
	NewMajor    bool     `json:"newer_major_exists"` // a newer major version exists (the device may or may not support it)
	Target      *Release `json:"target,omitempty"`   // the newest release in the device's own major
}

// Compare says how far behind a device is. ok is false when the platform or version is unknown.
func (c *Catalog) Compare(platform, version string) (Status, bool) {
	num, ok := schemas.VersionNum(version)
	if !ok {
		return Status{}, false
	}
	latest, ok := c.Latest(platform)
	if !ok {
		return Status{}, false
	}
	st := Status{}
	if t, ok := c.LatestInMajor(platform, int(num/1_000_000)); ok {
		st.Target = &t
		st.BehindMinor = num < t.Num
		st.Current = !st.BehindMinor
	}
	st.NewMajor = int(num/1_000_000) < latest.Major
	return st, true
}

// Refresher fetches the feed and keeps a Catalog (and optionally MongoDB) current.
type Refresher struct {
	Catalog *Catalog
	DB      *mongo.Database
	URL     string
	GDMFURL string
	HTTP    *http.Client
	Logf    func(string, ...any)
	// OnChange is called after the catalog gains a release it did not have.
	OnChange func([]Release)
}

func (r *Refresher) logf(f string, a ...any) {
	if r.Logf != nil {
		r.Logf(f, a...)
	}
}

// Load fills the catalog from the saved copy (so a restart does not wait for the feed).
func (r *Refresher) Load(ctx context.Context) error {
	if r.DB == nil {
		return nil
	}
	cur, err := r.DB.Collection("os_releases").Find(ctx, bson.D{})
	if err != nil {
		return err
	}
	var rows []Release
	if err := cur.All(ctx, &rows); err != nil {
		return err
	}
	if len(rows) > 0 {
		r.Catalog.Replace(rows)
	}
	return nil
}

// Check fetches the feed once. Releases already known stay known (the feed only lists recent ones). It returns the number of new releases.
func (r *Refresher) Check(ctx context.Context) (int, error) {
	url := r.URL
	if url == "" {
		url = FeedURL
	}
	hc := r.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: time.Minute}
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("releases feed: HTTP %d", resp.StatusCode)
	}
	fresh, err := Parse(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, err
	}
	if len(fresh) == 0 {
		return 0, fmt.Errorf("releases feed: no releases found (format changed?)")
	}
	known := map[string]bool{}
	merged := r.Catalog.All()
	for _, k := range merged {
		known[k.Platform+"|"+k.Version] = true
	}
	added := 0
	for _, f := range fresh {
		if !known[f.Platform+"|"+f.Version] {
			merged = append(merged, f)
			known[f.Platform+"|"+f.Version] = true
			added++
			if r.DB != nil {
				if _, err := r.DB.Collection("os_releases").ReplaceOne(ctx, bson.D{{Key: "_id", Value: f.Platform + "|" + f.Version}}, f, options.Replace().SetUpsert(true)); err != nil {
					return 0, err
				}
			}
		}
	}
	if added > 0 {
		r.Catalog.Replace(merged)
		r.logf("apple releases: %d new", added)
		if r.OnChange != nil {
			r.OnChange(merged)
		}
	}
	return added, nil
}

// Run checks GDMF and the releases feed now and then every interval (default hourly) until ctx ends.
func (r *Refresher) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	for {
		if _, err := r.CheckAll(ctx); err != nil && ctx.Err() == nil {
			r.logf("apple releases: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// GDMFURL is Apple's service for the software updates available to managed devices; Apple's declarative management documentation names it as the source for enforcement targets.
const GDMFURL = "https://gdmf.apple.com/v2/pmv"

// ParseGDMF reads GDMF's response: the public releases (what the Catalog learns) and everything on offer right now (what may be enforced).
func ParseGDMF(r io.Reader) (public, offered []Release, err error) {
	var doc struct {
		PublicAssetSets map[string][]gdmfEntry `json:"PublicAssetSets"`
		AssetSets       map[string][]gdmfEntry `json:"AssetSets"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, nil, err
	}
	conv := func(m map[string][]gdmfEntry) []Release {
		// GDMF lists one version several times, once per group of hardware (with its own build); a release is the union.
		byKey := map[string]*Release{}
		var order []string
		for platform, entries := range m {
			for _, e := range entries {
				num, ok := schemas.VersionNum(e.ProductVersion)
				if !ok {
					continue
				}
				pub, _ := time.Parse("2006-01-02", e.PostingDate)
				exp, _ := time.Parse("2006-01-02", e.ExpirationDate)
				key := platform + "|" + e.ProductVersion
				if r, ok := byKey[key]; ok {
					seen := make(map[string]bool, len(r.Devices))
					for _, d := range r.Devices {
						seen[d] = true
					}
					for _, d := range e.SupportedDevices {
						if !seen[d] {
							r.Devices = append(r.Devices, d)
						}
					}
					if pub.Before(r.PublishedAt) && !pub.IsZero() {
						r.PublishedAt = pub
					}
					if exp.After(r.ExpiresAt) {
						r.ExpiresAt = exp
					}
					continue
				}
				byKey[key] = &Release{Platform: platform, Version: e.ProductVersion, Build: e.Build, Major: int(num / 1_000_000), Num: num, PublishedAt: pub, ExpiresAt: exp, Devices: append([]string(nil), e.SupportedDevices...), Source: "gdmf"}
				order = append(order, key)
			}
		}
		sort.Strings(order)
		out := make([]Release, 0, len(order))
		for _, k := range order {
			out = append(out, *byKey[k])
		}
		return out
	}
	public, offered = conv(doc.PublicAssetSets), conv(doc.AssetSets)
	if len(public) == 0 {
		return nil, nil, fmt.Errorf("GDMF: no public releases found (format changed?)")
	}
	return public, append(offered, public...), nil
}

type gdmfEntry struct {
	ProductVersion   string   `json:"ProductVersion"`
	Build            string   `json:"Build"`
	PostingDate      string   `json:"PostingDate"`
	ExpirationDate   string   `json:"ExpirationDate"`
	SupportedDevices []string `json:"SupportedDevices"`
}

// CheckGDMF reads GDMF once: public releases join the catalog (with their hardware lists and expiry), and the offered set is remembered. It returns the number of new releases.
func (r *Refresher) CheckGDMF(ctx context.Context) (int, error) {
	url := r.GDMFURL
	if url == "" {
		url = GDMFURL
	}
	hc := r.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: time.Minute}
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("GDMF: HTTP %d", resp.StatusCode)
	}
	public, offered, err := ParseGDMF(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return 0, err
	}
	merged := r.Catalog.All()
	index := map[string]int{}
	for i, k := range merged {
		index[k.Platform+"|"+k.Version] = i
	}
	added := 0
	for _, f := range public {
		key := f.Platform + "|" + f.Version
		if i, ok := index[key]; ok {
			// GDMF knows more than the feed does (hardware, expiry, a precise date): keep what it says.
			merged[i].Devices, merged[i].ExpiresAt, merged[i].Source = f.Devices, f.ExpiresAt, "gdmf"
			if !f.PublishedAt.IsZero() {
				merged[i].PublishedAt = f.PublishedAt
			}
			if merged[i].Build == "" {
				merged[i].Build = f.Build
			}
		} else {
			merged = append(merged, f)
			index[key] = len(merged) - 1
			added++
		}
		if r.DB != nil {
			i := index[key]
			if _, err := r.DB.Collection("os_releases").ReplaceOne(ctx, bson.D{{Key: "_id", Value: key}}, merged[i], options.Replace().SetUpsert(true)); err != nil {
				return 0, err
			}
		}
	}
	r.Catalog.Replace(merged)
	r.Catalog.SetAvailable(offered)
	if added > 0 {
		r.logf("apple GDMF: %d new releases", added)
		if r.OnChange != nil {
			r.OnChange(merged)
		}
	}
	return added, nil
}

// CheckAll reads GDMF and the releases feed. One failing does not stop the other; the error is returned only if neither worked.
func (r *Refresher) CheckAll(ctx context.Context) (int, error) {
	n1, err1 := r.CheckGDMF(ctx)
	n2, err2 := r.Check(ctx)
	if err1 != nil && err2 != nil {
		return 0, fmt.Errorf("GDMF: %v; releases feed: %v", err1, err2)
	}
	if err1 != nil {
		r.logf("apple GDMF: %v", err1)
	}
	if err2 != nil {
		r.logf("apple releases feed: %v", err2)
	}
	return n1 + n2, nil
}
