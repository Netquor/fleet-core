package vpp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// LookupBase is Apple's public catalog service.
const LookupBase = "https://itunes.apple.com/lookup"

// AppInfo is what the App Store says about an app.
type AppInfo struct {
	AdamID   string `json:"adam_id"`
	BundleID string `json:"bundle_id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Seller   string `json:"seller,omitempty"`
}

// Lookup finds an app in the App Store catalog by its number: the bundle identifier is what removing the app needs, and what an administrator recognizes it by.
func Lookup(ctx context.Context, hc *http.Client, base, adamID, country string) (*AppInfo, error) {
	if base == "" {
		base = LookupBase
	}
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	if country == "" {
		country = "us"
	}
	// The iOS catalog first, then the Mac catalog.
	for _, entity := range []string{"", "macSoftware"} {
		q := url.Values{"id": {adamID}, "country": {country}}
		if entity != "" {
			q.Set("entity", entity)
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", base+"?"+q.Encode(), nil)
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		var out struct {
			Results []struct {
				TrackID    int64  `json:"trackId"`
				BundleID   string `json:"bundleId"`
				TrackName  string `json:"trackName"`
				Version    string `json:"version"`
				SellerName string `json:"sellerName"`
			} `json:"results"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("App Store lookup: HTTP %d", resp.StatusCode)
		}
		if err != nil {
			return nil, err
		}
		if len(out.Results) > 0 && out.Results[0].BundleID != "" {
			r := out.Results[0]
			return &AppInfo{AdamID: adamID, BundleID: r.BundleID, Name: r.TrackName, Version: r.Version, Seller: r.SellerName}, nil
		}
	}
	return nil, errors.New("the App Store has no app with that number in this country")
}
