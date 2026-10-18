// Package vpp talks to Apple's Apps and Books (VPP) service: which apps an organization owns, how many licenses are left, and who holds them. Licenses are assigned to devices by serial
// number, so an app installs with no Apple Account on the device. The token is the one downloaded from Apple Business Manager.
package vpp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BaseURL is Apple's service.
const BaseURL = "https://vpp.itunes.apple.com/mdm/v2"

// Token is a service token as Apple Business Manager issues it: base64 of a JSON document.
type Token struct {
	Raw     string
	Token   string    `json:"token"`
	Expires time.Time `json:"-"`
	ExpDate string    `json:"expDate"`
	OrgName string    `json:"orgName"`
}

// ParseToken reads a service token. It does not check it with Apple.
func ParseToken(s string) (*Token, error) {
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(s); err != nil {
			return nil, errors.New("the service token is not base64")
		}
	}
	t := &Token{Raw: s}
	if err := json.Unmarshal(raw, t); err != nil || t.Token == "" {
		return nil, errors.New("the service token is not the file Apple Business Manager issues")
	}
	if t.ExpDate != "" {
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05-0700", "2006-01-02T15:04:05Z0700"} {
			if e, err := time.Parse(layout, t.ExpDate); err == nil {
				t.Expires = e
				break
			}
		}
	}
	return t, nil
}

// Client calls the service with one token.
type Client struct {
	Token   string // the sToken, as downloaded
	BaseURL string
	HTTP    *http.Client
}

// Error is an answer from Apple that says no.
type Error struct {
	Status  int
	Number  int    `json:"errorNumber"`
	Message string `json:"errorMessage"`
	// RetryAfter is how long Apple asked to wait (when it limits the rate).
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("Apps and Books: %s (%d)", e.Message, e.Number)
	}
	return fmt.Sprintf("Apps and Books: HTTP %d", e.Status)
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	base := c.BaseURL
	if base == "" {
		base = BaseURL
	}
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 300 {
		e := &Error{Status: resp.StatusCode}
		_ = json.Unmarshal(b, e)
		if s := resp.Header.Get("Retry-After"); s != "" {
			var secs int
			fmt.Sscanf(s, "%d", &secs)
			e.RetryAfter = time.Duration(secs) * time.Second
		}
		return e
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Config is what Apple says about the location the token belongs to.
type Config struct {
	LocationName        string `json:"locationName"`
	UID                 string `json:"uId"`
	CountryISO2         string `json:"countryISO2ShortCode"`
	DefaultPlatform     string `json:"defaultPlatform"`
	AppleID             string `json:"appleId"`
	IsCustomB2B         bool   `json:"isCustomB2B"`
	APNSEnvironment     string `json:"apnsEnvironment"`
	MaxBatchAssociateSz int    `json:"maxBatchAssociateSize"`
}

// ClientConfig checks the token and returns its location.
func (c *Client) ClientConfig(ctx context.Context) (*Config, error) {
	var out Config
	return &out, c.do(ctx, "GET", "/client/config", nil, nil, &out)
}

// Asset is an app (or book) the organization owns licenses for.
type Asset struct {
	AdamID             string   `json:"adamId"`
	PricingParam       string   `json:"pricingParam"`
	ProductType        string   `json:"productType"`
	DeviceAssignable   bool     `json:"deviceAssignable"`
	Revocable          bool     `json:"revocable"`
	SupportedPlatforms []string `json:"supportedPlatforms"`
	TotalCount         int      `json:"totalCount"`
	AssignedCount      int      `json:"assignedCount"`
	RetiredCount       int      `json:"retiredCount"`
	AvailableCount     int      `json:"availableCount"`
}

// Supports reports whether the app runs on a platform (iPadOS counts as iOS).
func (a Asset) Supports(platform string) bool {
	if platform == "iPadOS" {
		platform = "iOS"
	}
	for _, p := range a.SupportedPlatforms {
		if p == platform {
			return true
		}
	}
	return len(a.SupportedPlatforms) == 0
}

// Assets lists owned assets, or one by its App Store ID.
func (c *Client) Assets(ctx context.Context, adamID string) ([]Asset, error) {
	var all []Asset
	q := url.Values{"includeLicenseCounts": {"true"}}
	if adamID != "" {
		q.Set("adamId", adamID)
	}
	for page := 0; page < 100; page++ {
		var out struct {
			Assets        []Asset `json:"assets"`
			NextPageToken string  `json:"nextPageToken"`
		}
		if err := c.do(ctx, "GET", "/assets", q, nil, &out); err != nil {
			return all, err
		}
		all = append(all, out.Assets...)
		if out.NextPageToken == "" {
			break
		}
		q.Set("pageToken", out.NextPageToken)
	}
	return all, nil
}

// Assignment is one license held by a device.
type Assignment struct {
	AdamID       string `json:"adamId"`
	PricingParam string `json:"pricingParam"`
	SerialNumber string `json:"serialNumber"`
}

// Assignments lists the licenses held, for one serial number and/or one app.
func (c *Client) Assignments(ctx context.Context, serial, adamID string) ([]Assignment, error) {
	var all []Assignment
	q := url.Values{}
	if serial != "" {
		q.Set("serialNumber", serial)
	}
	if adamID != "" {
		q.Set("adamId", adamID)
	}
	for page := 0; page < 1000; page++ {
		var out struct {
			Assignments   []Assignment `json:"assignments"`
			NextPageToken string       `json:"nextPageToken"`
		}
		if err := c.do(ctx, "GET", "/assignments", q, nil, &out); err != nil {
			return all, err
		}
		all = append(all, out.Assignments...)
		if out.NextPageToken == "" {
			break
		}
		q.Set("pageToken", out.NextPageToken)
	}
	return all, nil
}

type assetRef struct {
	AdamID       string `json:"adamId"`
	PricingParam string `json:"pricingParam"`
}

type assignBody struct {
	Assets        []assetRef `json:"assets"`
	SerialNumbers []string   `json:"serialNumbers"`
}

// Event is an asynchronous change at Apple: it is accepted first and carried out after.
type Event struct {
	EventID string `json:"eventId"`
	// Status is PROCESSING, COMPLETE or FAILED (from Status).
	Status string `json:"eventStatus"`
}

// Associate assigns licenses of the apps to the serial numbers. Apple accepts the request and does it after; follow it with EventStatus.
func (c *Client) Associate(ctx context.Context, adamIDs, serials []string) (*Event, error) {
	return c.assign(ctx, "/assignments/associate", adamIDs, serials)
}

// Disassociate takes the licenses back.
func (c *Client) Disassociate(ctx context.Context, adamIDs, serials []string) (*Event, error) {
	return c.assign(ctx, "/assignments/disassociate", adamIDs, serials)
}

func (c *Client) assign(ctx context.Context, path string, adamIDs, serials []string) (*Event, error) {
	b := assignBody{SerialNumbers: serials}
	for _, a := range adamIDs {
		b.Assets = append(b.Assets, assetRef{AdamID: a, PricingParam: "STDQ"})
	}
	var out Event
	return &out, c.do(ctx, "POST", path, nil, b, &out)
}

// EventStatus asks how an event went.
func (c *Client) EventStatus(ctx context.Context, eventID string) (*Event, error) {
	var out Event
	err := c.do(ctx, "GET", "/status", url.Values{"eventId": {eventID}}, nil, &out)
	if out.EventID == "" {
		out.EventID = eventID
	}
	return &out, err
}
