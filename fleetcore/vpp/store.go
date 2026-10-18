package vpp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/micromdm/nanomdm/fleetcore/seal"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TokenInfo describes a stored service token (never the token itself).
type TokenInfo struct {
	Name         string    `bson:"name" json:"name"`
	OrgName      string    `bson:"org_name" json:"org_name"`
	LocationName string    `bson:"location_name" json:"location_name"`
	Expires      time.Time `bson:"expires" json:"expires"`
	AddedAt      time.Time `bson:"added_at" json:"added_at"`
}

// Store keeps service tokens (sealed) and the state of license assignments.
type Store struct {
	db     *mongo.Database
	tid    string
	Sealer seal.Interface
	Now    func() time.Time
}

// NewStore returns the store. tenant may be empty.
func NewStore(ctx context.Context, db *mongo.Database, tenant string) (*Store, error) {
	s := &Store{db: db, tid: tenant}
	k := bson.D{{Key: "serial", Value: 1}}
	if tenant != "" {
		k = bson.D{{Key: "t", Value: 1}, {Key: "serial", Value: 1}}
	}
	if _, err := db.Collection("vpp_licenses").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: k}); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Store) key(parts ...string) string {
	k := strings.Join(parts, "\x1f")
	if s.tid == "" {
		return k
	}
	return s.tid + "\x1f" + k
}

func (s *Store) scope(f bson.D) bson.D {
	if s.tid == "" {
		return f
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, f...)
}

func (s *Store) stamp(d bson.D) bson.D {
	if s.tid == "" {
		return d
	}
	return append(bson.D{{Key: "t", Value: s.tid}}, d...)
}

// PutToken stores a service token after checking it with Apple (c may be nil to skip the check).
func (s *Store) PutToken(ctx context.Context, name, sToken string, c *Client) (*TokenInfo, error) {
	t, err := ParseToken(sToken)
	if err != nil {
		return nil, err
	}
	if !t.Expires.IsZero() && t.Expires.Before(s.now()) {
		return nil, errors.New("the service token has expired: download a new one from Apple Business Manager")
	}
	info := &TokenInfo{Name: name, OrgName: t.OrgName, Expires: t.Expires, AddedAt: s.now()}
	if c != nil {
		c.Token = t.Raw
		cfg, err := c.ClientConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("Apple did not accept the token: %w", err)
		}
		info.LocationName = cfg.LocationName
	}
	sealed, err := seal.Put(s.Sealer, "vpp.token", []byte(t.Raw))
	if err != nil {
		return nil, err
	}
	doc := s.stamp(bson.D{{Key: "name", Value: name}, {Key: "token", Value: sealed}, {Key: "org_name", Value: info.OrgName}, {Key: "location_name", Value: info.LocationName}, {Key: "expires", Value: info.Expires}, {Key: "added_at", Value: info.AddedAt}})
	_, err = s.db.Collection("vpp_tokens").ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(name)}}, doc, options.Replace().SetUpsert(true))
	return info, err
}

// Token returns a stored token for use.
func (s *Store) Token(ctx context.Context, name string) (string, error) {
	var d struct {
		Token string `bson:"token"`
	}
	err := s.db.Collection("vpp_tokens").FindOne(ctx, bson.D{{Key: "_id", Value: s.key(name)}}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", fmt.Errorf("no Apps and Books token named %q", name)
	}
	if err != nil {
		return "", err
	}
	b, err := seal.Get(s.Sealer, "vpp.token", d.Token)
	return string(b), err
}

// Tokens lists the stored tokens' details.
func (s *Store) Tokens(ctx context.Context) ([]TokenInfo, error) {
	cur, err := s.db.Collection("vpp_tokens").Find(ctx, s.scope(bson.D{}), options.Find().SetProjection(bson.D{{Key: "token", Value: 0}}).SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return nil, err
	}
	var out []TokenInfo
	return out, cur.All(ctx, &out)
}

// DeleteToken forgets a token.
func (s *Store) DeleteToken(ctx context.Context, name string) error {
	_, err := s.db.Collection("vpp_tokens").DeleteOne(ctx, bson.D{{Key: "_id", Value: s.key(name)}})
	return err
}

type licenseDoc struct {
	State   string    `bson:"state"` // assigned, pending, failed
	EventID string    `bson:"event_id"`
	Error   string    `bson:"error"`
	At      time.Time `bson:"at"`
}

func (s *Store) license(ctx context.Context, token, adam, serial string) (*licenseDoc, error) {
	var d licenseDoc
	err := s.db.Collection("vpp_licenses").FindOne(ctx, bson.D{{Key: "_id", Value: s.key(token, adam, serial)}}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &d, err
}

func (s *Store) setLicense(ctx context.Context, token, adam, serial string, d licenseDoc) error {
	d.At = s.now()
	doc := s.stamp(bson.D{{Key: "token", Value: token}, {Key: "adam", Value: adam}, {Key: "serial", Value: serial}, {Key: "state", Value: d.State}, {Key: "event_id", Value: d.EventID}, {Key: "error", Value: d.Error}, {Key: "at", Value: d.At}})
	_, err := s.db.Collection("vpp_licenses").ReplaceOne(ctx, bson.D{{Key: "_id", Value: s.key(token, adam, serial)}}, doc, options.Replace().SetUpsert(true))
	return err
}

// Licensing assigns licenses to devices on demand, remembering what it asked Apple so that it asks once.
type Licensing struct {
	Store   *Store
	HTTP    *http.Client
	BaseURL string

	mu     sync.Mutex
	assets map[string]cachedAsset
}

type cachedAsset struct {
	a  *Asset
	at time.Time
}

func (l *Licensing) client(ctx context.Context, token string) (*Client, error) {
	t, err := l.Store.Token(ctx, token)
	if err != nil {
		return nil, err
	}
	return &Client{Token: t, BaseURL: l.BaseURL, HTTP: l.HTTP}, nil
}

// Client returns a client for a stored token.
func (l *Licensing) Client(ctx context.Context, token string) (*Client, error) {
	return l.client(ctx, token)
}

func (l *Licensing) asset(ctx context.Context, c *Client, token, adam string) (*Asset, error) {
	l.mu.Lock()
	if ca, ok := l.assets[token+"|"+adam]; ok && time.Since(ca.at) < time.Minute {
		l.mu.Unlock()
		return ca.a, nil
	}
	l.mu.Unlock()
	as, err := c.Assets(ctx, adam)
	if err != nil {
		return nil, err
	}
	if len(as) == 0 {
		return nil, fmt.Errorf("the organization owns no licenses of app %s", adam)
	}
	a := as[0]
	l.mu.Lock()
	if l.assets == nil {
		l.assets = map[string]cachedAsset{}
	}
	l.assets[token+"|"+adam] = cachedAsset{&a, time.Now()}
	l.mu.Unlock()
	return &a, nil
}

// EnsureLicense makes sure the device (by serial number) holds a license of the app. It returns ready when it does, pending when Apple is still working or asked to wait, and an error when
// it cannot be had (not owned, none left, cannot be assigned to a device, not for this platform). It never asks Apple twice for the same assignment.
func (l *Licensing) EnsureLicense(ctx context.Context, token, adamID, serial, platform string) (ready, pending bool, err error) {
	if serial == "" {
		return false, false, errors.New("the device has no serial number to license the app to")
	}
	st := l.Store
	if d, err := st.license(ctx, token, adamID, serial); err != nil {
		return false, false, err
	} else if d != nil {
		switch d.State {
		case "assigned":
			return true, false, nil
		case "pending":
			c, err := l.client(ctx, token)
			if err != nil {
				return false, false, err
			}
			ev, err := c.EventStatus(ctx, d.EventID)
			if err != nil {
				var ae *Error
				if errors.As(err, &ae) && ae.Status == 429 {
					return false, true, nil
				}
				return false, true, nil // try again later
			}
			switch strings.ToUpper(ev.Status) {
			case "COMPLETE":
				return true, false, st.setLicense(ctx, token, adamID, serial, licenseDoc{State: "assigned"})
			case "FAILED":
				_ = st.setLicense(ctx, token, adamID, serial, licenseDoc{State: "failed", Error: "Apple could not assign the license"})
				return false, false, errors.New("Apple could not assign the license")
			}
			return false, true, nil
		}
		// failed earlier: ask again
	}
	c, err := l.client(ctx, token)
	if err != nil {
		return false, false, err
	}
	a, err := l.asset(ctx, c, token, adamID)
	if err != nil {
		return false, false, err
	}
	if !a.DeviceAssignable {
		return false, false, fmt.Errorf("app %s cannot be licensed to devices; it needs user licensing", adamID)
	}
	if !a.Supports(platform) {
		return false, false, fmt.Errorf("app %s is not available for %s", adamID, platform)
	}
	if held, err := c.Assignments(ctx, serial, adamID); err == nil {
		for _, h := range held {
			if h.AdamID == adamID && strings.EqualFold(h.SerialNumber, serial) {
				return true, false, st.setLicense(ctx, token, adamID, serial, licenseDoc{State: "assigned"})
			}
		}
	}
	if a.AvailableCount <= 0 {
		return false, false, fmt.Errorf("no licenses of app %s are left (%d owned, %d assigned)", adamID, a.TotalCount, a.AssignedCount)
	}
	ev, err := c.Associate(ctx, []string{adamID}, []string{serial})
	if err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == 429 {
			return false, true, nil
		}
		return false, false, err
	}
	l.mu.Lock()
	delete(l.assets, token+"|"+adamID) // the counts changed
	l.mu.Unlock()
	return false, true, st.setLicense(ctx, token, adamID, serial, licenseDoc{State: "pending", EventID: ev.EventID})
}
