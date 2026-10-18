package schemas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var nowFunc = func() time.Time { return time.Now().UTC() }

const repo = "apple/device-management"

// Refresher keeps the current set up to date with Apple's repository: it checks the release branch, and when it has moved downloads, parses and checks the new definitions and makes them current.
// A new set is saved in MongoDB (if given) so a restart, and every other server process, starts from it. A download that fails or looks wrong (too few definitions) changes nothing.
type Refresher struct {
	// Ref is a branch, tag or commit; "release" follows Apple's published releases.
	Ref string
	// DB, if set, keeps the newest set (collection schema_sets).
	DB   *mongo.Database
	HTTP *http.Client
	// APIBase and DownloadBase are GitHub's endpoints (set in tests).
	APIBase, DownloadBase string
	// Logf, if set, receives one line per check that changed or failed.
	Logf func(format string, args ...any)
}

func base(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (r *Refresher) logf(f string, a ...any) {
	if r.Logf != nil {
		r.Logf(f, a...)
	}
}

func (r *Refresher) client() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

// Load makes the saved set current if it is newer than what is in use. Call it at start-up.
func (r *Refresher) Load(ctx context.Context) error {
	if r.DB == nil {
		return nil
	}
	var doc struct {
		JSON string `bson:"json"`
	}
	err := r.DB.Collection("schema_sets").FindOne(ctx, bson.D{{Key: "_id", Value: "current"}}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil
	}
	if err != nil {
		return err
	}
	var s Set
	if err := json.Unmarshal([]byte(doc.JSON), &s); err != nil {
		return err
	}
	if s.FetchedAt.After(Current().FetchedAt) {
		Use(&s)
	}
	return nil
}

func (r *Refresher) resolve(ctx context.Context) (string, error) {
	if len(r.Ref) == 40 {
		return r.Ref, nil
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", base(r.APIBase, "https://api.github.com")+"/repos/"+repo+"/commits/"+r.Ref, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := r.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("resolving %s@%s: HTTP %d", repo, r.Ref, resp.StatusCode)
	}
	var c struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil || c.SHA == "" {
		return "", fmt.Errorf("resolving %s@%s: no commit", repo, r.Ref)
	}
	return c.SHA, nil
}

// Check looks for a newer release and switches to it. It returns the set in use afterwards and whether it changed.
func (r *Refresher) Check(ctx context.Context) (*Set, bool, error) {
	if r.Ref == "" {
		r.Ref = "release"
	}
	sha, err := r.resolve(ctx)
	if err != nil {
		return Current(), false, err
	}
	if Current().Ref == sha {
		return Current(), false, nil
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", base(r.DownloadBase, "https://codeload.github.com")+"/"+repo+"/tar.gz/"+sha, nil)
	resp, err := r.client().Do(req)
	if err != nil {
		return Current(), false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Current(), false, fmt.Errorf("downloading %s@%s: HTTP %d", repo, sha, resp.StatusCode)
	}
	s, err := ParseTarGz(resp.Body, sha)
	if err != nil {
		return Current(), false, err
	}
	// Refuse a snapshot that lost most of what the current one has (a broken download or a restructured repository).
	cur := Current()
	if len(s.Commands)*10 < len(cur.Commands)*8 || len(s.Profiles)*10 < len(cur.Profiles)*8 || len(s.Declarations)*10 < len(cur.Declarations)*8 {
		return cur, false, fmt.Errorf("release %s has %d commands and %d profiles against %d and %d: not using it", sha[:8], len(s.Commands), len(s.Profiles), len(cur.Commands), len(cur.Profiles))
	}
	if r.DB != nil {
		b, _ := json.Marshal(s)
		if _, err := r.DB.Collection("schema_sets").ReplaceOne(ctx, bson.D{{Key: "_id", Value: "current"}}, bson.D{{Key: "json", Value: string(b)}, {Key: "ref", Value: s.Ref}, {Key: "fetched_at", Value: s.FetchedAt}}, options.Replace().SetUpsert(true)); err != nil {
			return cur, false, err
		}
	}
	Use(s)
	r.logf("apple device-management schemas updated to %s: %d commands, %d profile payloads", sha[:8], len(s.Commands), len(s.Profiles))
	return s, true, nil
}

// Run checks now and then every interval until ctx ends. Other processes pick up a saved set when they next check (they find it already current by ref only after they download it;
// Load at start-up and the periodic check keep them within one interval).
func (r *Refresher) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	for {
		if _, _, err := r.Check(ctx); err != nil && ctx.Err() == nil {
			r.logf("checking Apple device-management schemas: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
