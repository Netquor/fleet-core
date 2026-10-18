// Package blueprints is desired-state management for devices: named blueprints (profiles and commands, a scope, a rollout) that the server keeps true for every device in scope.
//
// The design is a reconciler, the same shape as Kubernetes controllers and modern MDMs: what should be on a device is computed from blueprints and the device's attributes,
// compared with what was sent and confirmed, and only the difference is queued. Everything is idempotent, so it is safe to run again after any event, crash or missed check-in,
// and any number of server processes can share the work through leases in MongoDB.
package blueprints

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Device is the inventory record the engine decides with. It is created and kept current by check-ins.
type Device struct {
	ID         string    `bson:"id" json:"id"` // the enrollment ID
	UDID       string    `bson:"udid,omitempty" json:"udid,omitempty"`
	Serial     string    `bson:"serial,omitempty" json:"serial,omitempty"`
	Name       string    `bson:"name,omitempty" json:"name,omitempty"`
	Platform   string    `bson:"platform,omitempty" json:"platform,omitempty"` // macOS, iOS, iPadOS, tvOS, visionOS, watchOS
	Model      string    `bson:"model,omitempty" json:"model,omitempty"`
	OSVersion  string    `bson:"os_version,omitempty" json:"os_version,omitempty"`
	OSNum      int64     `bson:"os_num,omitempty" json:"-"` // major*1e6 + minor*1e3 + patch, for comparisons
	DEPName    string    `bson:"dep_name,omitempty" json:"dep_name,omitempty"`
	EnrollType string    `bson:"enroll_type,omitempty" json:"enroll_type,omitempty"`
	Tags       []string  `bson:"tags,omitempty" json:"tags,omitempty"`
	Groups     []string  `bson:"groups,omitempty" json:"groups,omitempty"` // static group membership
	EnrolledAt time.Time `bson:"enrolled_at,omitempty" json:"enrolled_at,omitempty"`
	LastSeen   time.Time `bson:"last_seen,omitempty" json:"last_seen,omitempty"`
	Active     bool      `bson:"active" json:"active"`
	// OSQueryAt is when the engine last asked the device for its OS version (DeviceInformation); OSCheckedAt when it last answered.
	OSQueryAt   time.Time `bson:"os_query_at,omitempty" json:"-"`
	OSCheckedAt time.Time `bson:"os_checked_at,omitempty" json:"os_checked_at,omitempty"`

	ReconcileAt time.Time `bson:"reconcile_at,omitempty" json:"-"`
	LeaseUntil  time.Time `bson:"lease_until,omitempty" json:"-"`
}

// Group is a named set of devices: static (devices are put in it) or dynamic (a rule).
type Group struct {
	ID          string `bson:"id" json:"id"`
	Name        string `bson:"name" json:"name"`
	Description string `bson:"description,omitempty" json:"description,omitempty"`
	// Rule makes the group dynamic: members are the devices it matches, evaluated when needed. Nil: static.
	Rule *Rule `bson:"rule,omitempty" json:"rule,omitempty"`
}

// Item is one thing a blueprint puts on a device.
type Item struct {
	ID   string `bson:"id" json:"id"`
	Kind string `bson:"kind" json:"kind"` // "profile" or "command"
	Name string `bson:"name,omitempty" json:"name,omitempty"`

	// Profile: the configuration profile (a .mobileconfig, base64 in JSON). Identifier is its PayloadIdentifier, found from the profile if left empty.
	Identifier string `bson:"identifier,omitempty" json:"identifier,omitempty"`
	Payload    []byte `bson:"payload,omitempty" json:"payload,omitempty"`

	// Command: any MDM command from the catalog. Once: run it once per change of the item, not on every drift check.
	RequestType string         `bson:"request_type,omitempty" json:"request_type,omitempty"`
	Params      map[string]any `bson:"params,omitempty" json:"params,omitempty"`
}

// Hash identifies the item's content: when it changes, devices get the new version.
func (i Item) Hash() string {
	h := sha256.New()
	h.Write([]byte(i.Kind + "\x00" + i.Identifier + "\x00" + i.RequestType + "\x00"))
	h.Write(i.Payload)
	if i.Params != nil {
		b, _ := json.Marshal(i.Params) // encoding/json sorts map keys
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// Ring is a stage of a staged rollout: devices up to Percent (cumulative, of a stable per-device bucket) get the change After this long after the rollout started.
type Ring struct {
	Name         string `bson:"name,omitempty" json:"name,omitempty"`
	Percent      int    `bson:"percent" json:"percent"`
	AfterSeconds int64  `bson:"after_seconds" json:"after_seconds"`
}

// Blueprint is a desired state for the devices its scope matches.
type Blueprint struct {
	ID          string `bson:"id" json:"id"`
	Name        string `bson:"name" json:"name"`
	Description string `bson:"description,omitempty" json:"description,omitempty"`
	Enabled     bool   `bson:"enabled" json:"enabled"`
	// Priority orders blueprints; when two put the same profile on a device the higher priority wins.
	Priority int    `bson:"priority" json:"priority"`
	Scope    Rule   `bson:"scope" json:"scope"`
	Items    []Item `bson:"items" json:"items"`
	// Rings stage a change over time. None: every device in scope at once.
	Rings []Ring `bson:"rings,omitempty" json:"rings,omitempty"`
	// KeepOnLeave leaves profiles installed when a device leaves the scope or the blueprint is deleted (the default removes them).
	KeepOnLeave bool `bson:"keep_on_leave,omitempty" json:"keep_on_leave,omitempty"`

	Revision  int       `bson:"revision" json:"revision"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
	UpdatedBy string    `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
	// RolloutAt is when the items last changed: rings count from here.
	RolloutAt time.Time `bson:"rollout_at" json:"rollout_at"`
}

// Application is the record of one item on one device.
type Application struct {
	Device      string    `bson:"device" json:"device"`
	Blueprint   string    `bson:"blueprint" json:"blueprint"`
	Item        string    `bson:"item" json:"item"`
	Kind        string    `bson:"kind" json:"kind"`
	Identifier  string    `bson:"identifier,omitempty" json:"identifier,omitempty"`
	Hash        string    `bson:"hash" json:"hash"`
	State       string    `bson:"state" json:"state"`                         // pending, applied, failed, removing, not_applicable
	Context     string    `bson:"context,omitempty" json:"context,omitempty"` // platform and OS version the decision was made for
	Note        string    `bson:"note,omitempty" json:"note,omitempty"`       // what was left out for the platform, or why it does not apply
	OrphanKeep  bool      `bson:"orphan_keep,omitempty" json:"-"`             // the blueprint was deleted with keep_on_leave
	CommandUUID string    `bson:"command_uuid,omitempty" json:"command_uuid,omitempty"`
	Attempts    int       `bson:"attempts" json:"attempts"`
	Error       string    `bson:"error,omitempty" json:"error,omitempty"`
	UpdatedAt   time.Time `bson:"updated_at" json:"updated_at"`
}

const (
	StatePending  = "pending"
	StateApplied  = "applied"
	StateFailed   = "failed"
	StateRemoving = "removing"
	StateNA       = "not_applicable"
)
