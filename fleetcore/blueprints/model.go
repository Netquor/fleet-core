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
	"fmt"
	"github.com/micromdm/nanomdm/fleetcore/applicability"
	"strings"
	"time"
)

// Device is the inventory record the engine decides with. It is created and kept current by check-ins.
type Device struct {
	ID     string `bson:"id" json:"id"` // the enrollment ID
	UDID   string `bson:"udid,omitempty" json:"udid,omitempty"`
	Serial string `bson:"serial,omitempty" json:"serial,omitempty"`
	Name   string `bson:"name,omitempty" json:"name,omitempty"`
	// ManagedAppleID is the person a User Enrollment (BYOD) device belongs to.
	ManagedAppleID string `bson:"managed_apple_id,omitempty" json:"managed_apple_id,omitempty"`
	Platform       string `bson:"platform,omitempty" json:"platform,omitempty"` // macOS, iOS, iPadOS, tvOS, visionOS, watchOS
	Model          string `bson:"model,omitempty" json:"model,omitempty"`
	OSVersion      string `bson:"os_version,omitempty" json:"os_version,omitempty"`
	OSNum          int64  `bson:"os_num,omitempty" json:"-"` // major*1e6 + minor*1e3 + patch, for comparisons
	DEPName        string `bson:"dep_name,omitempty" json:"dep_name,omitempty"`
	EnrollType     string `bson:"enroll_type,omitempty" json:"enroll_type,omitempty"`
	// Awaiting is set while the device sits in Setup Assistant waiting for the server to release it (ADE with await configuration); AwaitingSince says since when.
	Awaiting      bool      `bson:"awaiting,omitempty" json:"awaiting,omitempty"`
	AwaitingSince time.Time `bson:"awaiting_since,omitempty" json:"awaiting_since,omitempty"`
	Tags          []string  `bson:"tags,omitempty" json:"tags,omitempty"`
	Groups        []string  `bson:"groups,omitempty" json:"groups,omitempty"` // static group membership
	EnrolledAt    time.Time `bson:"enrolled_at,omitempty" json:"enrolled_at,omitempty"`
	LastSeen      time.Time `bson:"last_seen,omitempty" json:"last_seen,omitempty"`
	Active        bool      `bson:"active" json:"active"`
	// LostMode and Location are kept by the Lost Mode workflow.
	LostMode *LostMode `bson:"lost_mode,omitempty" json:"lost_mode,omitempty"`
	Location *Location `bson:"location,omitempty" json:"location,omitempty"`
	// Users are the device's user-channel enrollment IDs (macOS users, Shared iPad), for user-scoped declarations.
	Users []string `bson:"users,omitempty" json:"users,omitempty"`
	// Supervised is learned from the device (IsSupervised); nil until known. Many declarations need a supervised device.
	Supervised *bool `bson:"supervised,omitempty" json:"supervised,omitempty"`
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
	// Setup marks an item a device in Setup Assistant (ADE with await configuration) must have before it is released to the person: the server sends DeviceConfigured when every Setup
	// item has been applied, found not applicable, or has failed for good, or after the wait runs out.
	Setup bool `bson:"setup,omitempty" json:"setup,omitempty"`
	// Delivery of a profile: "auto" (the default) sends it as a legacy-profile declaration when the device takes declarative management, and as an MDM profile otherwise;
	// "declarative" insists on declarative management (a device that cannot is told so); "profile" always uses the MDM InstallProfile command.
	Delivery string `bson:"delivery,omitempty" json:"delivery,omitempty"`

	// Command: any MDM command from the catalog. Sent once per change of the item, not on every drift check.
	RequestType string         `bson:"request_type,omitempty" json:"request_type,omitempty"`
	Params      map[string]any `bson:"params,omitempty" json:"params,omitempty"`

	// Declaration: a declarative management configuration (kind "declaration"), for example com.apple.configuration.passcode.settings. It is activated automatically unless NoActivation.
	DeclarationType string         `bson:"declaration_type,omitempty" json:"declaration_type,omitempty"`
	Declaration     map[string]any `bson:"declaration,omitempty" json:"declaration,omitempty"`
	NoActivation    bool           `bson:"no_activation,omitempty" json:"no_activation,omitempty"`

	// Software update (kind "os_update"): move devices to a release by a deadline, with declarative management.
	// Target is "latest" (the newest release the device's hardware supports), "latest-in-major" (the newest of its own major version), or a version such as "27.0.1".
	// The deadline is DeadlineDays (default 7) after the release was published, or after this item last changed if that is later, at DeadlineHour local time (default 17).
	Target       string `bson:"target,omitempty" json:"target,omitempty"`
	DeadlineDays int    `bson:"deadline_days,omitempty" json:"deadline_days,omitempty"`
	DeadlineHour *int   `bson:"deadline_hour,omitempty" json:"deadline_hour,omitempty"`
	DetailsURL   string `bson:"details_url,omitempty" json:"details_url,omitempty"`

	// Asset (kind "asset"): data a configuration refers to. DeclarationType is the asset type (com.apple.asset.credential.userpassword...). With AssetData the server hosts the data
	// and writes the asset's Reference (URL, size, hash) itself; Declaration then holds only the other keys (Authentication, Accessible). Without it, Declaration is the whole payload.
	// A configuration refers to an asset by writing "$asset:<item id>" where the asset's identifier belongs.
	AssetData   []byte `bson:"asset_data,omitempty" json:"asset_data,omitempty"`
	ContentType string `bson:"content_type,omitempty" json:"content_type,omitempty"`

	// Predicate limits a declaration's activation to devices where it is true on the device (Apple's predicate format, for example
	// @status(device.model.family) == 'iPhone'). The server's own scope (the blueprint's rule) is decided before; this is for what only the device knows.
	Predicate string `bson:"predicate,omitempty" json:"predicate,omitempty"`
	// Scope is "system" (the default) or "user": a user-scoped declaration goes to each user channel of the device (macOS users, Shared iPad), not to the device.
	Scope string `bson:"scope,omitempty" json:"scope,omitempty"`
	// InstallAction is used only for a device that cannot take declarative enforcement but still understands the MDM ScheduleOSUpdate command (below iOS 17, macOS 14, or
	// before the command is removed in 27): Default (download and ask the user), DownloadOnly, InstallASAP, NotifyOnly, InstallLater or InstallForceRestart. Default is "Default".
	InstallAction string `bson:"install_action,omitempty" json:"install_action,omitempty"`
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
	h.Write([]byte(i.Delivery))
	if i.Setup {
		h.Write([]byte("setup"))
	}
	h.Write(i.AssetData)
	h.Write([]byte(i.ContentType + "\x00" + i.Predicate + "\x00" + i.Scope))
	if i.Kind == "declaration" || i.Kind == "os_update" || i.Kind == "asset" {
		b, _ := json.Marshal(i.Declaration)
		h.Write([]byte(i.DeclarationType + "\x00" + string(b) + "\x00" + i.Target + "\x00" + i.DetailsURL + fmt.Sprint(i.NoActivation, i.DeadlineDays)))
		if i.DeadlineHour != nil {
			h.Write([]byte(fmt.Sprint(*i.DeadlineHour)))
		}
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
	// StatusItems are extra status items devices in scope are asked to report over the declarative status channel (names from Apple's schema, for example passcode.is-compliant).
	StatusItems []string `bson:"status_items,omitempty" json:"status_items,omitempty"`
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
	Device     string `bson:"device" json:"device"`
	Blueprint  string `bson:"blueprint" json:"blueprint"`
	Item       string `bson:"item" json:"item"`
	Kind       string `bson:"kind" json:"kind"`
	Identifier string `bson:"identifier,omitempty" json:"identifier,omitempty"`
	Hash       string `bson:"hash" json:"hash"`
	// Delivery is how it got to the device: "profile" (an MDM command) or "declarative".
	Delivery string `bson:"delivery,omitempty" json:"delivery,omitempty"`
	// ServerToken is the token of the declaration the device must report as active (declarative items).
	ServerToken string    `bson:"server_token,omitempty" json:"server_token,omitempty"`
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

// EnrollKind is how Apple's schemas name the device's enrollment for allowed-enrollments: user, supervised or device.
func (d *Device) EnrollKind() string {
	switch {
	case strings.Contains(d.EnrollType, "User Enrollment"):
		return "user"
	case d.Supervised != nil && *d.Supervised:
		return "supervised"
	}
	return "device"
}

// UserEnrollment reports whether the device is enrolled with User Enrollment (BYOD): the organization manages only its own data, and Apple forbids many commands and settings there.
func (d *Device) UserEnrollment() bool { return strings.Contains(d.EnrollType, "User Enrollment") }

func (d *Device) profileOptions() []applicability.Option {
	if d.UserEnrollment() {
		return []applicability.Option{applicability.ForUserEnrollment()}
	}
	return nil
}

// LostMode is the state of Lost Mode on a device.
type LostMode struct {
	Enabled   bool      `bson:"enabled" json:"enabled"`
	Message   string    `bson:"message,omitempty" json:"message,omitempty"`
	Phone     string    `bson:"phone,omitempty" json:"phone,omitempty"`
	Footnote  string    `bson:"footnote,omitempty" json:"footnote,omitempty"`
	Confirmed bool      `bson:"confirmed" json:"confirmed"` // the device acknowledged the command
	Since     time.Time `bson:"since" json:"since"`
}

// Location is where a device last said it was.
type Location struct {
	Latitude           float64   `bson:"latitude" json:"latitude"`
	Longitude          float64   `bson:"longitude" json:"longitude"`
	Altitude           float64   `bson:"altitude,omitempty" json:"altitude,omitempty"`
	HorizontalAccuracy float64   `bson:"horizontal_accuracy,omitempty" json:"horizontal_accuracy,omitempty"`
	At                 time.Time `bson:"at" json:"at"`
}
