// Package schemas holds Apple's device-management definitions (github.com/apple/device-management): every MDM command and every configuration profile payload, with the type of each key,
// its allowed values and which operating systems support it. The server uses them to validate commands, to leave out profile settings a platform does not understand, and to describe itself.
//
// A snapshot is built into the binary (schemas.json, made by tools/genschemas) and can be replaced at runtime by Refresher, so a new Apple release is supported the day it is published,
// without a new build.
package schemas

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// OSInfo is what a schema says about one operating system.
type OSInfo struct {
	Introduced  string `json:"introduced,omitempty"` // "n/a": does not exist there
	Deprecated  string `json:"deprecated,omitempty"`
	Removed     string `json:"removed,omitempty"`
	Supervised  bool   `json:"supervised,omitempty"`
	RequiresDEP bool   `json:"requires_dep,omitempty"`
	// UserEnrollment is "allowed", "forbidden" or "ignored" for a User Enrollment (BYOD).
	UserEnrollment string `json:"user_enrollment,omitempty"`
	DeviceChannel  *bool  `json:"device_channel,omitempty"`
	UserChannel    *bool  `json:"user_channel,omitempty"`
}

// Unsupported reports whether the OS entry says the thing does not exist there.
func (o OSInfo) Unsupported() bool { return o.Introduced == "n/a" }

// UnsupportedOn is Unsupported, and also true when the thing was removed at or before the given OS version (empty: not judged by version).
func (o OSInfo) UnsupportedOn(version string) bool {
	if o.Unsupported() {
		return true
	}
	if o.Removed == "" || o.Removed == "n/a" || version == "" {
		return false
	}
	have, ok1 := VersionNum(version)
	gone, ok2 := VersionNum(o.Removed)
	return ok1 && ok2 && have >= gone
}

// DeprecatedOn reports that the thing is deprecated at the given OS version (still works, but should be replaced).
func (o OSInfo) DeprecatedOn(version string) bool {
	if o.Deprecated == "" || o.Deprecated == "n/a" || version == "" {
		return false
	}
	have, ok1 := VersionNum(version)
	dep, ok2 := VersionNum(o.Deprecated)
	return ok1 && ok2 && have >= dep
}

// VersionNum turns "15.1.1" into 15001001 so versions compare as numbers (up to three parts, each below 1000).
func VersionNum(v string) (int64, bool) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) == 0 || len(parts) > 3 {
		return 0, false
	}
	var n int64
	mul := int64(1_000_000)
	for _, p := range parts {
		x, err := strconv.ParseInt(p, 10, 64)
		if err != nil || x < 0 || x > 999 {
			return 0, false
		}
		n += x * mul
		mul /= 1000
	}
	return n, true
}

// Key is one key of a command or profile payload.
type Key struct {
	Key       string            `json:"key"`
	Type      string            `json:"type"`
	Required  bool              `json:"required,omitempty"`
	Default   any               `json:"default,omitempty"`
	Allowed   []any             `json:"allowed,omitempty"`
	Min       *float64          `json:"min,omitempty"`
	Max       *float64          `json:"max,omitempty"`
	Format    string            `json:"format,omitempty"`
	Content   string            `json:"content,omitempty"`
	OS        map[string]OSInfo `json:"os,omitempty"`
	Keys      []Key             `json:"keys,omitempty"`
	Recursive bool              `json:"recursive,omitempty"`
}

// Command is one MDM command.
type Command struct {
	RequestType string            `json:"request_type"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Content     string            `json:"content,omitempty"`
	OS          map[string]OSInfo `json:"os,omitempty"`
	Keys        []Key             `json:"keys,omitempty"`
	Destructive bool              `json:"destructive,omitempty"`
}

// Profile is one configuration profile payload type.
type Profile struct {
	PayloadType string            `json:"payload_type"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	OS          map[string]OSInfo `json:"os,omitempty"`
	Keys        []Key             `json:"keys,omitempty"`
}

// Set is a complete snapshot of one Apple release.
type Set struct {
	Ref       string     `json:"ref"`
	FetchedAt time.Time  `json:"fetched_at"`
	Commands  []*Command `json:"commands"`
	Profiles  []*Profile `json:"profiles"`

	cmds  map[string]*Command
	profs map[string]*Profile
}

// Command returns the command with that RequestType.
func (s *Set) Command(requestType string) (*Command, bool) {
	c, ok := s.cmds[requestType]
	return c, ok
}

// Profile returns the payload definition for a PayloadType.
func (s *Set) Profile(payloadType string) (*Profile, bool) {
	p, ok := s.profs[payloadType]
	return p, ok
}

func (s *Set) index() {
	s.cmds = make(map[string]*Command, len(s.Commands))
	s.profs = make(map[string]*Profile, len(s.Profiles))
	for _, c := range s.Commands {
		c.Destructive = destructive[c.RequestType]
		s.cmds[c.RequestType] = c
	}
	for _, p := range s.Profiles {
		s.profs[p.PayloadType] = p
	}
	sort.Slice(s.Commands, func(i, j int) bool { return s.Commands[i].RequestType < s.Commands[j].RequestType })
	sort.Slice(s.Profiles, func(i, j int) bool { return s.Profiles[i].PayloadType < s.Profiles[j].PayloadType })
}

// Commands that lose data or lock someone out.
var destructive = map[string]bool{
	"EraseDevice": true, "DeviceLock": true, "ClearPasscode": true, "DeleteUser": true, "ClearRestrictionsPassword": true, "EnableLostMode": true,
	"RestartDevice": true, "ShutDownDevice": true, "SetFirmwarePassword": true, "SetRecoveryLock": true, "RemoveProfile": true, "RemoveApplication": true, "LogOutUser": true,
	"RotateFileVaultKey": true,
}

// SchemaOS maps a platform name to the operating-system entry Apple's schemas use for it (iPadOS shares iOS).
func SchemaOS(platform string) string {
	if platform == "iPadOS" {
		return "iOS"
	}
	return platform
}

//go:embed schemas.json
var embedded []byte

var current atomic.Pointer[Set]

// Embedded decodes the snapshot built into the binary.
func Embedded() *Set {
	s := &Set{}
	if err := json.Unmarshal(embedded, s); err != nil {
		panic("schemas: embedded snapshot: " + err.Error())
	}
	s.index()
	return s
}

// Current is the set in use: the built-in snapshot until a refresh replaces it.
func Current() *Set {
	if s := current.Load(); s != nil {
		return s
	}
	current.CompareAndSwap(nil, Embedded())
	return current.Load()
}

var listeners atomic.Pointer[[]func(*Set)]

// Use makes a set current and tells those who asked (OnChange).
func Use(s *Set) {
	s.index()
	current.Store(s)
	if l := listeners.Load(); l != nil {
		for _, f := range *l {
			f(s)
		}
	}
}

// OnChange registers a function called when the current set is replaced.
func OnChange(f func(*Set)) {
	for {
		old := listeners.Load()
		var next []func(*Set)
		if old != nil {
			next = append(next, *old...)
		}
		next = append(next, f)
		if listeners.CompareAndSwap(old, &next) {
			return
		}
	}
}
