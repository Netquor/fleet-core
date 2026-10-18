// Package commands is the JSON command API: Apple's MDM commands as a catalog (generated from github.com/apple/device-management by tools/gencommands), a validator that checks a JSON
// request against a command's schema, and a builder that turns the request into the plist a device receives.
package commands

import (
	_ "embed"
	"encoding/json"
	"sort"
	"sync"
)

//go:embed commands.json
var catalogJSON []byte

// OSInfo is what a schema says about one operating system: the release that introduced a command or key ("n/a" when it does not exist there).
type OSInfo struct {
	Introduced  string `json:"introduced,omitempty"`
	Deprecated  string `json:"deprecated,omitempty"`
	Removed     string `json:"removed,omitempty"`
	Supervised  bool   `json:"supervised,omitempty"`
	RequiresDEP bool   `json:"requires_dep,omitempty"`
}

// Key is one key of a command: its type and constraints.
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

// Command is the schema of one MDM command.
type Command struct {
	RequestType string            `json:"request_type"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Content     string            `json:"content,omitempty"`
	OS          map[string]OSInfo `json:"os,omitempty"`
	Keys        []Key             `json:"keys,omitempty"`
	// Destructive commands lose data or lock someone out; the API wants an explicit confirmation.
	Destructive bool `json:"destructive,omitempty"`
}

// Catalog is every command of one Apple release.
type Catalog struct {
	Ref      string     `json:"ref"`
	Commands []*Command `json:"commands"`
	byType   map[string]*Command
}

var destructive = map[string]bool{
	"EraseDevice": true, "DeviceLock": true, "ClearPasscode": true, "DeleteUser": true, "ClearRestrictionsPassword": true, "EnableLostMode": true,
	"RestartDevice": true, "ShutDownDevice": true, "SetFirmwarePassword": true, "SetRecoveryLock": true, "RemoveProfile": true, "RemoveApplication": true, "LogOutUser": true,
	"RotateFileVaultKey": true,
}

var (
	once    sync.Once
	catalog *Catalog
)

// Default is the catalog built into the binary.
func Default() *Catalog {
	once.Do(func() {
		c := &Catalog{}
		if err := json.Unmarshal(catalogJSON, c); err != nil {
			panic("commands: embedded catalog: " + err.Error())
		}
		c.byType = make(map[string]*Command, len(c.Commands))
		for _, cmd := range c.Commands {
			cmd.Destructive = destructive[cmd.RequestType]
			c.byType[cmd.RequestType] = cmd
		}
		sort.Slice(c.Commands, func(i, j int) bool { return c.Commands[i].RequestType < c.Commands[j].RequestType })
		catalog = c
	})
	return catalog
}

// Get returns the command with that RequestType.
func (c *Catalog) Get(requestType string) (*Command, bool) {
	cmd, ok := c.byType[requestType]
	return cmd, ok
}
