// Package commands is the JSON command API: Apple's MDM commands as a catalog (from fleetcore/schemas, which follows Apple's releases), a validator that checks a JSON request against a
// command's schema, and a builder that turns the request into the plist a device receives.
package commands

import "github.com/micromdm/nanomdm/fleetcore/schemas"

// These are the schema types; they are aliases so a refreshed schema set needs no conversion.
type (
	OSInfo  = schemas.OSInfo
	Key     = schemas.Key
	Command = schemas.Command
)

// Catalog is every command of the schema set in use. It always reads the current set, so a refresh of Apple's definitions is seen at once.
type Catalog struct{}

// Default is the catalog of the current schema set.
func Default() *Catalog { return &Catalog{} }

// Get returns the command with that RequestType.
func (c *Catalog) Get(requestType string) (*Command, bool) {
	return schemas.Current().Command(requestType)
}

// All returns every command, sorted by RequestType.
func (c *Catalog) All() []*Command { return schemas.Current().Commands }

// Ref is the Apple release the catalog comes from.
func (c *Catalog) Ref() string { return schemas.Current().Ref }
