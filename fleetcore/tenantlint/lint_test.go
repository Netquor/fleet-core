package tenantlint_test

import (
	"go/token"
	"strings"
	"testing"

	"github.com/micromdm/nanomdm/fleetcore/tenantlint"
)

var opts = tenantlint.Options{
	Scopes: []string{"scope", "pk", "key", "appKey", "scopeF"},
	Stamps: []string{"stamp", "stampDoc", "stampSet"},
}

// Every package that keeps tenant data in shared collections.
func TestTenantIsolationInSource(t *testing.T) {
	for _, dir := range []string{"../../storage/mongodb", "../blueprints", "../ddm", "../dep", "../pki", "../applicability", "../byod", "../vault", "../workflows"} {
		dir := dir
		t.Run(dir, func(t *testing.T) { tenantlint.Check(t, dir, opts) })
	}
}

// The check itself: it flags an unscoped query and an unstamped insert, and accepts scoped, stamped and marked ones.
func TestLintCatchesWhatItShould(t *testing.T) {
	problems, checked, err := tenantlint.Find(token.NewFileSet(), "testdata/bad", opts)
	if err != nil {
		t.Fatal(err)
	}
	if checked != 5 {
		t.Errorf("looked at %d calls, want 5", checked)
	}
	if len(problems) != 2 || !strings.Contains(problems[0]+problems[1], "Leaky") || !strings.Contains(problems[0]+problems[1], "Unstamped") {
		t.Errorf("problems: %v", problems)
	}
}
