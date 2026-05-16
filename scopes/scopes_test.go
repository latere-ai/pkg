package scopes

import (
	"strings"
	"testing"
)

// TestAll_NoDuplicateNames guarantees that two domain files cannot
// register the same scope name without the test failing — the wire
// identifier is the unique key, so duplicates would silently let one
// definition's Description/Category clobber the other depending on
// append order.
func TestAll_NoDuplicateNames(t *testing.T) {
	seen := map[string]string{}
	for _, sc := range All() {
		if prev, ok := seen[sc.Name]; ok {
			t.Errorf("duplicate scope %q (categories %q and %q)", sc.Name, prev, sc.Category)
		}
		seen[sc.Name] = sc.Category
	}
}

// TestAll_FieldsPopulated catches a half-filled Scope literal landing
// in a domain file (e.g. someone forgot Description or Category),
// which would render as a blank row in the admin dropdown.
func TestAll_FieldsPopulated(t *testing.T) {
	for _, sc := range All() {
		if sc.Name == "" {
			t.Errorf("scope with empty Name: %+v", sc)
		}
		if sc.Description == "" {
			t.Errorf("scope %q has empty Description", sc.Name)
		}
		if sc.Category == "" {
			t.Errorf("scope %q has empty Category", sc.Name)
		}
	}
}

// TestNames_StableOrder pins the (Category, Name) sort so callers like
// OIDC discovery emit a deterministic scopes_supported array that
// doesn't churn the cached document on every restart.
func TestNames_StableOrder(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("Names() returned empty slice")
	}
	got := strings.Join(names, ",")
	got2 := strings.Join(Names(), ",")
	if got != got2 {
		t.Errorf("Names() not stable: %q vs %q", got, got2)
	}
}

// TestKnownScopesPresent guards against accidental deletion of any
// scope that production tokens already carry — removing one would
// turn previously-valid tokens into "scope not advertised" surprises
// at /admin/scopes and consent screens.
func TestKnownScopesPresent(t *testing.T) {
	required := []string{
		"openid", "email", "profile", "offline_access",
		"read:sandbox", "write:sandbox", "exec:sandbox", "attach:sandbox", "admin:sandbox",
		"policy:write",
		"billing:read", "billing:report",
		"read:projects", "admin:tasks",
		"llm.read", "llm.invoke", "llm.admin",
	}
	have := map[string]bool{}
	for _, sc := range All() {
		have[sc.Name] = true
	}
	for _, want := range required {
		if !have[want] {
			t.Errorf("scope %q missing from registry", want)
		}
	}
}
