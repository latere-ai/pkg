// Package scopes is the source of truth for every OAuth/RBAC scope
// the latere.ai auth service can issue.
//
// A service registers a scope here only when auth is the thing that issues it.
// A product that issues its own credentials owns its own vocabulary and does
// not appear in this registry: it mints its own tokens, decides what they may
// carry, and keeps that scope list beside the code that enforces it. Auth
// imports the union to populate /admin/scopes and the OIDC discovery
// document's scopes_supported field.
//
// Use the typed Scope values (e.g. scopes.AgentsRead) at call sites
// instead of bare string literals so a `gopls references` query
// finds every gate, and so renames are mechanical.
package scopes

import (
	"slices"
	"sort"
)

// Scope is a single OAuth/RBAC scope along with metadata used to
// surface it in admin UIs and OIDC discovery.
type Scope struct {
	// Name is the wire identifier sent on the OAuth `scope` parameter
	// and persisted on oauth_clients.allowed_scopes, e.g. "read:agents".
	Name string
	// Description is a one-line operator-facing summary shown in admin
	// dropdowns and consent screens.
	Description string
	// Category groups related scopes for display, e.g. "OIDC", "Agents".
	Category string
}

// All returns the union of every scope known across latere.ai
// services, sorted by (Category, Name) for stable rendering.
func All() []Scope {
	s := slices.Concat(oidc(), agents(), billing(), wallfacer())
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Category != s[j].Category {
			return s[i].Category < s[j].Category
		}
		return s[i].Name < s[j].Name
	})
	return s
}

// Names returns the wire identifiers of every known scope. Suitable
// for OIDC discovery's scopes_supported field.
func Names() []string {
	a := All()
	out := make([]string, len(a))
	for i, sc := range a {
		out[i] = sc.Name
	}
	return out
}
