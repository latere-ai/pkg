// Package scopes is the source of truth for every OAuth/RBAC scope
// the latere.ai auth service can issue.
//
// Each downstream service (sandbox, fs, latere-ai, latere-cli,
// wallfacer) registers the scopes it gates on in its own file in this
// package; auth imports the union to populate /admin/scopes and the
// OIDC discovery document's scopes_supported field. Adding a new
// scope is a single-file change here plus an import where the scope
// is enforced.
//
// Use the typed Scope values (e.g. scopes.SandboxRead) at call sites
// instead of bare string literals so a `gopls references` query
// finds every gate, and so renames are mechanical.
package scopes

import "sort"

// Scope is a single OAuth/RBAC scope along with metadata used to
// surface it in admin UIs and OIDC discovery.
type Scope struct {
	// Name is the wire identifier sent on the OAuth `scope` parameter
	// and persisted on oauth_clients.allowed_scopes, e.g. "read:sandbox".
	Name string
	// Description is a one-line operator-facing summary shown in admin
	// dropdowns and consent screens.
	Description string
	// Category groups related scopes for display, e.g. "OIDC", "Sandbox".
	Category string
}

// All returns the union of every scope known across latere.ai
// services, sorted by (Category, Name) for stable rendering.
func All() []Scope {
	s := []Scope{}
	s = append(s, oidc()...)
	s = append(s, sandbox()...)
	s = append(s, policy()...)
	s = append(s, billing()...)
	s = append(s, wallfacer()...)
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
