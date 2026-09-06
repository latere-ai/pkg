// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"slices"
	"strings"
)

// HasScope returns true if the identity is permitted for the given scope.
// The admin parameter is the product-specific admin scope that implies all
// other scopes (e.g. "admin:sandbox" or "admin:topos"). IsSuperadmin and the
// admin scope both bypass fine-grained scope checks. The bearer-token dev
// identity is superadmin so local dev works uniformly.
//
// Each product can wrap this in a method on its own Identity alias:
//
//	func (i Identity) HasScope(scope string) bool {
//	    return authkit.HasScope(i, scope, "admin:myproduct")
//	}
func HasScope(id Identity, want, admin string) bool {
	if id.IsSuperadmin {
		return true
	}
	return slices.ContainsFunc(id.Scopes, func(s string) bool {
		return s == want || s == admin
	})
}

// SplitScopes splits a space or comma delimited scope string into a deduped,
// order-preserving slice. It is the one parser for the AUTH_SCOPES and
// AUTH_DEV_SCOPES environment formats and for the "scope" claim.
func SplitScopes(s string) []string {
	parts := strings.Fields(strings.ReplaceAll(s, ",", " "))
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
