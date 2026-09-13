// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import "strings"

// SplitScopes splits a space or comma delimited scope string into a deduped,
// order-preserving slice. It is the one parser for the AUTH_SCOPES
// environment format, the scopes a relying party requests from the issuer.
// No decision is made from a scope: a token's "scp" is the client's
// ceiling, and access is by role (Identity.Has).
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
