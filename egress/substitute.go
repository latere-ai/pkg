// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package egress implements credential substitution at an egress boundary: a
// workload holds an opaque placeholder in place of a real secret, and the
// egress path swaps the placeholder for the secret on the way out, but only
// when the request is bound for a host the credential is scoped to.
//
// The package is layered so a front door can be built on the core without
// the CONNECT proxy:
//
//   - [Map], [NewMap], [Map.SubstituteValue], [Map.HostHasSecret] and
//     [SubstituteHTTPRequest] are the pure substitution engine. They have no
//     network, TLS, or platform dependency, which keeps the security-critical
//     core exhaustively unit-testable.
//   - [Registry] holds one [Map] per principal, and [IngestHandler] is the
//     control-plane API that fills it; [Client] is the matching caller.
//   - [MintPlaceholder] and [IsPlaceholder] define the placeholder shape.
//   - [TokenAuth] verifies a principal's JWT presented as proxy credentials.
//   - [Gateway] and [CA] are the TLS-terminating CONNECT proxy on top.
//
// The security property is destination scoping: a placeholder is replaced
// with its secret if and only if the destination host matches that entry's
// allowed hosts. A placeholder sent anywhere else passes through verbatim,
// which is what protects against an exfiltration attempt: a request to an
// unrelated host carrying the placeholder leaks only the opaque token.
package egress

import (
	"strings"

	"latere.ai/x/pkg/hostmatch"
)

// PlaceholderPrefix is the prefix every placeholder token carries, so the
// engine can pre-filter a request with a single substring check before doing
// any per-entry work.
const PlaceholderPrefix = "cph_"

// Entry is one credential's substitution rule: replace Placeholder with Secret,
// but only toward a host in AllowedHosts.
type Entry struct {
	Placeholder  []byte
	Secret       []byte
	AllowedHosts []string // exact FQDNs and "*."-prefixed wildcard patterns
}

// Map is one principal's substitution table. Construct it with [NewMap]; the
// zero value is an empty (no-op) map. It is read-only after construction and
// safe for concurrent use.
type Map struct {
	entries []compiledEntry
}

type compiledEntry struct {
	placeholder string
	secret      string
	hosts       hostmatch.Matcher
}

// NewMap compiles entries into a substitution table. Entries with an empty
// placeholder or no allowed hosts are dropped: a placeholder that can never be
// scoped to a destination would be a footgun, and the store that owns the
// credentials should already reject such entries at write time. This is
// defence in depth.
func NewMap(entries []Entry) *Map {
	m := &Map{}
	for _, e := range entries {
		ph := string(e.Placeholder)
		if ph == "" || len(e.AllowedHosts) == 0 {
			continue
		}
		m.entries = append(m.entries, compiledEntry{
			placeholder: ph,
			secret:      string(e.Secret),
			hosts:       hostmatch.New(e.AllowedHosts, normalizeHost),
		})
	}
	return m
}

// Empty reports whether the map has no usable entries.
func (m *Map) Empty() bool { return m == nil || len(m.entries) == 0 }

// HostHasSecret reports whether any entry may be substituted toward host. The
// gateway calls this on the CONNECT target before terminating TLS: hosts with
// a bound secret are inspected, every other host is a passthrough tunnel the
// gateway cannot read. TLS interception is therefore scoped to exactly the
// destinations a credential is bound to.
func (m *Map) HostHasSecret(host string) bool {
	if m.Empty() {
		return false
	}
	host = normalizeHost(host)
	for _, e := range m.entries {
		if e.hosts.Matches(host) {
			return true
		}
	}
	return false
}

// SubstituteValue rewrites a single string, replacing each placeholder with its
// secret when host matches that entry's allowed hosts. It is the primitive the
// HTTP adapters use to rewrite a header value or a query string independently.
// Returns the rewritten value and whether it changed.
func (m *Map) SubstituteValue(host, s string) (string, bool) {
	if m.Empty() || !strings.Contains(s, PlaceholderPrefix) {
		return s, false
	}
	host = normalizeHost(host)
	changed := false
	for _, e := range m.entries {
		if !e.hosts.Matches(host) {
			continue
		}
		if v, ok := replaceToken(s, e.placeholder, e.secret); ok {
			s = v
			changed = true
		}
	}
	return s, changed
}

// replaceToken replaces every whole-token occurrence of ph in s with secret. An
// occurrence counts only when it is not flanked by a token character on either
// side, so a placeholder is never matched as a substring of a longer token
// (e.g. ph "cph_ABC" does not match inside "cph_ABCDEF"). This keeps adjacent or
// overlapping placeholders from corrupting one another.
func replaceToken(s, ph, secret string) (string, bool) {
	if ph == "" || !strings.Contains(s, ph) {
		return s, false
	}
	var b strings.Builder
	changed := false
	i := 0
	for {
		j := strings.Index(s[i:], ph)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		start := i + j
		end := start + len(ph)
		leftOK := start == 0 || !isTokenChar(s[start-1])
		rightOK := end == len(s) || !isTokenChar(s[end])
		if leftOK && rightOK {
			b.WriteString(s[i:start])
			b.WriteString(secret)
			changed = true
			i = end
		} else {
			// Not a whole-token match; keep scanning past this position.
			b.WriteString(s[i : start+1])
			i = start + 1
		}
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func isTokenChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_':
		return true
	default:
		return false
	}
}

// normalizeHost prepares a destination host (or allowlist pattern) for the
// shared hostmatch rule: lowercase, trim whitespace and the trailing dot,
// and strip a port when the value is an unambiguous host:port form.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	// Strip a port if present (host:port).
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// Only strip when the tail is a plausible port and there's no bracket
		// (IPv6 literals aren't a substitution target, so treat conservatively).
		if !strings.Contains(host, "]") && strings.IndexByte(host[i+1:], ':') < 0 {
			host = host[:i]
		}
	}
	return host
}
