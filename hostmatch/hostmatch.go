// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package hostmatch matches a destination host against an allowlist of exact
// FQDNs and "*."-prefixed wildcard patterns. It is the single host-match rule
// every egress enforcement path shares (credential substitution scoping,
// network egress policy), so operators reason about one rule everywhere:
// "*.example.com" matches any sub-label of example.com at any depth, but not
// example.com itself.
//
// Host normalization stays with the caller: each enforcement path applies its
// own rules (port stripping, lowercasing, trailing-dot removal) to patterns
// via the normalize hook in New, and to hosts before calling Matches.
package hostmatch

import (
	"regexp"
	"strings"
)

// patternRE constrains a host pattern to an exact FQDN or a "*."-prefixed
// wildcard. It is the single grammar every egress allow-list surface shares,
// so a change to what counts as a valid host pattern lands in one place.
var patternRE = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

// ValidPattern reports whether s is an exact FQDN or a "*."-wildcard pattern.
// Callers normalize (trim, lower-case, trailing-dot) before validating.
func ValidPattern(s string) bool {
	return patternRE.MatchString(s)
}

// Matcher matches normalized hosts against exact FQDNs and "*." wildcard
// suffixes. Construct it with New; the zero value matches nothing. It is
// read-only after construction and safe for concurrent use.
type Matcher struct {
	exact    map[string]struct{}
	suffixes []string // ".example.com"
}

// New compiles patterns into a Matcher, applying normalize to each pattern
// and dropping the empties it produces. Matches expects hosts normalized
// with the same rules.
func New(patterns []string, normalize func(string) string) Matcher {
	m := Matcher{exact: map[string]struct{}{}}
	for _, p := range patterns {
		p = normalize(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			m.suffixes = append(m.suffixes, p[1:])
		} else {
			m.exact[p] = struct{}{}
		}
	}
	return m
}

// Matches reports whether a normalized host is allowed: an exact entry, or a
// strict sub-label under a wildcard suffix. The empty host never matches.
func (m Matcher) Matches(host string) bool {
	if host == "" {
		return false
	}
	if _, ok := m.exact[host]; ok {
		return true
	}
	for _, s := range m.suffixes {
		if strings.HasSuffix(host, s) && len(host) > len(s) {
			return true
		}
	}
	return false
}
