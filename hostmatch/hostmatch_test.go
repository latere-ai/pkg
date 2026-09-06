// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostmatch

import (
	"strings"
	"testing"
)

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func TestMatcherExactAndWildcard(t *testing.T) {
	m := New([]string{"example.com", "*.api.dev", "", "  "}, lower)
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", false},    // exact entry does not cover sub-labels
		{"api.dev", false},            // wildcard excludes the apex
		{"a.api.dev", true},           // one sub-label
		{"deep.nested.api.dev", true}, // any depth
		{"evil-api.dev", false},       // suffix must align on a label boundary
		{"", false},
		{"other.com", false},
	}
	for _, c := range cases {
		if got := m.Matches(c.host); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestMatcherAppliesNormalizeToPatterns(t *testing.T) {
	m := New([]string{"  API.Example.COM  "}, lower)
	if !m.Matches("api.example.com") {
		t.Fatal("normalized pattern must match normalized host")
	}
	if m.Matches("API.Example.COM") {
		t.Fatal("Matches takes a pre-normalized host; raw input must not match")
	}
}

func TestZeroMatcherMatchesNothing(t *testing.T) {
	var m Matcher
	if m.Matches("example.com") {
		t.Fatal("zero Matcher must match nothing")
	}
}

func TestValidPattern(t *testing.T) {
	cases := map[string]bool{
		"example.com":       true,
		"api.github.com":    true,
		"*.example.com":     true,
		"a.b.c.example.com": true,
		"example":           false, // single label
		"*.com":             false, // wildcard needs at least two labels
		"*example.com":      false, // wildcard must be "*."
		"exa mple.com":      false,
		"":                  false,
		"-bad.example.com":  false,
	}
	for in, want := range cases {
		if got := ValidPattern(in); got != want {
			t.Errorf("ValidPattern(%q) = %v want %v", in, got, want)
		}
	}
}

// A wildcard never matches its own apex, and an exact pattern never matches a
// sub-label, whatever the input.
func FuzzMatches(f *testing.F) {
	f.Add("*.example.com", "a.example.com")
	f.Add("example.com", "example.com")
	f.Add("*.example.com", "example.com")
	f.Fuzz(func(t *testing.T, pattern, host string) {
		m := New([]string{pattern}, lower)
		got := m.Matches(host)
		p := lower(pattern)
		switch {
		case host == "":
			if got {
				t.Fatal("empty host matched")
			}
		case strings.HasPrefix(p, "*."):
			want := strings.HasSuffix(host, p[1:]) && len(host) > len(p)-1
			if got != want {
				t.Fatalf("wildcard %q vs %q: got %v want %v", p, host, got, want)
			}
		default:
			if got != (host == p && p != "") {
				t.Fatalf("exact %q vs %q: got %v", p, host, got)
			}
		}
	})
}

// ValidPattern accepts only what the grammar allows: never a leading dot,
// never a bare wildcard, never whitespace.
func FuzzValidPattern(f *testing.F) {
	f.Add("*.example.com")
	f.Add("exa mple.com")
	f.Fuzz(func(t *testing.T, s string) {
		ok := ValidPattern(s)
		if !ok {
			return
		}
		if strings.ContainsAny(s, " \t\n") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
			t.Fatalf("ValidPattern(%q) accepted a malformed pattern", s)
		}
		if strings.HasPrefix(s, "*") && !strings.HasPrefix(s, "*.") {
			t.Fatalf("ValidPattern(%q) accepted a bare wildcard", s)
		}
		if strings.Count(s, ".") < 1 {
			t.Fatalf("ValidPattern(%q) accepted a single label", s)
		}
	})
}
