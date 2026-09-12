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

func TestSingleLabelOptIn(t *testing.T) {
	for _, name := range []string{"localhost", "postgres", "a", "service-1", strings.Repeat("a", 63)} {
		if ValidPattern(name) {
			t.Fatalf("default grammar widened for %q", name)
		}
		if !ValidPattern(name, WithSingleLabel()) {
			t.Fatalf("single label %q rejected", name)
		}
		matcher := New([]string{name}, lower)
		if !matcher.Matches(name) || matcher.Matches("sub."+name) {
			t.Fatal("single label is not exact")
		}
	}
	for _, name := range []string{"", "*", "*.localhost", "-bad", "bad-", "a_b", "a b", "localhost:80", ".a", "a.", strings.Repeat("a", 64)} {
		if ValidPattern(name, WithSingleLabel()) {
			t.Fatalf("malformed or wildcard label %q accepted", name)
		}
	}
	for _, name := range []string{"example.com", "*.example.com", "127.0.0.1"} {
		if !ValidPattern(name, WithSingleLabel()) {
			t.Fatalf("existing pattern %q rejected", name)
		}
	}
}

func FuzzSingleLabel(f *testing.F) {
	f.Add("localhost")
	f.Add("*.localhost")
	f.Fuzz(func(t *testing.T, s string) {
		if !ValidPattern(s, WithSingleLabel()) || ValidPattern(s) {
			return
		}
		if len(s) == 0 || len(s) > 63 || strings.ContainsAny(s, ".* :/_\t\r\n") || s[0] == '-' || s[len(s)-1] == '-' {
			t.Fatalf("invalid single label %q", s)
		}
		for _, r := range s {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				t.Fatalf("invalid character in %q", s)
			}
		}
	})
}
