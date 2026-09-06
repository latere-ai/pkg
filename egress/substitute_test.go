// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"latere.ai/x/pkg/hostmatch"
)

func ph(s string) []byte { return []byte(s) }

// mkMap is a terse constructor for tests.
func mkMap(entries ...Entry) *Map { return NewMap(entries) }

// reqWith builds an outbound request with the given path+query and headers.
func reqWith(t *testing.T, target string, headers map[string]string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", "https://upstream.test"+target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// SubstituteHTTPRequest scopes substitution by the host argument, not req.URL.Host:
// the request URL points at upstream.test while the allow-listed host is passed
// separately, and substitution still fires.
func TestSubstitute_ScopesByHostArgNotURL(t *testing.T) {
	m := mkMap(Entry{
		Placeholder:  ph("cph_PROVIDER"),
		Secret:       ph("sk-real"),
		AllowedHosts: []string{"api.provider.example"},
	})
	req := reqWith(t, "/v1/messages", map[string]string{"Authorization": "Bearer cph_PROVIDER"})
	if req.URL.Host != "upstream.test" {
		t.Fatalf("precondition: URL host = %q", req.URL.Host)
	}
	if !SubstituteHTTPRequest("api.provider.example", req, m) {
		t.Fatal("expected substitution keyed off the host argument")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-real" {
		t.Fatalf("header not substituted: %q", got)
	}
}

// A placeholder must never be replaced when it appears as a substring of a
// longer token, or the engine could corrupt an unrelated value.
func TestSubstitute_SubstringSafety(t *testing.T) {
	m := mkMap(Entry{
		Placeholder:  ph("cph_ABC"),
		Secret:       ph("X"),
		AllowedHosts: []string{"h.example.com"},
	})
	cases := []struct{ in, want string }{
		{"cph_ABCDEF", "cph_ABCDEF"},       // longer token, must not match
		{"prefixcph_ABC", "prefixcph_ABC"}, // left-flanked, must not match
		{"cph_ABC", "X"},                   // whole token, must match
		{"x cph_ABC y", "x X y"},           // whole token amid spaces
	}
	for _, c := range cases {
		if got, _ := m.SubstituteValue("h.example.com", c.in); got != c.want {
			t.Errorf("SubstituteValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSubstitute_WildcardBoundaries(t *testing.T) {
	m := mkMap(Entry{
		Placeholder:  ph("cph_K"),
		Secret:       ph("S"),
		AllowedHosts: []string{"*.example.com"},
	})
	cases := map[string]bool{
		"a.example.com":        true,
		"a.b.example.com":      true,  // wildcard matches any depth (platform convention)
		"example.com":          false, // apex is not a sub-label
		"notexample.com":       false,
		"example.com.evil.com": false,
	}
	for host, want := range cases {
		v, got := m.SubstituteValue(host, "k=cph_K")
		if got != want {
			t.Errorf("host %q: fired=%v, want %v (value=%q)", host, got, want, v)
		}
	}
}

func TestSubstitute_MultiSecretIndependentScoping(t *testing.T) {
	m := mkMap(
		Entry{Placeholder: ph("cph_A"), Secret: ph("AAA"), AllowedHosts: []string{"a.example.com"}},
		Entry{Placeholder: ph("cph_B"), Secret: ph("BBB"), AllowedHosts: []string{"b.example.com"}},
	)
	// Request to a.example.com carrying both placeholders: only A resolves.
	req := reqWith(t, "/", map[string]string{"A": "cph_A", "B": "cph_B"})
	if !SubstituteHTTPRequest("a.example.com", req, m) {
		t.Fatal("expected A to fire")
	}
	if req.Header.Get("A") != "AAA" {
		t.Errorf("A not substituted: %q", req.Header.Get("A"))
	}
	if req.Header.Get("B") != "cph_B" {
		t.Errorf("B must remain a placeholder toward a.example.com: %q", req.Header.Get("B"))
	}
}

func TestSubstitute_MultipleOccurrences(t *testing.T) {
	m := mkMap(Entry{Placeholder: ph("cph_K"), Secret: ph("S"), AllowedHosts: []string{"h"}})
	req := reqWith(t, "/?a=cph_K&b=cph_K", map[string]string{"H": "cph_K,cph_K"})
	SubstituteHTTPRequest("h", req, m)
	if req.URL.RawQuery != "a=S&b=S" {
		t.Errorf("query: %q", req.URL.RawQuery)
	}
	if req.Header.Get("H") != "S,S" {
		t.Errorf("header: %q", req.Header.Get("H"))
	}
}

func TestSubstitute_AdjacentPlaceholders(t *testing.T) {
	// Two different placeholders back to back, comma-separated (a token boundary).
	m := mkMap(
		Entry{Placeholder: ph("cph_A"), Secret: ph("AA"), AllowedHosts: []string{"h"}},
		Entry{Placeholder: ph("cph_B"), Secret: ph("BB"), AllowedHosts: []string{"h"}},
	)
	if v, _ := m.SubstituteValue("h", "cph_A,cph_B"); v != "AA,BB" {
		t.Errorf("adjacent placeholders: %q", v)
	}
}

func TestSubstitute_EmptyAndPrefilter(t *testing.T) {
	// Empty map is a no-op.
	if _, ok := (&Map{}).SubstituteValue("h", "k=cph_K"); ok {
		t.Error("empty map must not fire")
	}
	if !(&Map{}).Empty() {
		t.Error("zero Map should be Empty")
	}
	if !(*Map)(nil).Empty() {
		t.Error("nil Map should be Empty")
	}
	// Non-nil map, but request carries no placeholder prefix → fast false.
	m := mkMap(Entry{Placeholder: ph("cph_K"), Secret: ph("S"), AllowedHosts: []string{"h"}})
	req := reqWith(t, "/plain", map[string]string{"A": "b"})
	if SubstituteHTTPRequest("h", req, m) {
		t.Error("no placeholder present must not fire")
	}
	// Nil request is safe.
	if SubstituteHTTPRequest("h", nil, m) {
		t.Error("nil request must not fire")
	}
}

func TestSubstitute_HostPortNormalized(t *testing.T) {
	m := mkMap(Entry{Placeholder: ph("cph_K"), Secret: ph("S"), AllowedHosts: []string{"api.example.com"}})
	v, ok := m.SubstituteValue("API.Example.com:443", "k=cph_K")
	if !ok {
		t.Fatal("host with port + mixed case should match")
	}
	if v != "k=S" {
		t.Errorf("value: %q", v)
	}
}

func TestNewMap_DropsUnusableEntries(t *testing.T) {
	m := NewMap([]Entry{
		{Placeholder: ph(""), Secret: ph("S"), AllowedHosts: []string{"h"}}, // no placeholder
		{Placeholder: ph("cph_X"), Secret: ph("S"), AllowedHosts: nil},      // no hosts
		{Placeholder: ph("cph_Y"), Secret: ph("S"), AllowedHosts: []string{"h"}},
	})
	if len(m.entries) != 1 {
		t.Fatalf("expected 1 usable entry, got %d", len(m.entries))
	}
	if m.Empty() {
		t.Error("map with one entry should not be Empty")
	}
}

func TestHostMatcher_NormalizeEdgeCases(t *testing.T) {
	hm := hostmatch.New([]string{"  API.Example.com.  ", "", "*.internal."}, normalizeHost)
	if !hm.Matches("api.example.com") {
		t.Error("trimmed/lowercased/trailing-dot exact should match")
	}
	if !hm.Matches("db.internal") {
		t.Error("wildcard should match")
	}
	if hm.Matches("") {
		t.Error("empty host must not match")
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"API.Example.com:443": "api.example.com",
		"  host.  ":           "host",
		"[::1]:443":           "[::1]:443", // bracketed IPv6 is left alone
		"a:b:c":               "a:b",       // only the last :segment is treated as a port
		"":                    "",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q want %q", in, got, want)
		}
	}
}

func TestHostHasSecret_EmptyMap(t *testing.T) {
	if (&Map{}).HostHasSecret("api.example.com") {
		t.Fatal("empty map should report no secret for any host")
	}
}

func FuzzSubstitute_NonMatchingHostIsInvariant(f *testing.F) {
	f.Add("k=cph_K", "Bearer cph_K", "cph_K", "SECRET")
	f.Fuzz(func(t *testing.T, query, header, placeholder, secret string) {
		if placeholder == "" {
			return
		}
		m := NewMap([]Entry{{
			Placeholder:  []byte(placeholder),
			Secret:       []byte(secret),
			AllowedHosts: []string{"allowed.example.com"},
		}})
		// A host that is guaranteed not to match the allow-list.
		if v, changed := m.SubstituteValue("attacker.invalid", query); changed || v != query {
			t.Fatalf("substitution fired for a non-allowed host: %q -> %q", query, v)
		}
		if v, changed := m.SubstituteValue("attacker.invalid", header); changed || v != header {
			t.Fatalf("substitution fired for a non-allowed host: %q -> %q", header, v)
		}
	})
}

func FuzzSubstitute_NeverPanics(f *testing.F) {
	f.Add("k=cph_K", "cph_K cph_K", "cph_K", "S", "allowed")
	f.Fuzz(func(t *testing.T, query, header, placeholder, secret, host string) {
		m := NewMap([]Entry{{
			Placeholder:  []byte(placeholder),
			Secret:       []byte(secret),
			AllowedHosts: []string{"allowed", "*.example.com"},
		}})
		_, _ = m.SubstituteValue(host, query)  // must not panic
		_, _ = m.SubstituteValue(host, header) // must not panic
	})
}

// A substituted value never carries the placeholder as a whole token any more,
// and an unchanged report means the bytes are byte-for-byte the input.
func FuzzReplaceToken(f *testing.F) {
	f.Add("a cph_K b", "cph_K", "S")
	f.Add("cph_Kcph_K", "cph_K", "S")
	f.Fuzz(func(t *testing.T, s, token, secret string) {
		out, changed := replaceToken(s, token, secret)
		if !changed && out != s {
			t.Fatalf("unchanged report but output differs: %q -> %q", s, out)
		}
		if changed && !strings.Contains(s, token) {
			t.Fatalf("changed without the token present: %q", s)
		}
	})
}

// normalizeHost never panics, never yields an uppercase letter, and passes an
// already normalized host through unchanged.
func FuzzNormalizeHost(f *testing.F) {
	f.Add("API.Example.com:443")
	f.Add("[::1]:443")
	f.Add(" host. ")
	f.Fuzz(func(t *testing.T, host string) {
		n := normalizeHost(host)
		if strings.ToLower(n) != n {
			t.Fatalf("normalizeHost(%q) = %q keeps uppercase", host, n)
		}
		clean := !strings.ContainsRune(host, ':') && strings.TrimSpace(host) == host &&
			!strings.HasSuffix(host, ".") && strings.ToLower(host) == host
		if clean && n != host {
			t.Fatalf("normalizeHost(%q) changed an already normalized host to %q", host, n)
		}
	})
}

func TestSubstituteValue_EarlyReturns(t *testing.T) {
	m := mkMap(Entry{Placeholder: ph("cph_k"), Secret: ph("S"), AllowedHosts: []string{"h"}})
	// No placeholder prefix in the string → unchanged, not fired.
	if v, ok := m.SubstituteValue("h", "no placeholder here"); ok || v != "no placeholder here" {
		t.Fatalf("no-prefix should be a no-op: %q %v", v, ok)
	}
	// Empty map → unchanged.
	if v, ok := (&Map{}).SubstituteValue("h", "cph_k"); ok || v != "cph_k" {
		t.Fatalf("empty map should be a no-op: %q %v", v, ok)
	}
}
