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
//   - [Map], [NewMap], [NewMapStrict], [Map.SubstituteValue],
//     [Map.SubstituteValueContext], [Map.HostHasSecret],
//     [SubstituteHTTPRequest] and [SubstituteHTTPRequestContext] are the pure
//     substitution engine. They have no network, TLS, or platform dependency,
//     which keeps the security-critical core exhaustively unit-testable.
//   - [OAuthClientCredentials] is the one built-in dynamic credential: an
//     [Entry.Resolve] that mints and caches an OAuth 2.0 access token. It is
//     the only piece of the engine that talks to the network, and only to
//     the token endpoint the entry names.
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
//
// # Static and dynamic secrets
//
// An entry's secret is static ([Entry.Secret]) or produced at substitution
// time ([Entry.Resolve]). The context-free functions [Map.SubstituteValue]
// and [SubstituteHTTPRequest] serve static entries only: an entry with a
// resolver is skipped and its placeholder passes through unchanged. The
// context-taking variants [Map.SubstituteValueContext] and
// [SubstituteHTTPRequestContext] serve both kinds and return the resolver's
// error, so a caller that holds dynamic entries must use them.
//
// # Where substitution applies
//
// Header values and the raw query string are always in scope. The framing
// and hop-by-hop headers Content-Length, Transfer-Encoding, TE, Trailer,
// Connection, Keep-Alive, Upgrade, Proxy-Connection, Proxy-Authorization and
// every X-Forwarded-* header are never rewritten. The request body is in
// scope only for entries with [Entry.SubstituteBody] set, and only when the
// body is small and textual: Content-Length is known and at most
// [DefaultMaxBodyBytes] (or the [WithMaxBodyBytes] limit) and Content-Type
// is JSON, a form, or text. A streaming, chunked, larger, or binary body is
// never read, so SSE and uploads are never buffered.
package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

	// Resolve, when set, produces the secret at substitution time and Secret
	// is ignored. The returned bytes replace the placeholder verbatim, so for
	// a bearer token they are the bare token: the request already carries
	// the "Bearer " the SDK put around the placeholder. A resolver must be
	// safe for concurrent use and should cache; [OAuthClientCredentials] is
	// the built-in one. Only the context-taking substitution functions call
	// it. A resolved secret containing CR or LF fails the substitution with
	// [ErrSecretLineBreak], for the same reason [NewMap] drops such a static
	// secret.
	Resolve func(ctx context.Context) ([]byte, error)

	// SubstituteBody opts this entry into request-body substitution by
	// [SubstituteHTTPRequestContext], under the body rule in the package
	// documentation. Header and query substitution is unaffected.
	SubstituteBody bool
}

// Reasons [NewMapStrict] drops an entry.
var (
	ErrEmptyPlaceholder = errors.New("egress: empty placeholder")
	ErrNoAllowedHosts   = errors.New("egress: no allowed hosts")
	// ErrSecretLineBreak marks a secret containing CR or LF. Such a secret
	// written into a header value would end the header and let the rest of
	// the secret be parsed as new headers, so the engine refuses it.
	ErrSecretLineBreak = errors.New("egress: secret contains CR or LF")
)

// DroppedEntry is one entry [NewMapStrict] refused, with the input index it
// sat at and the reason. Placeholder is echoed because it is opaque; the
// secret is not.
type DroppedEntry struct {
	Index       int
	Placeholder string
	Err         error
}

func (d DroppedEntry) Error() string {
	return fmt.Sprintf("entry %d (%s): %v", d.Index, d.Placeholder, d.Err)
}

// Unwrap returns the reason, so errors.Is(d, ErrSecretLineBreak) works.
func (d DroppedEntry) Unwrap() error { return d.Err }

// Map is one principal's substitution table. Construct it with [NewMap]; the
// zero value is an empty (no-op) map. It is read-only after construction and
// safe for concurrent use.
type Map struct {
	entries []compiledEntry
}

type compiledEntry struct {
	placeholder string
	secret      string
	resolve     func(ctx context.Context) ([]byte, error)
	body        bool
	hosts       hostmatch.Matcher
}

// NewMap compiles entries into a substitution table. Entries with an empty
// placeholder, no allowed hosts, or a static secret containing CR or LF are
// dropped: a placeholder that can never be scoped to a destination would be a
// footgun, a line break in a header value is an injection, and the store
// that owns the credentials should already reject such entries at write
// time. This is defence in depth. [NewMapStrict] reports what was dropped.
func NewMap(entries []Entry) *Map {
	m, _ := NewMapStrict(entries)
	return m
}

// NewMapStrict is [NewMap] that also returns every entry it dropped and why.
// The map is always usable; dropped is nil when nothing was dropped.
func NewMapStrict(entries []Entry) (m *Map, dropped []DroppedEntry) {
	m = &Map{}
	for i, e := range entries {
		ph := string(e.Placeholder)
		if err := e.check(); err != nil {
			dropped = append(dropped, DroppedEntry{Index: i, Placeholder: ph, Err: err})
			continue
		}
		m.entries = append(m.entries, compiledEntry{
			placeholder: ph,
			secret:      string(e.Secret),
			resolve:     e.Resolve,
			body:        e.SubstituteBody,
			hosts:       hostmatch.New(e.AllowedHosts, normalizeHost),
		})
	}
	return m, dropped
}

func (e Entry) check() error {
	switch {
	case len(e.Placeholder) == 0:
		return ErrEmptyPlaceholder
	case len(e.AllowedHosts) == 0:
		return ErrNoAllowedHosts
	case e.Resolve == nil && hasLineBreak(e.Secret):
		return ErrSecretLineBreak
	}
	return nil
}

func hasLineBreak(b []byte) bool { return bytes.ContainsAny(b, "\r\n") }

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
//
// Only static entries take part: an entry with [Entry.Resolve] set is skipped
// and its placeholder is returned unchanged. Use [Map.SubstituteValueContext]
// when the map may hold dynamic entries.
func (m *Map) SubstituteValue(host, s string) (string, bool) {
	v, changed, _ := m.substitute(context.Background(), host, s, modeStaticOnly, nil)
	return v, changed
}

// SubstituteValueContext is [Map.SubstituteValue] for maps that may hold
// dynamic entries: an entry's resolver runs, with ctx, only when its
// placeholder occurs in s and host is in scope. On a resolver error the
// original s is returned unchanged with the error, so a caller never sends a
// half-rewritten value.
func (m *Map) SubstituteValueContext(ctx context.Context, host, s string) (string, bool, error) {
	return m.substitute(ctx, host, s, 0, nil)
}

// resolved memoises one call's resolver results, so a request that carries
// the same dynamic placeholder in a header and in the body resolves it once.
type resolved map[*compiledEntry]string

// subMode narrows which entries a substitution pass considers.
type subMode uint8

const (
	// modeStaticOnly skips entries with a resolver: the context-free API.
	modeStaticOnly subMode = 1 << iota
	// modeBodyOnly keeps only entries that opted into body substitution.
	modeBodyOnly
)

// substitute is the engine behind every public substitution function. cache
// may be nil. Static entries never error. On error s is returned as given.
func (m *Map) substitute(ctx context.Context, host, s string, mode subMode, cache resolved) (string, bool, error) {
	if m.Empty() || !strings.Contains(s, PlaceholderPrefix) {
		return s, false, nil
	}
	host = normalizeHost(host)
	out := s
	changed := false
	for i := range m.entries {
		e := &m.entries[i]
		if mode&modeStaticOnly != 0 && e.resolve != nil {
			continue
		}
		if mode&modeBodyOnly != 0 && !e.body {
			continue
		}
		if !e.hosts.Matches(host) || !strings.Contains(out, e.placeholder) {
			continue
		}
		secret, err := e.secretFor(ctx, cache)
		if err != nil {
			return s, false, err
		}
		if v, ok := replaceToken(out, e.placeholder, secret); ok {
			out = v
			changed = true
		}
	}
	return out, changed, nil
}

// secretFor is the entry's secret: the static one, or the resolver's result.
func (e *compiledEntry) secretFor(ctx context.Context, cache resolved) (string, error) {
	if e.resolve == nil {
		return e.secret, nil
	}
	if v, ok := cache[e]; ok {
		return v, nil
	}
	b, err := e.resolve(ctx)
	if err != nil {
		return "", fmt.Errorf("egress: resolve %s: %w", e.placeholder, err)
	}
	if hasLineBreak(b) {
		return "", fmt.Errorf("egress: resolve %s: %w", e.placeholder, ErrSecretLineBreak)
	}
	if cache != nil {
		cache[e] = string(b)
	}
	return string(b), nil
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
