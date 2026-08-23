// Package sanitize provides string sanitization utilities for display
// truncation and generated slugs.
package sanitize

import "strings"

// Truncate returns s truncated to at most n runes, appending "…" when trimmed.
// It handles multi-byte characters correctly by operating on runes rather than
// bytes. A negative n is treated as zero, so every budget below the input's
// length yields the ellipsis alone rather than an out-of-range slice.
func Truncate(s string, n int) string {
	n = max(n, 0)
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

// TruncateTrimRight returns s truncated to at most n runes, removes trailing
// runes in cutset from the shortened text, and appends "…" when truncated.
// A negative n is treated as zero, matching [Truncate].
func TruncateTrimRight(s string, n int, cutset string) string {
	n = max(n, 0)
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return strings.TrimRight(string(runes[:n]), cutset) + "…"
}

// Fallback is the slug returned when s carries no alphanumeric character to
// build one from. It is returned verbatim, so it is the one result that can
// exceed maxLen.
const Fallback = "task"

// Slug creates a container-name-safe slug from s.
// The result is lowercase, non-empty, contains only [a-z0-9-] with no edge or
// doubled dash, and collapses runs of non-alphanumeric characters into a single
// dash.
//
// Length is bounded by maxLen with two exceptions worth knowing before passing
// a small bound: the accumulator is appended to before it is measured, so one
// character is always admitted even at maxLen <= 0, and an input with nothing
// alphanumeric in it yields [Fallback] at its own length. Callers wanting a
// hard cap should bound the result themselves.
func Slug(s string, maxLen int) string {
	var b []byte
	prevDash := true // suppress leading dashes
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b = append(b, byte(r))
			prevDash = false
		} else if !prevDash {
			b = append(b, '-')
			prevDash = true
		}
		if len(b) >= maxLen {
			break
		}
	}
	slug := strings.TrimRight(string(b), "-")
	if slug == "" {
		return Fallback
	}
	return slug
}
