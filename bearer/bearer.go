// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package bearer reads the token from an Authorization: Bearer header and
// compares tokens in constant time. The scheme is matched case-insensitively,
// as RFC 7235 section 2.1 requires, which is the one detail that the copies
// this package replaces disagreed on.
package bearer

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// FromRequest returns the token carried by r's Authorization header. ok is
// false when the header is absent, uses another scheme, or has no token.
func FromRequest(r *http.Request) (token string, ok bool) {
	return Parse(r.Header.Get("Authorization"))
}

// Parse returns the token in an Authorization header value of the form
// "Bearer <token>". The scheme is matched case-insensitively and whitespace
// around the token is dropped. ok is false when the value is empty, uses
// another scheme, or carries no token after the scheme.
func Parse(header string) (token string, ok bool) {
	scheme, rest, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	// The header was trimmed before the cut, so rest is never all space.
	return strings.TrimSpace(rest), true
}

// Equal reports whether a and b are the same token, in time that depends
// only on their lengths. Use it for every comparison against a configured
// secret; a plain == leaks how many leading bytes matched.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
