// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package requestid reads, checks and mints the request id a service carries
// in the X-Request-Id header. A client's id is used only when it is 1 to
// MaxLen bytes of visible ASCII, which keeps it from breaking a log line,
// a trace attribute or a response header; anything else is replaced by a
// freshly minted id.
package requestid

import (
	"crypto/rand"
	"net/http"
	"strings"
)

const (
	// Header is the header a request id travels in, inbound and outbound.
	Header = "X-Request-Id"
	// MaxLen is the longest id taken from a client, in bytes.
	MaxLen = 128
)

// Valid reports whether id is 1 to MaxLen bytes, each a visible ASCII
// character (0x21 to 0x7e). Spaces, control bytes and non-ASCII bytes are
// refused.
func Valid(id string) bool {
	if id == "" || len(id) > MaxLen {
		return false
	}
	for i := range len(id) {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return true
}

// New mints an id: "req_" followed by a random lowercase token.
func New() string {
	return "req_" + strings.ToLower(rand.Text())
}

// FromRequest returns the request's X-Request-Id value when it is Valid, and
// a new id otherwise.
func FromRequest(r *http.Request) string {
	if id := r.Header.Get(Header); Valid(id) {
		return id
	}
	return New()
}
