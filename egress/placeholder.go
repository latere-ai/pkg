// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// placeholderEntropyBytes is the random payload width per placeholder: 20 bytes
// = 160 bits, comfortably above a 128-bit floor. base32 of 20 bytes is 32
// characters, so a placeholder is PlaceholderPrefix + 32 chars.
const placeholderEntropyBytes = 20

// b32 is unpadded base32, lowercased on output, so a placeholder is a single
// token of [PlaceholderPrefix + a-z2-7]. Every byte is a token char, which
// keeps the substitution engine's whole-token boundary check simple.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// randRead is crypto/rand.Read, replaceable in tests to exercise the failure
// branch.
var randRead = rand.Read

// MintPlaceholder returns a fresh, high-entropy, opaque placeholder for a
// credential. The token encodes nothing about the secret it stands in for.
// Placeholders are per-principal and re-minted whenever the principal's token
// is re-minted (create, start, rotation), so a leaked placeholder from a prior
// run is already dead.
func MintPlaceholder() string {
	buf := make([]byte, placeholderEntropyBytes)
	if _, err := randRead(buf); err != nil {
		// crypto/rand.Read never returns an error on supported platforms; if it
		// somehow does, panic rather than mint a low-entropy placeholder.
		panic("egress: crypto/rand failed: " + err.Error())
	}
	return PlaceholderPrefix + strings.ToLower(b32.EncodeToString(buf))
}

// IsPlaceholder reports whether s has the placeholder shape (prefix + the
// expected token width). Used by defensive checks; not a security boundary.
func IsPlaceholder(s string) bool {
	if !strings.HasPrefix(s, PlaceholderPrefix) {
		return false
	}
	body := s[len(PlaceholderPrefix):]
	return len(body) == b32.EncodedLen(placeholderEntropyBytes)
}
