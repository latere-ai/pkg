// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package placeholder mints and recognises the opaque token a sandbox holds
// in place of a credential value. It imports only the standard library so a
// control plane's exported packages, which dial nothing, can mint one
// without pulling in the gateway, its TLS stack, or its HTTP clients.
package placeholder

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// Prefix is the prefix every placeholder token carries, so the substitution
// engine can skip a value that cannot contain one with a single scan.
const Prefix = "cph_"

// entropyBytes is the random payload width per placeholder: 20 bytes = 160
// bits, above a 128-bit floor. base32 of 20 bytes is 32 characters, so a
// placeholder is Prefix + 32 chars.
const entropyBytes = 20

// b32 is unpadded base32, lowercased on output, so a placeholder is a single
// token of [Prefix + a-z2-7]. Every byte is a token char, which keeps the
// substitution engine's whole-token boundary check simple.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// randRead is crypto/rand.Read, replaceable in tests to exercise the failure
// branch.
var randRead = rand.Read

// Mint returns a fresh, high-entropy, opaque placeholder for a credential.
// The token encodes nothing about the secret it stands in for. Placeholders
// are per-principal and re-minted whenever the principal's token is re-minted
// (create, start, rotation), so a leaked placeholder from a prior run is
// already dead.
func Mint() string {
	buf := make([]byte, entropyBytes)
	if _, err := randRead(buf); err != nil {
		// crypto/rand.Read never returns an error on supported platforms; if it
		// somehow does, panic rather than mint a low-entropy placeholder.
		panic("placeholder: crypto/rand failed: " + err.Error())
	}
	return Prefix + strings.ToLower(b32.EncodeToString(buf))
}

// Is reports whether s has the placeholder shape (prefix + the expected token
// width). Used by defensive checks; not a security boundary.
func Is(s string) bool {
	if !strings.HasPrefix(s, Prefix) {
		return false
	}
	body := s[len(Prefix):]
	return len(body) == b32.EncodedLen(entropyBytes)
}
