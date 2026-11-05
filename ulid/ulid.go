// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package ulid mints and checks prefixed, time-ordered identifiers such as
// fil_01hq3k...: a caller-chosen prefix followed by a 26-character ULID in
// Crockford base32, which is 48 bits of Unix milliseconds then 80 random
// bits. Identifiers sort by when they were minted, and within one
// millisecond a Generator keeps them in minting order.
//
// Stored identifiers are permanent, so a Generator mints in the case its
// caller chooses and Valid and Time accept either case.
package ulid

import (
	"crypto/rand"
	"strings"
	"sync"
	"time"
)

const (
	// ulidLen is the length of the encoded ULID in characters.
	ulidLen = 26

	lowerAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	upperAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// decode maps a byte to its Crockford value, or 0xff when it is not in
// the alphabet. Both cases are accepted.
var decode = func() (t [256]byte) {
	for i := range t {
		t[i] = 0xff
	}
	for i := range len(lowerAlphabet) {
		t[lowerAlphabet[i]] = byte(i)
		t[upperAlphabet[i]] = byte(i)
	}
	return t
}()

// Generator mints identifiers. Two minted in the same millisecond still
// sort in the order they were minted: the second takes the first's random
// part plus one. If the clock steps backward the last timestamp is kept,
// so values keep increasing. If the increment overflows the 80-bit random
// part, it wraps to zero. The zero value is ready to use and a Generator is
// safe for concurrent use.
type Generator struct {
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
	// Upper mints uppercase identifiers instead of lowercase.
	Upper bool

	mu   sync.Mutex
	ms   uint64
	tail [10]byte
}

var std Generator

// New returns prefix followed by a new ULID, in lowercase, from a package
// default Generator.
func New(prefix string) string { return std.New(prefix) }

// New returns prefix verbatim followed by a new 26-character ULID.
func (g *Generator) New(prefix string) string {
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	ms := uint64(now().UnixMilli())

	g.mu.Lock()
	if ms > g.ms {
		g.ms = ms
		// crypto/rand.Read does not return an error: it aborts the
		// process when the system source is unavailable.
		_, _ = rand.Read(g.tail[:])
	} else {
		// Same millisecond, or a clock that stepped back: stay on the
		// last timestamp and count up so order is kept.
		for i := len(g.tail) - 1; i >= 0; i-- {
			if g.tail[i]++; g.tail[i] != 0 {
				break
			}
		}
	}
	var raw [16]byte
	for i := range 6 {
		raw[i] = byte(g.ms >> (40 - 8*i))
	}
	copy(raw[6:], g.tail[:])
	g.mu.Unlock()

	alphabet := lowerAlphabet
	if g.Upper {
		alphabet = upperAlphabet
	}
	// 128 bits in 26 characters of 5 bits: the first character holds the
	// top 3 bits and each later one the next 5.
	out := make([]byte, 0, len(prefix)+ulidLen)
	out = append(out, prefix...)
	out = append(out, alphabet[raw[0]>>5])
	acc, bits := uint(raw[0]&0x1f), 5
	for _, b := range raw[1:] {
		acc, bits = acc<<8|uint(b), bits+8
		for bits >= 5 {
			bits -= 5
			out = append(out, alphabet[acc>>bits&0x1f])
		}
	}
	return string(out)
}

// Valid reports whether id is prefix followed by exactly 26 Crockford
// base32 characters in either case, the first of them 0 to 7 (a larger one
// overflows the 48-bit timestamp).
func Valid(prefix, id string) bool {
	rest, ok := strings.CutPrefix(id, prefix)
	return ok && isULID(rest)
}

// Time returns the millisecond timestamp encoded in the last 26 characters
// of id, in either case. It reports false when they are not a ULID.
func Time(id string) (time.Time, bool) {
	if len(id) < ulidLen {
		return time.Time{}, false
	}
	s := id[len(id)-ulidLen:]
	if !isULID(s) {
		return time.Time{}, false
	}
	var ms uint64
	for i := range 10 {
		ms = ms<<5 | uint64(decode[s[i]])
	}
	return time.UnixMilli(int64(ms)), true
}

// isULID reports whether s is 26 Crockford characters whose first holds
// no more than 3 bits.
func isULID(s string) bool {
	if len(s) != ulidLen || s[0] > '7' {
		return false
	}
	for i := range len(s) {
		if decode[s[i]] == 0xff {
			return false
		}
	}
	return true
}
