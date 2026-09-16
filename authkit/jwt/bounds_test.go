// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestMaxTokenBytesRefusesAboveTheBound: a token of exactly the bound is
// read, one byte more is refused before it is parsed. The refused string is
// the accepted token with one byte appended, so the bound is what fired and
// not the parser.
func TestMaxTokenBytesRefusesAboveTheBound(t *testing.T) {
	key := genKey(t)
	tok := signToken(t, key, defaultHeader(key), defaultPayload())
	n := len(tok)
	v := testValidator(t, key, func(c *Config) { c.MaxTokenBytes = n })

	if _, err := v.Validate(tok); err != nil {
		t.Fatalf("a token of exactly %d bytes was refused: %v", n, err)
	}
	_, err := v.Validate(tok + "x")
	if !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("a token of %d bytes: err = %v, want ErrTokenTooLarge", n+1, err)
	}
	if got := ReasonOf(err); got != ReasonTooLarge {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonTooLarge)
	}
}

// TestMaxTokenBytesDefault: the bound a caller configures nothing for is
// 8 KiB, the one the cores' verifier has carried.
func TestMaxTokenBytesDefault(t *testing.T) {
	if DefaultMaxTokenBytes != 8<<10 {
		t.Fatalf("DefaultMaxTokenBytes = %d, want 8192", DefaultMaxTokenBytes)
	}
	key := genKey(t)
	v := testValidator(t, key)
	if _, err := v.Validate(signToken(t, key, defaultHeader(key), defaultPayload())); err != nil {
		t.Fatalf("an ordinary token was refused: %v", err)
	}

	big := defaultPayload()
	big["filler"] = strings.Repeat("x", DefaultMaxTokenBytes)
	tok := signToken(t, key, defaultHeader(key), big)
	if len(tok) <= DefaultMaxTokenBytes {
		t.Fatalf("the oversize token is %d bytes", len(tok))
	}
	if _, err := v.Validate(tok); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("err = %v, want ErrTokenTooLarge", err)
	}
}

// TestMaxTokenBytesNegativeIsUnbounded: a caller whose tokens are larger
// than the default turns the bound off.
func TestMaxTokenBytesNegativeIsUnbounded(t *testing.T) {
	key := genKey(t)
	big := defaultPayload()
	big["filler"] = strings.Repeat("x", DefaultMaxTokenBytes)
	tok := signToken(t, key, defaultHeader(key), big)

	v := testValidator(t, key, func(c *Config) { c.MaxTokenBytes = -1 })
	if _, err := v.Validate(tok); err != nil {
		t.Fatalf("a %d-byte token was refused with the bound off: %v", len(tok), err)
	}
}

// freezeClock pins timeNow for the test, so a bound measured in whole hours
// is measured against an instant that does not move.
func freezeClock(t *testing.T, at time.Time) {
	t.Helper()
	orig := timeNow
	timeNow = func() time.Time { return at }
	t.Cleanup(func() { timeNow = orig })
}

// agedToken is a token whose iat is age old and whose exp is an hour out,
// so the age is the only thing that can refuse it.
func agedToken(t *testing.T, key *rsa.PrivateKey, now time.Time, age time.Duration) string {
	t.Helper()
	p := defaultPayload()
	p["iat"] = float64(now.Add(-age).Unix())
	p["exp"] = float64(now.Add(time.Hour).Unix())
	return signToken(t, key, defaultHeader(key), p)
}

// TestMaxTokenAgeRefusesAnOldIssuedAt: a token stays a credential for as
// long as the bound, whatever exp it carries. The bound itself is admitted
// and a second past it is not.
func TestMaxTokenAgeRefusesAnOldIssuedAt(t *testing.T) {
	key := genKey(t)
	// iat is whole seconds, so the frozen instant is one too: a bound
	// measured in hours is then exactly a bound.
	now := time.Unix(time.Now().Unix(), 0)
	freezeClock(t, now)
	v := testValidator(t, key, func(c *Config) { c.MaxTokenAge = time.Hour })

	if _, err := v.Validate(agedToken(t, key, now, time.Hour)); err != nil {
		t.Fatalf("a token exactly at the bound was refused: %v", err)
	}
	_, err := v.Validate(agedToken(t, key, now, time.Hour+time.Second))
	if !errors.Is(err, ErrTokenTooOld) {
		t.Fatalf("err = %v, want ErrTokenTooOld", err)
	}
	if got := ReasonOf(err); got != ReasonTooOld {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonTooOld)
	}
}

// TestMaxTokenAgeDefault: the age a caller configures nothing for is a day,
// the one the cores' verifier has carried.
func TestMaxTokenAgeDefault(t *testing.T) {
	if DefaultMaxTokenAge != 24*time.Hour {
		t.Fatalf("DefaultMaxTokenAge = %v, want 24h", DefaultMaxTokenAge)
	}
	key := genKey(t)
	// iat is whole seconds, so the frozen instant is one too: a bound
	// measured in hours is then exactly a bound.
	now := time.Unix(time.Now().Unix(), 0)
	freezeClock(t, now)
	v := testValidator(t, key)

	if _, err := v.Validate(agedToken(t, key, now, 23*time.Hour)); err != nil {
		t.Fatalf("a token minted 23 hours ago was refused: %v", err)
	}
	if _, err := v.Validate(agedToken(t, key, now, 25*time.Hour)); !errors.Is(err, ErrTokenTooOld) {
		t.Fatalf("err = %v, want ErrTokenTooOld", err)
	}
}

// TestMaxTokenAgeNegativeIsUnbounded: a caller whose tokens outlive a day
// turns the age off, and exp alone decides.
func TestMaxTokenAgeNegativeIsUnbounded(t *testing.T) {
	key := genKey(t)
	// iat is whole seconds, so the frozen instant is one too: a bound
	// measured in hours is then exactly a bound.
	now := time.Unix(time.Now().Unix(), 0)
	freezeClock(t, now)
	v := testValidator(t, key, func(c *Config) { c.MaxTokenAge = -1 })
	if _, err := v.Validate(agedToken(t, key, now, 30*24*time.Hour)); err != nil {
		t.Fatalf("a month-old token was refused with the age off: %v", err)
	}
}

// TestIssuedAtZeroIsAncient: a token that stamps "iat": 0 named the epoch,
// which is a token older than any bound. It is not a token with no iat, and
// the age bound is what refuses it.
func TestIssuedAtZeroIsAncient(t *testing.T) {
	key := genKey(t)
	p := defaultPayload()
	p["iat"] = float64(0)
	tok := signToken(t, key, defaultHeader(key), p)

	_, err := testValidator(t, key).Validate(tok)
	if !errors.Is(err, ErrTokenTooOld) {
		t.Fatalf("err = %v, want ErrTokenTooOld", err)
	}
	if got := ReasonOf(err); got != ReasonTooOld {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonTooOld)
	}
}

// TestRequireIssuedAt: a token with no iat has no age, so it verifies
// unless a caller declares that its issuers stamp one.
func TestRequireIssuedAt(t *testing.T) {
	key := genKey(t)
	p := defaultPayload()
	delete(p, "iat")
	tok := signToken(t, key, defaultHeader(key), p)

	if _, err := testValidator(t, key).Validate(tok); err != nil {
		t.Fatalf("a token with no iat was refused: %v", err)
	}
	_, err := testValidator(t, key, func(c *Config) { c.RequireIssuedAt = true }).Validate(tok)
	if !errors.Is(err, ErrTokenTooOld) {
		t.Fatalf("err = %v, want ErrTokenTooOld", err)
	}
}
