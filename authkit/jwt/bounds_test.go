// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"errors"
	"strings"
	"testing"
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
