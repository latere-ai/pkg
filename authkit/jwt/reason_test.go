// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestReasonOfNamesEveryRefusal is the reason table of the family's C5
// (latere-ai/specs, decisions/2026-09-13-one-platform-open-cores.md): one
// row per way a token is refused, and the value a core writes on the wire.
func TestReasonOfNamesEveryRefusal(t *testing.T) {
	key := genKey(t)
	past := float64(time.Now().Add(-2 * time.Hour).Unix())
	future := float64(time.Now().Add(time.Hour).Unix())

	// token builds a token from the default payload with the given edits.
	token := func(edit func(map[string]any)) string {
		p := defaultPayload()
		edit(p)
		return signToken(t, key, defaultHeader(key), p)
	}

	for _, tc := range []struct {
		name  string
		want  Reason
		wire  string
		sen   error
		token string
		opts  []func(*Config)
	}{
		{
			name: "expired", want: ReasonExpired, wire: "expired", sen: ErrTokenExpired,
			token: token(func(p map[string]any) { p["exp"] = past }),
		},
		{
			name: "not yet valid", want: ReasonNotYetValid, wire: "nbf", sen: ErrTokenNotValidYet,
			token: token(func(p map[string]any) { p["nbf"] = future }),
		},
		{
			name: "bad signature", want: ReasonBadSignature, wire: "signature", sen: ErrInvalidSignature,
			token: token(func(map[string]any) {}) + "tampered",
		},
		{
			name: "bad audience", want: ReasonBadAudience, wire: "audience", sen: ErrInvalidAudience,
			token: token(func(p map[string]any) { p["aud"] = "another-service" }),
			opts:  []func(*Config){func(c *Config) { c.Audiences = []string{"my-client"} }},
		},
		{
			name: "bad issuer", want: ReasonBadIssuer, wire: "issuer", sen: ErrInvalidIssuer,
			token: token(func(p map[string]any) { p["iss"] = "https://elsewhere.example" }),
			opts:  []func(*Config){func(c *Config) { c.Issuer = "https://auth.latere.ai" }},
		},
		{
			name: "too large", want: ReasonTooLarge, wire: "size", sen: ErrTokenTooLarge,
			token: token(func(p map[string]any) { p["filler"] = strings.Repeat("x", DefaultMaxTokenBytes) }),
		},
		{
			name: "too old", want: ReasonTooOld, wire: "iat", sen: ErrTokenTooOld,
			token: token(func(p map[string]any) {
				p["iat"] = float64(time.Now().Add(-25 * time.Hour).Unix())
			}),
		},
		{
			name: "malformed", want: ReasonMalformed, wire: "malformed", sen: ErrMalformedToken,
			token: "one.two",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := testValidator(t, key, tc.opts...).Validate(tc.token)
			if !errors.Is(err, tc.sen) {
				t.Fatalf("err = %v, want %v", err, tc.sen)
			}
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("ReasonOf(%v) = %q, want %q", err, got, tc.want)
			}
			if string(tc.want) != tc.wire {
				t.Fatalf("Reason %q is written %q on the wire, want %q", tc.name, tc.want, tc.wire)
			}
		})
	}
}

// TestReasonOfReadsThroughAWrap: a core that wraps the refusal with its own
// context still reads the reason, and an error that is not a refusal has none.
func TestReasonOfReadsThroughAWrap(t *testing.T) {
	wrapped := fmt.Errorf("verify the bearer token: %w", ErrTokenExpired)
	if got := ReasonOf(wrapped); got != ReasonExpired {
		t.Fatalf("ReasonOf(wrapped) = %q, want %q", got, ReasonExpired)
	}
	if got := ReasonOf(errors.New("a fetch failed")); got != "" {
		t.Fatalf("ReasonOf(other) = %q, want the empty reason", got)
	}
	if got := ReasonOf(nil); got != "" {
		t.Fatalf("ReasonOf(nil) = %q, want the empty reason", got)
	}
}

// TestUnsupportedAlgIsASignatureRefusal: an alg that is neither RS256 nor
// ES256 is refused before a key is read, and its wire reason is the
// signature one, as it is in the verifier this table came from.
func TestUnsupportedAlgIsASignatureRefusal(t *testing.T) {
	key := genKey(t)
	tok := signToken(t, key, map[string]any{"alg": "HS256", "typ": "JWT"}, defaultPayload())
	_, err := testValidator(t, key).Validate(tok)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("err = %v, want ErrUnsupportedAlg", err)
	}
	if got := ReasonOf(err); got != ReasonBadSignature {
		t.Fatalf("ReasonOf(ErrUnsupportedAlg) = %q, want %q", got, ReasonBadSignature)
	}
}
