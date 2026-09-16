// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"errors"
	"testing"
	"time"
)

// TestIssuerComparisonTrimsTrailingSlashes: an issuer that publishes
// "https://x" and stamps "https://x/" names one issuer, and a caller cannot
// fix the difference from outside. Both sides are compared trimmed.
func TestIssuerComparisonTrimsTrailingSlashes(t *testing.T) {
	key := genKey(t)
	for _, tc := range []struct {
		name       string
		configured string
		claimed    string
		want       error
	}{
		{"the claim carries the slash", "https://auth.example", "https://auth.example/", nil},
		{"the configuration carries it", "https://auth.example/", "https://auth.example", nil},
		{"both carry it", "https://auth.example/", "https://auth.example/", nil},
		{"neither carries it", "https://auth.example", "https://auth.example", nil},
		{"several slashes", "https://auth.example///", "https://auth.example/", nil},
		{"another issuer entirely", "https://auth.example", "https://elsewhere.example", ErrInvalidIssuer},
		{"a slash is not a path", "https://auth.example", "https://auth.example/realm", ErrInvalidIssuer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := defaultPayload()
			p["iss"] = tc.claimed
			tok := signToken(t, key, defaultHeader(key), p)
			v := testValidator(t, key, func(c *Config) { c.Issuer = tc.configured })

			c, err := v.Validate(tok)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("iss %q against Issuer %q was refused: %v", tc.claimed, tc.configured, err)
			}
			// The claim itself is handed back as the token carried it.
			if c.Iss != tc.claimed {
				t.Fatalf("Claims.Iss = %q, want the claim verbatim %q", c.Iss, tc.claimed)
			}
		})
	}
}

// TestLocalIssuerComparisonTrimsTrailingSlashes: the local issuer is matched
// by the same rule, so a node configured with a trailing slash still routes
// its own tokens to its own key.
func TestLocalIssuerComparisonTrimsTrailingSlashes(t *testing.T) {
	remote := genKey(t)
	srv := serveJWKS(t, remote)
	key := localKey(t)
	v := New(Config{
		JWKSURL: srv.URL, CacheTTL: time.Hour,
		Issuer:      "https://auth.example",
		LocalIssuer: localIssuer + "/", LocalKey: &key.PublicKey, LocalKeyID: "node-1",
	})

	if _, err := v.Validate(localToken(t, key, "node-1")); err != nil {
		t.Fatalf("a local token was not routed to the local key: %v", err)
	}
}
