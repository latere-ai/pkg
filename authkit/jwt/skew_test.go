// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

// at builds a token whose envelope sits at the given offsets from now. A
// zero offset leaves the claim where the default payload had it.
func at(t *testing.T, key *rsa.PrivateKey, now time.Time, exp, nbf time.Duration) string {
	t.Helper()
	p := defaultPayload()
	p["iat"] = float64(now.Unix())
	p["exp"] = float64(now.Add(exp).Unix())
	if nbf != 0 {
		p["nbf"] = float64(now.Add(nbf).Unix())
	}
	return signToken(t, key, defaultHeader(key), p)
}

// TestClockSkewOnExp: the issuer's clock and this node's differ, so a token
// stays good for the tolerance past its exp. The tolerance itself is
// admitted and a second past it is not.
func TestClockSkewOnExp(t *testing.T) {
	key := genKey(t)
	now := time.Unix(time.Now().Unix(), 0)
	freezeClock(t, now)
	tok := at(t, key, now, -30*time.Second, 0)

	if _, err := testValidator(t, key).Validate(tok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("with no skew: err = %v, want ErrTokenExpired", err)
	}
	skewed := testValidator(t, key, func(c *Config) { c.ClockSkew = 60 * time.Second })
	if _, err := skewed.Validate(tok); err != nil {
		t.Fatalf("30s past exp under a 60s skew was refused: %v", err)
	}
	if _, err := skewed.Validate(at(t, key, now, -60*time.Second, 0)); err != nil {
		t.Fatalf("exactly at the skew was refused: %v", err)
	}
	if _, err := skewed.Validate(at(t, key, now, -61*time.Second, 0)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("a second past the skew: err = %v, want ErrTokenExpired", err)
	}
}

// TestClockSkewOnNbf: the same tolerance, in the other direction, on a
// token that is not valid yet.
func TestClockSkewOnNbf(t *testing.T) {
	key := genKey(t)
	now := time.Unix(time.Now().Unix(), 0)
	freezeClock(t, now)
	tok := at(t, key, now, time.Hour, 30*time.Second)

	if _, err := testValidator(t, key).Validate(tok); !errors.Is(err, ErrTokenNotValidYet) {
		t.Fatalf("with no skew: err = %v, want ErrTokenNotValidYet", err)
	}
	skewed := testValidator(t, key, func(c *Config) { c.ClockSkew = 60 * time.Second })
	if _, err := skewed.Validate(tok); err != nil {
		t.Fatalf("30s before nbf under a 60s skew was refused: %v", err)
	}
	if _, err := skewed.Validate(at(t, key, now, time.Hour, 60*time.Second)); err != nil {
		t.Fatalf("exactly at the skew was refused: %v", err)
	}
	if _, err := skewed.Validate(at(t, key, now, time.Hour, 61*time.Second)); !errors.Is(err, ErrTokenNotValidYet) {
		t.Fatalf("a second before the skew: err = %v, want ErrTokenNotValidYet", err)
	}
}

// TestClockSkewDefaultIsNone: a caller that configures no skew gets none,
// so nothing it verified before verifies differently.
func TestClockSkewDefaultIsNone(t *testing.T) {
	key := genKey(t)
	now := time.Unix(time.Now().Unix(), 0)
	freezeClock(t, now)
	if _, err := testValidator(t, key).Validate(at(t, key, now, -time.Second, 0)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

// TestClockSkewDoesNotReachTheAgeBound: the skew is a tolerance between two
// clocks on the envelope, not on how long a token stays a credential. The
// age is measured against this node's clock alone.
func TestClockSkewDoesNotReachTheAgeBound(t *testing.T) {
	key := genKey(t)
	now := time.Unix(time.Now().Unix(), 0)
	freezeClock(t, now)
	p := defaultPayload()
	p["iat"] = float64(now.Add(-DefaultMaxTokenAge - 30*time.Second).Unix())
	p["exp"] = float64(now.Add(time.Hour).Unix())
	tok := signToken(t, key, defaultHeader(key), p)

	v := testValidator(t, key, func(c *Config) { c.ClockSkew = 60 * time.Second })
	if _, err := v.Validate(tok); !errors.Is(err, ErrTokenTooOld) {
		t.Fatalf("err = %v, want ErrTokenTooOld: the skew must not widen the age bound", err)
	}
}

// TestClockSkewIsNotAppliedToALocalToken: a token this process minted was
// stamped on this clock, so there are no two clocks to reconcile. It is
// expired a second after its exp whatever skew the issuers get.
func TestClockSkewIsNotAppliedToALocalToken(t *testing.T) {
	remote := genKey(t)
	srv := serveJWKS(t, remote)
	key := localKey(t)
	now := time.Unix(time.Now().Unix(), 0)
	freezeClock(t, now)
	v := New(Config{
		JWKSURL: srv.URL, CacheTTL: time.Hour, ClockSkew: 60 * time.Second,
		LocalIssuer: localIssuer, LocalKey: &key.PublicKey, LocalKeyID: "node-1",
	})

	p := defaultPayload()
	p["iss"] = localIssuer
	p["iat"] = float64(now.Unix())
	p["exp"] = float64(now.Add(-30 * time.Second).Unix())
	tok := signES256(t, key, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "node-1"}, p)

	if _, err := v.Validate(tok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired: a local token gets no skew", err)
	}
	// The same token under the issuer's skew, minted for the issuer, is fine.
	if _, err := v.Validate(at(t, remote, now, -30*time.Second, 0)); err != nil {
		t.Fatalf("an issuer's token 30s past exp was refused under a 60s skew: %v", err)
	}
}
