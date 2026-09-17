// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testClock is a clock a test moves. It is read concurrently by the key
// set, so it is guarded.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

// newTestClock starts a clock far from the wall clock, so a window read
// against time.Now instead of this one fails rather than passing by luck.
func newTestClock() *testClock {
	return &testClock{at: time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// clockToken is a token minted on the given instant: issued then, and
// valid for an hour after.
func clockToken(t *testing.T, key *rsa.PrivateKey, at time.Time, edit ...func(map[string]any)) string {
	t.Helper()
	p := map[string]any{
		"sub": "user-123",
		"iss": "https://auth.latere.ai",
		"aud": "my-client",
		"iat": float64(at.Unix()),
		"exp": float64(at.Add(time.Hour).Unix()),
	}
	for _, e := range edit {
		e(p)
	}
	return signToken(t, key, defaultHeader(key), p)
}

// TestConfigNowRunsTheClaimsWindowOnTheCallersClock: a token minted on the
// caller's clock verifies under that clock and expires when the clock
// moves past its "exp". Every window reads the one clock, so the same
// token that verifies at mint time is expired an hour and a second later,
// and the "iat" bound is measured there too rather than against real time.
func TestConfigNowRunsTheClaimsWindowOnTheCallersClock(t *testing.T) {
	clk := newTestClock()
	key := genKey(t)
	v := testValidator(t, key, func(c *Config) {
		c.Now = clk.Now
		c.RequireIssuedAt = true
	})

	tok := clockToken(t, key, clk.Now())
	claims, err := v.Validate(tok)
	if err != nil {
		t.Fatalf("a token minted on the caller's clock was refused: %v", err)
	}
	if claims.Sub != "user-123" {
		t.Fatalf("Sub = %q, want %q", claims.Sub, "user-123")
	}

	// Still inside the hour it was minted for.
	clk.advance(59 * time.Minute)
	if _, err := v.Validate(tok); err != nil {
		t.Fatalf("a token 59 minutes into its hour was refused: %v", err)
	}

	// Past its "exp" on that same clock.
	clk.advance(2 * time.Minute)
	if _, err := v.Validate(tok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("a token past its exp: err = %v, want ErrTokenExpired", err)
	}
}

// TestConfigNowMeasuresNbfAndAgeToo: the two remaining windows read the
// caller's clock. A token whose "nbf" is ahead of that clock is not yet
// valid and becomes valid when the clock reaches it, and a token older
// than MaxTokenAge on that clock is too old whatever "exp" it carries.
func TestConfigNowMeasuresNbfAndAgeToo(t *testing.T) {
	clk := newTestClock()
	key := genKey(t)
	v := testValidator(t, key, func(c *Config) { c.Now = clk.Now })

	start := clk.Now()
	notYet := clockToken(t, key, start, func(p map[string]any) {
		p["nbf"] = float64(start.Add(10 * time.Minute).Unix())
	})
	if _, err := v.Validate(notYet); !errors.Is(err, ErrTokenNotValidYet) {
		t.Fatalf("a token before its nbf: err = %v, want ErrTokenNotValidYet", err)
	}
	clk.advance(11 * time.Minute)
	if _, err := v.Validate(notYet); err != nil {
		t.Fatalf("a token past its nbf was refused: %v", err)
	}

	// The age bound is read on the same clock: a token issued a day and a
	// half before it, minted with an "exp" that is still ahead.
	old := clockToken(t, key, clk.Now().Add(-36*time.Hour), func(p map[string]any) {
		p["exp"] = float64(clk.Now().Add(time.Hour).Unix())
	})
	if _, err := v.Validate(old); !errors.Is(err, ErrTokenTooOld) {
		t.Fatalf("a token older than MaxTokenAge: err = %v, want ErrTokenTooOld", err)
	}
}

// TestConfigNowDrivesTheKeySetCache: the cache TTL is measured on the
// caller's clock, so a test that moves the clock past CacheTTL sees the
// refetch a node would see rather than waiting for it.
func TestConfigNowDrivesTheKeySetCache(t *testing.T) {
	clk := newTestClock()
	key := genKey(t)
	var hits atomic.Int64
	data := jwksJSON(t, key)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if _, err := w.Write(data); err != nil {
			t.Errorf("write JWKS: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	v := New(Config{JWKSURL: srv.URL, CacheTTL: time.Hour, Now: clk.Now})
	for range 3 {
		if _, err := v.Validate(clockToken(t, key, clk.Now())); err != nil {
			t.Fatalf("a token was refused: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("fetches within the TTL = %d, want 1", got)
	}

	clk.advance(2 * time.Hour)
	if _, err := v.Validate(clockToken(t, key, clk.Now())); err != nil {
		t.Fatalf("a token after the TTL elapsed was refused: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("fetches after the TTL elapsed = %d, want 2", got)
	}
}

// TestConfigNowDrivesTheForcedRefreshBackOff: a kid the set does not hold
// forces one refresh, and the window that bounds how often is measured on
// the caller's clock. Two unknown kids at one instant buy one forced
// refresh between them; moving the clock past the window buys another.
func TestConfigNowDrivesTheForcedRefreshBackOff(t *testing.T) {
	clk := newTestClock()
	key, absent := genKey(t), genKey(t)
	var hits atomic.Int64
	data := jwksJSON(t, key)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if _, err := w.Write(data); err != nil {
			t.Errorf("write JWKS: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	v := New(Config{JWKSURL: srv.URL, CacheTTL: time.Hour, Now: clk.Now})
	unknown := signToken(t, key, defaultHeader(absent), map[string]any{
		"sub": "user-123", "iat": float64(clk.Now().Unix()),
		"exp": float64(clk.Now().Add(time.Hour).Unix()),
	})

	// The first miss: one fetch to fill the cache, one forced by the miss.
	if _, err := v.Validate(unknown); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("fetches on the first unknown kid = %d, want 2", got)
	}

	// A second miss at the same instant is inside the back-off window.
	if _, err := v.Validate(unknown); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("fetches inside the back-off window = %d, want 2", got)
	}

	// Past the window on the caller's clock, the next miss forces again.
	clk.advance(minForcedRefreshInterval + time.Second)
	if _, err := v.Validate(unknown); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("fetches past the back-off window = %d, want 3", got)
	}
}

// TestNilConfigNowIsTheWallClock: a caller that supplies no clock is
// unchanged, on the validator and on a key set alike.
func TestNilConfigNowIsTheWallClock(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	if _, err := v.Validate(signToken(t, key, defaultHeader(key), defaultPayload())); err != nil {
		t.Fatalf("a token on the wall clock was refused: %v", err)
	}
	before := time.Now()
	got := (&jwksCache{}).now()
	if got.Before(before) || got.After(time.Now()) {
		t.Fatalf("a key set with no clock read %v, want an instant around now", got)
	}
}
