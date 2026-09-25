// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// actorIssuer is an issuer that mints actor tokens: it records every mint,
// checks the session token it was shown, and refuses an audience it does
// not know the way auth does.
func actorIssuer(t *testing.T, session string, known ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var mints atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/actor-tokens" || r.Method != http.MethodPost {
			http.Error(w, r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+session {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Audience string `json:"audience"`
			TTL      int    `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TTL != 300 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if slices.Contains(known, body.Audience) {
			n := mints.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"actor_token": body.Audience + "-token-" + strconv.Itoa(int(n)),
				"expires_in":  300,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_target","message":"audience ` + body.Audience + ` is not one this client may mint for"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &mints
}

func actorClient(t *testing.T, authURL string) (*Client, *time.Time) {
	t.Helper()
	c := New(Config{AuthURL: authURL, ClientID: "cid", ClientSecret: "sec", RedirectURL: "https://app.test/cb"})
	if c == nil {
		t.Fatal("New returned nil")
	}
	clock := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c.actors.now = func() time.Time { return clock }
	return c, &clock
}

// One mint per session and audience, reused until 30 s before it lapses;
// a second audience is its own token; a second session is its own token.
func TestActorTokenIsMintedOncePerAudienceUntilNearExpiry(t *testing.T) {
	srv, mints := actorIssuer(t, "session-1", "origo", "lux")
	c, clock := actorClient(t, srv.URL)
	sess := &Session{AccessToken: "session-1"}
	ctx := context.Background()

	first, expiry, err := c.ActorToken(ctx, sess, "origo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "origo-token-") {
		t.Fatalf("token = %q", first)
	}
	if got := expiry.Sub(*clock); got != 300*time.Second {
		t.Errorf("expiry is %v from now, want the issuer's 300s on our clock", got)
	}
	for range 5 {
		again, _, err := c.ActorToken(ctx, sess, "origo")
		if err != nil || again != first {
			t.Fatalf("reuse: %q %v, want %q", again, err, first)
		}
	}
	if mints.Load() != 1 {
		t.Fatalf("mints = %d after repeated calls, want 1", mints.Load())
	}

	if _, _, err := c.ActorToken(ctx, sess, "lux"); err != nil {
		t.Fatal(err)
	}
	if mints.Load() != 2 {
		t.Fatalf("mints = %d after a second audience, want 2", mints.Load())
	}

	*clock = clock.Add(269 * time.Second)
	if again, _, _ := c.ActorToken(ctx, sess, "origo"); again != first {
		t.Fatalf("31s before expiry the token is still good, got %q", again)
	}
	*clock = clock.Add(2 * time.Second)
	renewed, _, err := c.ActorToken(ctx, sess, "origo")
	if err != nil {
		t.Fatal(err)
	}
	if renewed == first || mints.Load() != 3 {
		t.Fatalf("29s before expiry a new token is minted: got %q, mints = %d", renewed, mints.Load())
	}

	other := &Session{AccessToken: "session-2"}
	if _, _, err := c.ActorToken(ctx, other, "origo"); err == nil {
		t.Fatal("a second session must present its own token to the issuer, which this issuer refuses")
	}
}

// The issuer's refusal reaches the caller with its reason, and nothing is
// cached for it.
func TestActorTokenRefusalCarriesTheIssuersReason(t *testing.T) {
	srv, mints := actorIssuer(t, "session-1", "origo")
	c, _ := actorClient(t, srv.URL)
	sess := &Session{AccessToken: "session-1"}

	_, _, err := c.ActorToken(context.Background(), sess, "arca")
	if err == nil || !strings.Contains(err.Error(), "invalid_target") || !strings.Contains(err.Error(), "arca") {
		t.Fatalf("err = %v, want the issuer's invalid_target for arca", err)
	}
	if mints.Load() != 0 {
		t.Errorf("mints = %d, want none", mints.Load())
	}
	if _, _, err := c.ActorToken(context.Background(), nil, "origo"); err == nil {
		t.Error("no session must be refused before any call")
	}
	if _, _, err := MintActorToken(context.Background(), srv.URL, "session-1", ""); err == nil {
		t.Error("an empty audience must be refused before any call")
	}
	var nilClient *Client
	if _, _, err := nilClient.ActorToken(context.Background(), sess, "origo"); err == nil {
		t.Error("a nil client must return an error")
	}
}
