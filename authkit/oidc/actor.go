// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ActorTokenLifetime is the lifetime asked of the issuer for every actor
// token: the most it grants. A caller holds the token for one request or a
// short run of them and the cache below mints again before it lapses, so
// there is nothing a shorter request would gain.
const ActorTokenLifetime = 300 * time.Second

// actorTokenRenewal is how long before expiry a cached actor token is
// replaced: enough for the request it is attached to, and its retries, to
// reach the product before the token lapses.
const actorTokenRenewal = 30 * time.Second

// MintActorToken asks the issuer for a token addressed to one product for
// the person accessToken proves. It posts to /actor-tokens with the session
// token and returns the actor token and when it expires. The issuer mints
// only for an audience the client is registered to act at; any other is
// refused, and the error carries the issuer's reason.
//
// This is the one way a service acts for a person at another service in
// the family: the session token is addressed to the issuer and opens
// nothing else, and the actor token is addressed to the product and opens
// nothing else.
func MintActorToken(ctx context.Context, authURL, accessToken, audience string) (string, time.Time, error) {
	token, lifetime, err := mintActorToken(ctx, authURL, accessToken, audience)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, time.Now().Add(lifetime), nil
}

// mintActorToken is MintActorToken with the lifetime the issuer granted,
// so a caller with its own clock places the expiry on it.
func mintActorToken(ctx context.Context, authURL, accessToken, audience string) (string, time.Duration, error) {
	if audience == "" {
		return "", 0, errors.New("oidc: actor token: audience is required")
	}
	body, err := json.Marshal(map[string]any{
		"audience":    audience,
		"ttl_seconds": int(ActorTokenLifetime / time.Second),
	})
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(authURL, "/")+"/actor-tokens", strings.NewReader(string(body)))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpDo(req)
	if err != nil {
		return "", 0, fmt.Errorf("oidc: actor token for %s: %w", audience, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		reason, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return "", 0, fmt.Errorf("oidc: actor token for %s: %d: %s", audience, resp.StatusCode, strings.TrimSpace(string(reason)))
	}
	var out struct {
		ActorToken string `json:"actor_token"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("oidc: actor token for %s: decode: %w", audience, err)
	}
	if out.ActorToken == "" || out.ExpiresIn <= 0 {
		return "", 0, fmt.Errorf("oidc: actor token for %s: the issuer returned no token", audience)
	}
	return out.ActorToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

// actorKey names one cached actor token: the session token it was minted
// with and the product it is addressed to. A new login is a new session
// token and so a new key; the old entries lapse with their expiry.
type actorKey struct{ session, audience string }

type actorEntry struct {
	token  string
	expiry time.Time
}

// ActorToken returns a token addressed to audience for the person sess
// holds, minting through [MintActorToken] once per session and audience
// and reusing it until shortly before it expires. A service calls it on
// every request to a product and pays the mint at most once per lifetime.
func (c *Client) ActorToken(ctx context.Context, sess *Session, audience string) (string, time.Time, error) {
	if c == nil {
		return "", time.Time{}, errors.New("oidc: client is nil")
	}
	if sess == nil || sess.AccessToken == "" {
		return "", time.Time{}, errors.New("oidc: actor token: no session")
	}
	key := actorKey{sess.AccessToken, audience}
	now := c.actors.now()
	c.actors.mu.Lock()
	if e, ok := c.actors.tokens[key]; ok && now.Before(e.expiry.Add(-actorTokenRenewal)) {
		c.actors.mu.Unlock()
		return e.token, e.expiry, nil
	}
	c.actors.mu.Unlock()

	token, lifetime, err := mintActorToken(ctx, c.cfg.AuthURL, sess.AccessToken, audience)
	if err != nil {
		return "", time.Time{}, err
	}
	expiry := now.Add(lifetime)

	c.actors.mu.Lock()
	defer c.actors.mu.Unlock()
	if c.actors.tokens == nil {
		c.actors.tokens = map[actorKey]actorEntry{}
	}
	for k, e := range c.actors.tokens {
		if !now.Before(e.expiry) {
			delete(c.actors.tokens, k)
		}
	}
	c.actors.tokens[key] = actorEntry{token: token, expiry: expiry}
	return token, expiry, nil
}

// actorCache is the state ActorToken keeps on a Client.
type actorCache struct {
	mu     sync.Mutex
	tokens map[actorKey]actorEntry
	// now is the clock ActorToken reads; a test sets it.
	now func() time.Time
}
