// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	pkgotel "latere.ai/x/pkg/otel"
)

// DefaultTokenSkew is how far ahead of expiry [OAuthClientCredentials]
// refreshes a token when Skew is zero.
const DefaultTokenSkew = 30 * time.Second

// DefaultMintTimeout bounds one token request when
// [OAuthClientCredentials.MintTimeout] is zero.
const DefaultMintTimeout = 30 * time.Second

// maxTokenResponse caps how much of a token response is read. A real token
// response is a few hundred bytes; the cap keeps a misbehaving endpoint from
// filling memory.
const maxTokenResponse = 1 << 20

// ErrNoValidToken is returned by [OAuthClientCredentials.Resolve] when the
// mint failed and no still-valid token is cached. It wraps the mint error.
var ErrNoValidToken = errors.New("egress: no valid access token")

// OAuthClientCredentials mints an access token by the OAuth 2.0
// client_credentials grant (RFC 6749 section 4.4) and is the built-in
// [Entry.Resolve]. Use it by pointer, one value per entry:
//
//	cc := &egress.OAuthClientCredentials{TokenURL: u, ClientID: id, ClientSecret: sec}
//	egress.Entry{Placeholder: ph, AllowedHosts: hosts, Resolve: cc.Resolve}
//
// The token is cached until Skew before its expiry, then re-minted on the
// next Resolve. Concurrent callers share one in-flight mint. When a mint
// fails and the cached token is still valid, the cached token is served;
// when nothing valid is cached the error is returned, wrapping
// [ErrNoValidToken]. A response without expires_in is served once and not
// cached, so a token whose lifetime is unknown is never served stale.
//
// The client authenticates with HTTP Basic as RFC 6749 section 2.3.1
// prescribes: id and secret form-urlencoded, then base64. Scope and Audience
// are sent as the scope and audience form fields when non-empty.
type OAuthClientCredentials struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scope        string // space-separated, optional
	Audience     string // optional; the audience form field some servers require

	// Skew is how far ahead of expiry a refresh starts. Default
	// [DefaultTokenSkew].
	Skew time.Duration
	// MintTimeout bounds one token request. The mint runs detached from the
	// caller's context so a cancelled caller does not fail the callers that
	// share the mint. Default [DefaultMintTimeout].
	MintTimeout time.Duration
	// HTTPClient sends the token request. Default: an instrumented client
	// over [http.DefaultTransport], as every outbound call in this module.
	HTTPClient *http.Client
	// Now is the clock. Default [time.Now].
	Now func() time.Time

	mu     sync.Mutex
	token  string
	expiry time.Time
	call   *mintCall // the in-flight mint, or nil
}

// mintCall is one shared mint: waiters block on done, then read the result.
type mintCall struct {
	done chan struct{}
	err  error
}

// Resolve returns the bare access token, minting or refreshing it as needed.
// ctx bounds only this caller's wait, not the mint itself.
func (c *OAuthClientCredentials) Resolve(ctx context.Context) ([]byte, error) {
	now := c.now()
	c.mu.Lock()
	if c.token != "" && now.Before(c.expiry.Add(-c.skew())) {
		tok := c.token
		c.mu.Unlock()
		return []byte(tok), nil
	}
	call := c.call
	if call == nil {
		call = &mintCall{done: make(chan struct{})}
		c.call = call
		go c.runMint(ctx, call)
	}
	c.mu.Unlock()

	select {
	case <-call.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if call.err == nil {
		return []byte(c.token), nil
	}
	if c.token != "" && c.now().Before(c.expiry) {
		// The refresh failed but the old token still has life in it.
		return []byte(c.token), nil
	}
	return nil, fmt.Errorf("%w: %w", ErrNoValidToken, call.err)
}

// runMint performs one token request and publishes the result to every
// waiter, then clears the in-flight slot so the next miss starts a new mint.
// The request keeps the leader's context values (tracing, for one) but not
// its cancellation: the mint serves every waiter, not just the leader.
func (c *OAuthClientCredentials) runMint(ctx context.Context, call *mintCall) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.mintTimeout())
	defer cancel()
	tok, lifetime, err := c.mint(ctx)

	c.mu.Lock()
	if err == nil {
		c.token = tok
		// A missing lifetime expires the token as it is issued: it is served
		// to this mint's waiters and never from cache.
		c.expiry = c.now().Add(lifetime)
	}
	call.err = err
	c.call = nil
	c.mu.Unlock()
	close(call.done)
}

// mint sends the client_credentials request and parses the response.
func (c *OAuthClientCredentials) mint(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if c.Scope != "" {
		form.Set("scope", c.Scope)
	}
	if c.Audience != "" {
		form.Set("audience", c.Audience)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode/100 != 2 {
		return "", 0, fmt.Errorf("token endpoint: %s: %s", resp.Status, tokenErrorText(body))
	}
	return parseTokenResponse(body)
}

// tokenResponse is the RFC 6749 section 5.1 success body. expires_in is a
// number by the RFC and a string on some servers, so it is decoded loosely.
type tokenResponse struct {
	AccessToken string          `json:"access_token"`
	TokenType   string          `json:"token_type"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
}

// parseTokenResponse returns the bare token and its lifetime. A missing or
// zero expires_in yields a zero lifetime. A token_type other than bearer is
// an error: the substituted value is the bare token and the request around
// it says "Bearer".
func parseTokenResponse(body []byte) (string, time.Duration, error) {
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, errors.New("token response: missing access_token")
	}
	if tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "bearer") {
		return "", 0, fmt.Errorf("token response: unsupported token_type %q", tr.TokenType)
	}
	lifetime, err := parseExpiresIn(tr.ExpiresIn)
	if err != nil {
		return "", 0, err
	}
	return tr.AccessToken, lifetime, nil
}

// parseExpiresIn accepts a JSON number, a quoted number, null, or nothing.
func parseExpiresIn(raw json.RawMessage) (time.Duration, error) {
	s := strings.TrimSpace(string(raw))
	s = strings.Trim(s, `"`)
	if s == "" || s == "null" {
		return 0, nil
	}
	secs, err := strconv.ParseFloat(s, 64)
	if err != nil || secs < 0 || secs > float64(1<<40) {
		return 0, fmt.Errorf("token response: invalid expires_in %q", s)
	}
	return time.Duration(secs * float64(time.Second)), nil
}

// tokenErrorText is the RFC 6749 section 5.2 error code and description when
// the failure body carries them, else a short excerpt of the body.
func tokenErrorText(body []byte) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		if e.Description != "" {
			return e.Error + ": " + e.Description
		}
		return e.Error
	}
	const max = 200
	s := strings.TrimSpace(string(body))
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

func (c *OAuthClientCredentials) skew() time.Duration {
	if c.Skew > 0 {
		return c.Skew
	}
	return DefaultTokenSkew
}

func (c *OAuthClientCredentials) mintTimeout() time.Duration {
	if c.MintTimeout > 0 {
		return c.MintTimeout
	}
	return DefaultMintTimeout
}

// defaultTokenClient is the client every resolver without one shares.
var defaultTokenClient = &http.Client{Transport: pkgotel.Transport(nil)}

func (c *OAuthClientCredentials) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return defaultTokenClient
}

func (c *OAuthClientCredentials) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
