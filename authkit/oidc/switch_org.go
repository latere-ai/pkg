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
	"net/url"
	"strings"
	"time"
)

// ErrSwitchOrgRefused is the issuer refusing a context switch: the person is
// not a member of the organization, the refresh token is no longer valid, or
// the client may not switch. The session is unchanged.
var ErrSwitchOrgRefused = errors.New("oidc: the issuer refused the context switch")

// SwitchOrg moves sess into another context without a second sign-in: it
// spends sess's refresh token with the org_id parameter the latere issuer
// honors on the refresh-token grant, and answers the session that results.
// orgID is the organization to act in, and "" is the personal context. The
// issuer checks the membership; a refusal is [ErrSwitchOrgRefused] and sess
// is left as it was.
//
// The answer carries the new access token, its expiry, the rotated refresh
// token when the issuer rotated it, and the organization and roles the new
// token names. The caller persists it with [Client.SetSession]. Actor tokens
// minted afterwards through [Client.ActorToken] carry the new context,
// because they copy the membership of the token they are minted from.
func (c *Client) SwitchOrg(ctx context.Context, sess *Session, orgID string) (*Session, error) {
	if c == nil {
		return nil, errors.New("oidc: client is nil")
	}
	if sess == nil || sess.RefreshToken == "" {
		return nil, errors.New("oidc: switch org: the session holds no refresh token")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {sess.RefreshToken},
		// Sent even when empty: the issuer reads a present, empty org_id
		// as the personal context and an absent one as no switch.
		"org_id": {orgID},
	}
	if c.cfg.ClientSecret == "" {
		form.Set("client_id", c.cfg.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.cfg.AuthURL, "/")+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc: switch org: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	}
	resp, err := httpDo(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: switch org: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oidc: switch org: read the answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrSwitchOrgRefused, resp.StatusCode)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("oidc: switch org: decode the answer: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("oidc: switch org: the answer carries no access token")
	}
	claims, err := decodeJWTClaims(tok.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: switch org: %w", err)
	}

	next := *sess
	next.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		next.RefreshToken = tok.RefreshToken
	}
	now := time.Now().UTC()
	next.Expiry = now.Add(15 * time.Minute)
	if tok.ExpiresIn > 0 {
		next.Expiry = now.Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	if !sess.IssuedAt.IsZero() {
		next.IssuedAt = now
	}
	next.User.OrgID = claims.OrgID
	next.User.Roles = append([]string{}, claims.Roles...)
	return &next, nil
}
