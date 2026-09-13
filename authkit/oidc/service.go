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
	"sync"
	"time"
)

// ServiceTokenLifetimeMargin is how long before a service token expires the
// source stops handing it out and mints again, so a token given to a
// caller is never within seconds of lapsing in flight.
const ServiceTokenLifetimeMargin = 30 * time.Second

// ClientCredentials asks the issuer for a service token: the client's own
// identity, minted with the client_credentials grant, addressed to
// audience. It is the credential a service presents when it acts as itself
// and not for a person (rule R5 of latere-ai/specs
// infrastructure/identity.md). An empty audience asks for a token the
// issuer's own API accepts; scopes, when given, are the ceiling the issuer
// intersects with the client's registry row. The client authenticates with
// HTTP Basic, the method every OAuth issuer accepts.
func ClientCredentials(ctx context.Context, authURL, clientID, clientSecret, audience string, scopes []string) (string, time.Time, error) {
	token, lifetime, err := clientCredentials(ctx, authURL, clientID, clientSecret, audience, scopes)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, time.Now().Add(lifetime), nil
}

func clientCredentials(ctx context.Context, authURL, clientID, clientSecret, audience string, scopes []string) (string, time.Duration, error) {
	if clientID == "" || clientSecret == "" {
		return "", 0, errors.New("oidc: service token: a client id and secret are required")
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if audience != "" {
		form.Set("audience", audience)
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(authURL, "/")+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := httpDo(req)
	if err != nil {
		return "", 0, fmt.Errorf("oidc: service token for %s: %w", clientID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		reason, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return "", 0, fmt.Errorf("oidc: service token for %s: %d: %s", clientID, resp.StatusCode, strings.TrimSpace(string(reason)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("oidc: service token for %s: decode: %w", clientID, err)
	}
	if out.AccessToken == "" || out.ExpiresIn <= 0 {
		return "", 0, fmt.Errorf("oidc: service token for %s: the issuer returned no token", clientID)
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

// ServiceTokenSource hands out one client's service token for one audience,
// minting through [ClientCredentials] and reusing the result until
// [ServiceTokenLifetimeMargin] before it expires. A service that calls
// another on its own behalf holds one per audience and asks it per call.
type ServiceTokenSource struct {
	authURL, clientID, clientSecret, audience string
	scopes                                    []string

	mu     sync.Mutex
	token  string
	expiry time.Time
	now    func() time.Time
	mint   func(ctx context.Context) (string, time.Duration, error)
}

// NewServiceTokenSource builds a source for one client and one audience.
func NewServiceTokenSource(authURL, clientID, clientSecret, audience string, scopes []string) *ServiceTokenSource {
	s := &ServiceTokenSource{authURL: authURL, clientID: clientID, clientSecret: clientSecret, audience: audience, scopes: scopes, now: time.Now}
	s.mint = func(ctx context.Context) (string, time.Duration, error) {
		return clientCredentials(ctx, s.authURL, s.clientID, s.clientSecret, s.audience, s.scopes)
	}
	return s
}

// Token returns the current service token, minting when none is held or
// the held one is within the margin of expiry.
func (s *ServiceTokenSource) Token(ctx context.Context) (string, error) {
	if s == nil {
		return "", errors.New("oidc: service token source is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Add(ServiceTokenLifetimeMargin).Before(s.expiry) {
		return s.token, nil
	}
	token, lifetime, err := s.mint(ctx)
	if err != nil {
		return "", err
	}
	s.token, s.expiry = token, s.now().Add(lifetime)
	return token, nil
}
