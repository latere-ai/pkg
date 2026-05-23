package authkit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RegisterAgentRequest carries the fields for POST {auth}/agents.
type RegisterAgentRequest struct {
	OrgID         string   `json:"org_id"`
	AgentType     string   `json:"agent_type"`
	Description   string   `json:"description"`
	MaxScopes     []string `json:"max_scopes"`
	DefaultScopes []string `json:"default_scopes"`
}

// Package-level HTTP client variable. Tests can swap it for an httptest-backed
// client to exercise all code paths without network calls.
var exchangeHTTPClient = &http.Client{Timeout: 10 * time.Second}

// ExchangeForAgent performs an RFC 8693 token exchange to obtain an
// agent-scoped token. authBaseURL is the auth service root
// (e.g. "https://auth.latere.ai"). userJWT is the acting user's bearer token.
// agentID is the agent's principal_id returned by RegisterAgentPrincipal.
//
// Calls POST {authBaseURL}/token with the token-exchange grant. Returns the
// access_token string on success.
func ExchangeForAgent(ctx context.Context, authBaseURL, userJWT, agentID string) (string, error) {
	authBaseURL = strings.TrimRight(authBaseURL, "/")
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {userJWT},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"agent_id":           {agentID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		authBaseURL+"/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("exchange: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := exchangeHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("exchange: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return "", fmt.Errorf("exchange: status %d: %s", resp.StatusCode, errBody.Error)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("exchange: decode: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("exchange: empty access_token in response")
	}
	return tok.AccessToken, nil
}

// RegisterAgentPrincipal calls POST {authBaseURL}/agents to register a new
// agent principal. userJWT must have permission to create agents in the
// target org. Returns the principal_id of the newly created agent.
func RegisterAgentPrincipal(ctx context.Context, authBaseURL, userJWT string, req RegisterAgentRequest) (string, error) {
	authBaseURL = strings.TrimRight(authBaseURL, "/")
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("register agent: marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		authBaseURL+"/agents",
		strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("register agent: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+userJWT)

	resp, err := exchangeHTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("register agent: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return "", fmt.Errorf("register agent: status %d: %s", resp.StatusCode, errBody.Error)
	}

	var out struct {
		PrincipalID string `json:"principal_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("register agent: decode: %w", err)
	}
	if out.PrincipalID == "" {
		return "", fmt.Errorf("register agent: empty principal_id in response")
	}
	return out.PrincipalID, nil
}
