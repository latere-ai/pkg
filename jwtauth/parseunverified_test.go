package jwtauth

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"
)

// unsignedToken builds a well-formed three-segment JWT whose signature
// is junk. ParseUnverified must not care about the signature.
func unsignedToken(payload map[string]any) string {
	return b64(map[string]any{"alg": "RS256"}) + "." + b64(payload) + ".not-a-real-signature"
}

func TestParseUnverified_HappyPath(t *testing.T) {
	tok := unsignedToken(map[string]any{
		"sub":            "user-1",
		"email":          "a@b.co",
		"principal_type": "user",
		"org_id":         "org-9",
		"client_id":      "lux-dashboard",
		"is_superadmin":  true,
		"scp":            []string{"llm.read", "llm.invoke", "llm.admin"},
		"roles":          []string{"admin"},
		"exp":            float64(time.Now().Add(time.Hour).Unix()),
	})
	c, err := ParseUnverified(tok)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if c.Sub != "user-1" || c.Email != "a@b.co" || c.OrgID != "org-9" {
		t.Errorf("identity = %+v", c)
	}
	if c.PrincipalType != PrincipalUser || !c.IsSuperadmin {
		t.Errorf("principal = %v superadmin=%v", c.PrincipalType, c.IsSuperadmin)
	}
	if c.ClientID != "lux-dashboard" {
		t.Errorf("ClientID = %q, want lux-dashboard", c.ClientID)
	}
	if len(c.Scopes) != 3 || c.Scopes[0] != "llm.read" {
		t.Errorf("Scopes = %v, want [llm.read llm.invoke llm.admin]", c.Scopes)
	}
	if c.Exp.IsZero() {
		t.Error("Exp not populated")
	}
}

func TestParseUnverified_GrantorID(t *testing.T) {
	// Flat grantor_id (auth's agent/actor wire shape) maps to Claims.
	c, err := ParseUnverified(unsignedToken(map[string]any{
		"sub":            "agent-1",
		"principal_type": "agent",
		"grantor_id":     "owner-9",
		"exp":            float64(time.Now().Add(time.Hour).Unix()),
	}))
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if c.GrantorID != "owner-9" {
		t.Errorf("GrantorID = %q, want owner-9", c.GrantorID)
	}
	// Nested act.sub also populates GrantorID when grantor_id is absent.
	c2, err := ParseUnverified(unsignedToken(map[string]any{
		"sub": "agent-1",
		"act": map[string]any{"sub": "owner-7"},
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}))
	if err != nil {
		t.Fatalf("ParseUnverified act: %v", err)
	}
	if c2.GrantorID != "owner-7" {
		t.Errorf("GrantorID from act.sub = %q, want owner-7", c2.GrantorID)
	}
}

func TestParseUnverified_AgentID(t *testing.T) {
	// The flat agent_id claim (the reporting dimension on a delegated run)
	// maps to Claims.AgentID, distinct from the owner-bearing grantor_id.
	c, err := ParseUnverified(unsignedToken(map[string]any{
		"sub":            "owner-9",
		"principal_type": "agent",
		"grantor_id":     "owner-9",
		"agent_id":       "pr-agent-1",
		"exp":            float64(time.Now().Add(time.Hour).Unix()),
	}))
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if c.AgentID != "pr-agent-1" {
		t.Errorf("AgentID = %q, want pr-agent-1", c.AgentID)
	}
	// Ordinary tokens carry no agent_id.
	c2, err := ParseUnverified(unsignedToken(map[string]any{
		"sub": "user-1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}))
	if err != nil {
		t.Fatalf("ParseUnverified plain: %v", err)
	}
	if c2.AgentID != "" {
		t.Errorf("AgentID = %q, want empty for a non-agent token", c2.AgentID)
	}
}

func TestParseUnverified_Malformed(t *testing.T) {
	cases := map[string]string{
		"not three segments": "a.b",
		"bad base64 payload": "aaa.!!!.ccc",
		"payload not json":   b64(map[string]any{"alg": "RS256"}) + "." + base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".sig",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseUnverified(tok); err != ErrMalformedToken {
				t.Errorf("err = %v, want ErrMalformedToken", err)
			}
		})
	}
}

func TestParseUnverified_EmptySub(t *testing.T) {
	if _, err := ParseUnverified(unsignedToken(map[string]any{"email": "x@y.z"})); err != ErrMalformedToken {
		t.Errorf("err = %v, want ErrMalformedToken (empty sub)", err)
	}
}

func TestParseUnverified_ClientIDResolution(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{"client_id wins", map[string]any{"sub": "s", "client_id": "cid", "azp": "azpv"}, "cid"},
		{"azp fallback", map[string]any{"sub": "s", "azp": "azpv"}, "azpv"},
		{"neither", map[string]any{"sub": "s"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseUnverified(unsignedToken(tt.payload))
			if err != nil {
				t.Fatalf("ParseUnverified: %v", err)
			}
			if c.ClientID != tt.want {
				t.Errorf("ClientID = %q, want %q", c.ClientID, tt.want)
			}
		})
	}
}

// TestParseUnverified_NoJWKS is the security-contract regression:
// ParseUnverified must never perform network I/O. If it reaches for
// the JWKS endpoint this panics and fails the test.
func TestParseUnverified_NoJWKS(t *testing.T) {
	orig := httpGet
	t.Cleanup(func() { httpGet = orig })
	httpGet = func(string) (*http.Response, error) {
		panic("ParseUnverified must not fetch JWKS")
	}
	if _, err := ParseUnverified(unsignedToken(map[string]any{"sub": "s", "scp": []string{"llm.read"}})); err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
}

// TestParseUnverified_ExpiredStillParses documents the contract: an
// expired token Validate would reject is still decoded here, because
// the caller (a trusted session cookie) owns lifecycle policy.
func TestParseUnverified_ExpiredStillParses(t *testing.T) {
	tok := unsignedToken(map[string]any{
		"sub": "s",
		"scp": []string{"llm.read"},
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	})
	c, err := ParseUnverified(tok)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if !c.Exp.Before(time.Now()) {
		t.Error("expected Exp in the past")
	}
	if len(c.Scopes) != 1 || c.Scopes[0] != "llm.read" {
		t.Errorf("Scopes = %v", c.Scopes)
	}
}
