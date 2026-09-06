// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"latere.ai/x/pkg/authkit"
)

// makeRichJWT builds an unsigned JWT whose payload is the given claims, allowing
// array and bool claims (roles, scopes, is_superadmin) that makeJWT can't carry.
func makeRichJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestDecodeJWTClaimsSuperset(t *testing.T) {
	jwt := makeRichJWT(map[string]any{
		"sub": "u1", "email": "a@b.com", "name": "Alice",
		"display_name": "Ali", "picture": "https://p/x", "avatar_url": "https://p/y",
		"org_id": "org1", "azp": "client-xyz", "scope": "openid email cella:run",
		"roles": []string{"owner", "admin"}, "is_superadmin": true,
	})
	c, err := decodeJWTClaims(jwt)
	if err != nil {
		t.Fatalf("decodeJWTClaims: %v", err)
	}
	if c.Name != "Alice" || c.DisplayName != "Ali" || c.AvatarURL != "https://p/y" {
		t.Errorf("name claims = %+v", c)
	}
	if c.AuthorizedParty != "client-xyz" || c.ClientID != "" {
		t.Errorf("azp/client_id = %q/%q", c.AuthorizedParty, c.ClientID)
	}
	if c.Scope != "openid email cella:run" || !c.IsSuperadmin {
		t.Errorf("scope/superadmin = %q/%v", c.Scope, c.IsSuperadmin)
	}
	if len(c.Roles) != 2 || c.Roles[0] != "owner" {
		t.Errorf("roles = %v", c.Roles)
	}
}

func TestSessionFromToken(t *testing.T) {
	exp := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	jwt := makeRichJWT(map[string]any{
		"sub": "u1", "email": "a@b.com", "name": "Alice",
		"display_name": "Ali", "picture": "https://p/x", "avatar_url": "https://p/y",
		"org_id": "org1", "azp": "client-xyz", "scope": "openid cella:run",
		"roles": []string{"owner"}, "is_superadmin": true,
	})
	tok := &oauth2.Token{AccessToken: jwt, RefreshToken: "rt", Expiry: exp}

	sess := SessionFromToken(tok, 30*24*time.Hour)
	u := sess.User
	if u.Sub != "u1" || u.Email != "a@b.com" || u.Name != "Alice" {
		t.Errorf("identity = %+v", u)
	}
	if u.DisplayName != "Ali" {
		t.Errorf("DisplayName = %q, want Ali", u.DisplayName)
	}
	if u.Picture != "https://p/x" {
		t.Errorf("picture = %q, want the picture claim over avatar_url", u.Picture)
	}
	if u.PrincipalType != authkit.PrincipalUser {
		t.Errorf("PrincipalType = %q, want user", u.PrincipalType)
	}
	if u.ClientID != "client-xyz" {
		t.Errorf("ClientID = %q, want client-xyz (from azp)", u.ClientID)
	}
	if len(u.Scopes) != 2 || u.Scopes[1] != "cella:run" {
		t.Errorf("Scopes = %v", u.Scopes)
	}
	if !u.IsSuperadmin || len(u.Roles) != 1 || u.Roles[0] != "owner" {
		t.Errorf("superadmin/roles = %v/%v", u.IsSuperadmin, u.Roles)
	}
	if !sess.Expiry.Equal(exp) {
		t.Errorf("Expiry = %v, want %v", sess.Expiry, exp)
	}
	if sess.IssuedAt.IsZero() || sess.SessionExpiry.IsZero() {
		t.Errorf("IssuedAt=%v SessionExpiry=%v, both should be set", sess.IssuedAt, sess.SessionExpiry)
	}
}

// TestDefaultConfigSessionJSONOmitsTimeFields checks the SERIALIZED cookie
// bytes (not just in-memory IsZero): with no TTL the session must not carry
// iat/sexp at all, so existing relying-party cookies stay shape-identical. A
// configured TTL must include sexp. Guards against the time.Time omitempty
// no-op (omitzero is required, and IssuedAt must not be stamped for ttl<=0).
func TestDefaultConfigSessionJSONOmitsTimeFields(t *testing.T) {
	jwt := makeRichJWT(map[string]any{"sub": "u1"})

	def, _ := json.Marshal(SessionFromToken(&oauth2.Token{AccessToken: jwt}, 0))
	if s := string(def); strings.Contains(s, `"iat"`) || strings.Contains(s, `"sexp"`) {
		t.Errorf("default-config session JSON must omit iat/sexp, got: %s", s)
	}

	conf, _ := json.Marshal(SessionFromToken(&oauth2.Token{AccessToken: jwt}, time.Hour))
	if s := string(conf); !strings.Contains(s, `"sexp"`) || !strings.Contains(s, `"iat"`) {
		t.Errorf("configured session JSON must include iat/sexp, got: %s", s)
	}
}

func TestSessionFromTokenNoTTLNoSessionExpiry(t *testing.T) {
	jwt := makeRichJWT(map[string]any{"sub": "u1"})
	sess := SessionFromToken(&oauth2.Token{AccessToken: jwt}, 0)
	if !sess.SessionExpiry.IsZero() {
		t.Errorf("SessionExpiry = %v, want zero for ttl<=0", sess.SessionExpiry)
	}
	// Zero token expiry falls back to a short default, never zero.
	if sess.Expiry.IsZero() {
		t.Error("Expiry should fall back to a non-zero default")
	}
}

func TestSessionFromTokenFallbacks(t *testing.T) {
	// Only name + avatar_url present: DisplayName falls back to name, Picture
	// to the legacy avatar_url claim.
	jwt := makeRichJWT(map[string]any{"sub": "u1", "name": "Bob", "avatar_url": "https://p/b"})
	u := SessionFromToken(&oauth2.Token{AccessToken: jwt}, 0).User
	if u.DisplayName != "Bob" {
		t.Errorf("DisplayName = %q, want Bob (fallback to name)", u.DisplayName)
	}
	if u.Picture != "https://p/b" {
		t.Errorf("Picture = %q, want avatar_url fallback", u.Picture)
	}
}

func TestSessionFromTokenNonJWT(t *testing.T) {
	// A non-JWT access token yields an empty identity, not a panic.
	sess := SessionFromToken(&oauth2.Token{AccessToken: "opaque"}, time.Hour)
	if sess.User.Sub != "" {
		t.Errorf("Sub = %q, want empty for non-JWT", sess.User.Sub)
	}
	if sess.AccessToken != "opaque" {
		t.Errorf("AccessToken = %q", sess.AccessToken)
	}
}

// TestHandleCallbackPopulatesSupersetFields proves login through HandleCallback
// surfaces the new fields end-to-end (via the default-config client, ttl=0).
func TestHandleCallbackPopulatesSupersetFields(t *testing.T) {
	jwt := makeRichJWT(map[string]any{
		"sub": "user1", "email": "user@test.com", "azp": "cella-dashboard",
		"scope": "openid cella:run", "roles": []string{"admin"}, "is_superadmin": true,
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": jwt, "token_type": "Bearer", "refresh_token": "rt-123", "expires_in": 3600,
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	}))
	defer ts.Close()

	c := New(Config{AuthURL: ts.URL, ClientID: "cid", ClientSecret: "sec", RedirectURL: "https://app.example.com/callback"})

	wSetup := httptest.NewRecorder()
	if err := c.SetFlowState(wSetup, &FlowState{CodeVerifier: "v", State: "s", ReturnTo: "/dashboard"}); err != nil {
		t.Fatalf("SetFlowState: %v", err)
	}
	r := httptest.NewRequest("GET", "/callback?code=authcode&state=s", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	c.HandleCallback(w, r)

	r2 := httptest.NewRequest("GET", "/", nil)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == SessionCookieName {
			r2.AddCookie(ck)
		}
	}
	sess, err := c.GetSession(r2)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.User.ClientID != "cella-dashboard" || !sess.User.IsSuperadmin {
		t.Errorf("superset fields not populated: %+v", sess.User)
	}
	if len(sess.User.Scopes) != 2 || len(sess.User.Roles) != 1 {
		t.Errorf("scopes/roles = %v / %v", sess.User.Scopes, sess.User.Roles)
	}
	// Default-config client (ttl=0) must not stamp SessionExpiry.
	if !sess.SessionExpiry.IsZero() {
		t.Errorf("SessionExpiry = %v, want zero for default config", sess.SessionExpiry)
	}
}
