// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"latere.ai/x/pkg/authkit"
)

// A client acting for a person requests no audience: the issuer addresses
// the login token to itself, and products are reached with actor tokens.
// The parameter is sent only when the configuration names an audience.
func TestAuthorizeRequestsNoAudienceByDefault(t *testing.T) {
	base := Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	}
	c := New(base)
	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.cfg.Audience != "" {
		t.Errorf("Audience = %q, want none by default", c.cfg.Audience)
	}
	u, _ := url.Parse(c.AuthCodeURLWithOpts("state", "verifier", nil))
	if _, ok := u.Query()["audience"]; ok {
		t.Errorf("authorize URL carries audience=%q, want none", u.Query().Get("audience"))
	}

	base.Audience = "svc.example.com"
	u, _ = url.Parse(New(base).AuthCodeURLWithOpts("state", "verifier", nil))
	if got := u.Query().Get("audience"); got != "svc.example.com" {
		t.Errorf("audience = %q, want the configured one", got)
	}
}

// TestNew_ScopesDefault asserts the OIDC-minimum default kicks in
// when Config.Scopes is left empty, so basic /userinfo lookups work
// out of the box.
func TestNew_ScopesDefault(t *testing.T) {
	c := New(Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	})
	got := c.AuthCodeURLWithOpts("state", "verifier", nil)
	parsed, _ := url.Parse(got)
	scope := parsed.Query().Get("scope")
	if !strings.Contains(scope, "openid") || !strings.Contains(scope, "email") || !strings.Contains(scope, "profile") {
		t.Errorf("default scope = %q, want to contain openid/email/profile", scope)
	}
}

// TestNew_ScopesOverride asserts Config.Scopes wins when set, so
// product RPs can request offline_access or product-specific scopes.
func TestNew_ScopesOverride(t *testing.T) {
	c := New(Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
		Scopes:       []string{"openid", "offline_access", "read:resource"},
	})
	got := c.AuthCodeURLWithOpts("state", "verifier", nil)
	parsed, _ := url.Parse(got)
	scope := parsed.Query().Get("scope")
	if !strings.Contains(scope, "offline_access") || !strings.Contains(scope, "read:resource") {
		t.Errorf("scope = %q, want override scopes", scope)
	}
	// Default scopes (email, profile) should be dropped — caller
	// is in charge once they set Scopes explicitly.
	if strings.Contains(scope, "email") || strings.Contains(scope, "profile") {
		t.Errorf("scope = %q, override should replace default not extend", scope)
	}
}

func TestNew_AudienceExplicit(t *testing.T) {
	c := New(Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
		Audience:     "sandboxd",
	})
	if got := c.cfg.Audience; got != "sandboxd" {
		t.Errorf("Audience = %q, want explicit override", got)
	}
}

func TestAuthURLParams_PreservesPresentEmptyKeys(t *testing.T) {
	// A present-but-empty value (org_id="") must round-trip — it is the auth
	// service's switch-to-personal signal. A key present with a nil value slice
	// (the defensive len(vs)==0 branch) must also forward as an empty param.
	c := New(Config{
		AuthURL:     "https://auth.example.com",
		ClientID:    "cid",
		RedirectURL: "https://app.example.com/cb",
		CookieKey:   "0123456789abcdef0123456789abcdef",
	})
	authURL := c.AuthCodeURLWithOpts("state", "verifier", url.Values{
		"org_id": {""},  // present-but-empty value
		"empty":  nil,   // present key, no values -> len(vs)==0 branch
		"scope":  {"a"}, // ordinary value
	})
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := parsed.Query()
	for _, k := range []string{"org_id", "empty", "scope"} {
		if !q.Has(k) {
			t.Errorf("param %q dropped from authorize URL: %s", k, authURL)
		}
	}
	if got := q.Get("scope"); got != "a" {
		t.Errorf("scope = %q, want a", got)
	}
}

// TestHandleLogin_ForwardsOnlyAConfiguredAudience anchors the audience
// rule on the path real relying parties hit (HandleLogin, not the low-level
// URL builder): none by default, the configured one when set.
func TestHandleLogin_ForwardsOnlyAConfiguredAudience(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	c.HandleLogin(w, r)
	if loc := w.Result().Header.Get("Location"); strings.Contains(loc, "audience=") {
		t.Errorf("authorize URL carries an audience by default: %s", loc)
	}

	c.cfg.Audience = "svc.example.com"
	w = httptest.NewRecorder()
	c.HandleLogin(w, httptest.NewRequest("GET", "/login", nil))
	if loc := w.Result().Header.Get("Location"); !strings.Contains(loc, "audience=svc.example.com") {
		t.Errorf("authorize URL missing the configured audience: %s", loc)
	}
}

// TestFetchUserInfo_PopulatesOrgIDAndAvatar pins the /userinfo →
// User mapping. RPs rely on org_id and avatar_url being read off the
// response without having to inline a struct duplicate.
func TestFetchUserInfo_PopulatesOrgIDAndAvatar(t *testing.T) {
	orig := httpDo
	t.Cleanup(func() { httpDo = orig })
	httpDo = func(req *http.Request) (*http.Response, error) {
		body := `{"sub":"u1","email":"a@b.com","name":"Alice","picture":"https://pic.test/a","org_id":"org-1"}`
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}
	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)
	u, err := c.FetchUserInfo(r, "tok")
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if u.OrgID != "org-1" {
		t.Errorf("OrgID = %q, want org-1", u.OrgID)
	}
	if u.Picture != "https://pic.test/a" {
		t.Errorf("Picture = %q", u.Picture)
	}
	if u.PrincipalType != authkit.PrincipalUser {
		t.Errorf("PrincipalType = %q, want user", u.PrincipalType)
	}
}

// TestFetchOrgs_BearerHeader exercises the helper end-to-end against a
// stub auth server, verifying the Authorization header and decoded
// payload match the /me/orgs contract.
func TestFetchOrgs_BearerHeader(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/me/orgs" {
			http.NotFound(w, r)
			return
		}
		sawAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode([]OrgEntry{
			{ID: "org-1", Name: "Acme", Slug: "acme", Owner: true},
			{ID: "org-2", Name: "Globex"},
		})
	}))
	defer srv.Close()

	c := New(Config{
		AuthURL:      srv.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	})
	orgs, err := c.FetchOrgs(context.Background(), "tok-abc")
	if err != nil {
		t.Fatalf("FetchOrgs: %v", err)
	}
	if sawAuth != "Bearer tok-abc" {
		t.Errorf("Authorization header = %q, want Bearer tok-abc", sawAuth)
	}
	if len(orgs) != 2 || orgs[0].ID != "org-1" || orgs[1].ID != "org-2" {
		t.Errorf("orgs = %+v", orgs)
	}
	if !orgs[0].Owner {
		t.Errorf("orgs[0].Owner = false, want true (owner flag dropped)")
	}
}

// TestFetchOrgs_NonOK surfaces the 401 path the auth service returns
// when the bearer token has the wrong (or empty) audience claim. The
// helper must propagate the error rather than degrade silently to an
// empty list — a quiet fallback is what hides this kind of
// misconfiguration in production.
func TestFetchOrgs_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"audience mismatch"}`))
	}))
	defer srv.Close()
	c := New(Config{
		AuthURL:      srv.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	})
	_, err := c.FetchOrgs(context.Background(), "tok")
	if err == nil {
		t.Fatal("FetchOrgs accepted 401 silently")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want to surface status code", err.Error())
	}
}

// TestHandleCallback_StoresOrgIDFromJWT verifies the JWT-side org
// claim survives the auth-code exchange. RPs that render an org
// switcher rely on session.User.OrgID being set on first login;
// without this the switcher is blank until the next /userinfo
// round-trip.
func TestHandleCallback_StoresOrgIDFromJWT(t *testing.T) {
	jwt := makeJWT(map[string]string{
		"sub":    "u1",
		"email":  "a@b.com",
		"org_id": "org-42",
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  jwt,
			"token_type":    "Bearer",
			"refresh_token": "rt",
			"expires_in":    3600,
		})
	}))
	defer ts.Close()

	c := New(Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	})
	wSetup := httptest.NewRecorder()
	if err := c.SetFlowState(wSetup, &FlowState{
		CodeVerifier: "v",
		State:        "s",
		ReturnTo:     "/dashboard",
	}); err != nil {
		t.Fatalf("SetFlowState: %v", err)
	}

	r := httptest.NewRequest("GET", "/callback?code=x&state=s", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	c.HandleCallback(w, r)

	var sessCookie *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == SessionCookieName {
			sessCookie = ck
		}
	}
	if sessCookie == nil {
		t.Fatal("session cookie not set")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(sessCookie)
	sess, err := c.GetSession(r2)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.User.OrgID != "org-42" {
		t.Errorf("session.User.OrgID = %q, want org-42 (from JWT)", sess.User.OrgID)
	}
}
