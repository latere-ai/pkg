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
)

// TestNew_AudienceDefaultsToAuthURL pins the "every RP that calls the
// auth service's JWT endpoints gets the right aud out of the box"
// contract. Without this default, callers that forget to set Audience
// would land tokens with aud:[] and silently 401 against /me/orgs
// and /userinfo.
func TestNew_AudienceDefaultsToAuthURL(t *testing.T) {
	c := New(Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	})
	if c == nil {
		t.Fatal("New returned nil")
	}
	if got := c.cfg.Audience; got != "https://auth.example.com" {
		t.Errorf("Audience default = %q, want AuthURL", got)
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

// TestAuthCodeURLWithOpts_IncludesAudience asserts the audience param
// makes it onto the /authorize URL. The auth service reads the
// audience from the request form during the authorize step; if it's
// missing the issued JWT lands with aud:[] (the JWT strategy always
// materialises the claim from the granted audience set, even when
// empty), and downstream JWT-protected calls then 401.
func TestAuthCodeURLWithOpts_IncludesAudience(t *testing.T) {
	c := New(Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	})
	authURL := c.AuthCodeURLWithOpts("state", "verifier", nil)
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := parsed.Query().Get("audience"); got != "https://auth.example.com" {
		t.Errorf("audience param = %q, want issuer URL", got)
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

// TestHandleLogin_ForwardsAudience anchors the audience param on the
// path that real RPs hit (HandleLogin, not the low-level URL builder).
// Regression-guards a future change that decouples the two.
func TestHandleLogin_ForwardsAudience(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	c.HandleLogin(w, r)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "audience=https%3A%2F%2Fauth.example.com") {
		t.Errorf("authorize URL missing audience param: %s", loc)
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
	// AvatarURL should mirror Picture so callers keyed on either name
	// see the same value.
	if u.Picture != "https://pic.test/a" {
		t.Errorf("Picture = %q", u.Picture)
	}
	if u.AvatarURL != "https://pic.test/a" {
		t.Errorf("AvatarURL = %q, want mirror of Picture", u.AvatarURL)
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
