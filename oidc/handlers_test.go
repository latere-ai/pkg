package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- decodeJWTClaims ---

func makeJWT(claims map[string]string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload, _ := json.Marshal(claims)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".signature"
}

func TestDecodeJWTClaims(t *testing.T) {
	jwt := makeJWT(map[string]string{"sub": "u1", "email": "a@b.com"})
	c, err := decodeJWTClaims(jwt)
	if err != nil {
		t.Fatalf("decodeJWTClaims error: %v", err)
	}
	if c.Sub != "u1" || c.Email != "a@b.com" {
		t.Errorf("claims = %+v", c)
	}
}

func TestDecodeJWTClaimsInvalid(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"no dots", "nodots"},
		{"one dot", "one.part"},
		{"bad base64", "header.%%%bad.sig"},
		{"bad json", "header." + base64.RawURLEncoding.EncodeToString([]byte("notjson")) + ".sig"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeJWTClaims(tt.token)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// --- isSafeRedirect ---

func TestIsSafeRedirect(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"/", true},
		{"/dashboard", true},
		{"/a/b/c", true},
		{"", false},
		{"//evil.com", false},
		{"https://evil.com", false},
		{"javascript:alert(1)", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isSafeRedirect(tt.input); got != tt.want {
				t.Errorf("isSafeRedirect(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- HandleLogin ---

func TestHandleLogin(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/login?return_to=/dashboard", nil)
	w := httptest.NewRecorder()

	c.HandleLogin(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "auth.example.com/authorize") {
		t.Errorf("redirect missing authorize endpoint: %s", loc)
	}
	if !strings.Contains(loc, "code_challenge=") {
		t.Errorf("redirect missing PKCE challenge: %s", loc)
	}

	// Flow cookie must be set.
	var flowCookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == FlowCookieName {
			flowCookie = ck
		}
	}
	if flowCookie == nil {
		t.Fatal("flow cookie not set")
	}

	// Verify the flow state was stored with the return_to.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(flowCookie)
	flow, err := c.GetFlowState(r2)
	if err != nil {
		t.Fatalf("GetFlowState: %v", err)
	}
	if flow.ReturnTo != "/dashboard" {
		t.Errorf("ReturnTo = %q, want /dashboard", flow.ReturnTo)
	}
}

func TestHandleLogin_UnsafeReturnTo(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/login?return_to=https://evil.com", nil)
	w := httptest.NewRecorder()

	c.HandleLogin(w, r)

	// Flow state should default to "/".
	for _, ck := range w.Result().Cookies() {
		if ck.Name == FlowCookieName {
			r2 := httptest.NewRequest("GET", "/", nil)
			r2.AddCookie(ck)
			flow, _ := c.GetFlowState(r2)
			if flow != nil && flow.ReturnTo != "/" {
				t.Errorf("ReturnTo = %q, want /", flow.ReturnTo)
			}
		}
	}
}

func TestHandleLogin_StateError(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = failReader{}

	c := testClient(t)
	r := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()

	c.HandleLogin(w, r)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Result().StatusCode)
	}
}

// --- HandleCallback ---

func TestHandleCallback_ErrorParam(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/callback?error=access_denied&error_description=nope", nil)
	w := httptest.NewRecorder()

	c.HandleCallback(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "auth_error=access_denied") {
		t.Errorf("redirect = %q, want auth_error param", loc)
	}
}

func TestHandleCallback_NoFlowState(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/callback?code=abc&state=xyz", nil)
	w := httptest.NewRecorder()

	c.HandleCallback(w, r)

	resp := w.Result()
	loc := resp.Header.Get("Location")
	if loc != "/login" {
		t.Errorf("redirect = %q, want /login", loc)
	}
}

func TestHandleCallback_StateMismatch(t *testing.T) {
	c := testClient(t)

	// Set up a flow state with a known state.
	wSetup := httptest.NewRecorder()
	c.SetFlowState(wSetup, &FlowState{
		CodeVerifier: "v",
		State:        "correct-state",
		ReturnTo:     "/",
	})

	r := httptest.NewRequest("GET", "/callback?code=abc&state=wrong-state", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	c.HandleCallback(w, r)

	loc := w.Result().Header.Get("Location")
	if loc != "/login" {
		t.Errorf("redirect = %q, want /login", loc)
	}
}

func TestHandleCallback_Success(t *testing.T) {
	// Set up a token server.
	jwt := makeJWT(map[string]string{"sub": "user1", "email": "user@test.com"})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  jwt,
			"token_type":    "Bearer",
			"refresh_token": "rt-123",
			"expires_in":    3600,
		})
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/callback",
	}
	c := New(cfg)

	// Set up flow state.
	wSetup := httptest.NewRecorder()
	c.SetFlowState(wSetup, &FlowState{
		CodeVerifier: "verifier",
		State:        "test-state",
		ReturnTo:     "/dashboard",
	})

	r := httptest.NewRequest("GET", "/callback?code=authcode&state=test-state", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	c.HandleCallback(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/dashboard" {
		t.Errorf("redirect = %q, want /dashboard", loc)
	}

	// Session cookie must be set.
	var sessCookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == SessionCookieName {
			sessCookie = ck
		}
	}
	if sessCookie == nil {
		t.Fatal("session cookie not set")
	}

	// Verify session contents.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(sessCookie)
	sess, err := c.GetSession(r2)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.User.Sub != "user1" || sess.User.Email != "user@test.com" {
		t.Errorf("session user = %+v", sess.User)
	}
	if sess.RefreshToken != "rt-123" {
		t.Errorf("refresh token = %q", sess.RefreshToken)
	}
}

func TestHandleCallback_ExchangeError(t *testing.T) {
	// Token server returns an error.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/callback",
	}
	c := New(cfg)

	wSetup := httptest.NewRecorder()
	c.SetFlowState(wSetup, &FlowState{
		CodeVerifier: "v",
		State:        "s",
		ReturnTo:     "/",
	})

	r := httptest.NewRequest("GET", "/callback?code=bad&state=s", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	c.HandleCallback(w, r)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "auth_error=token_exchange_failed") {
		t.Errorf("redirect = %q, want auth_error", loc)
	}
}

func TestHandleCallback_BadJWT(t *testing.T) {
	// Token server returns a non-JWT access token.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "not-a-jwt",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/callback",
	}
	c := New(cfg)

	wSetup := httptest.NewRecorder()
	c.SetFlowState(wSetup, &FlowState{
		CodeVerifier: "v",
		State:        "s",
		ReturnTo:     "/",
	})

	r := httptest.NewRequest("GET", "/callback?code=x&state=s", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	c.HandleCallback(w, r)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "auth_error=invalid_token") {
		t.Errorf("redirect = %q, want auth_error=invalid_token", loc)
	}
}

// --- HandleLogout ---

func TestHandleLogout(t *testing.T) {
	c := testClient(t)

	// Set a session first.
	wSetup := httptest.NewRecorder()
	c.SetSession(wSetup, &Session{AccessToken: "tok"})

	r := httptest.NewRequest("GET", "/logout", nil)
	r.Host = "app.example.com"
	r.TLS = nil // not localhost, so scheme = https
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	c.HandleLogout(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "auth.example.com/logout") {
		t.Errorf("redirect missing auth logout: %s", loc)
	}
	if !strings.Contains(loc, "post_logout_redirect_uri=") {
		t.Errorf("redirect missing post_logout_redirect_uri: %s", loc)
	}

	// Session cookie must be cleared.
	for _, ck := range resp.Cookies() {
		if ck.Name == SessionCookieName && ck.MaxAge != -1 {
			t.Errorf("session cookie MaxAge = %d, want -1", ck.MaxAge)
		}
	}
}

func TestHandleLogout_Localhost(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/logout", nil)
	r.Host = "localhost:8080"
	w := httptest.NewRecorder()

	c.HandleLogout(w, r)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "http%3A%2F%2Flocalhost%3A8080") {
		t.Errorf("localhost redirect should use http scheme: %s", loc)
	}
}

func TestHandleLogout_ReturnTo(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/logout?return_to=/goodbye", nil)
	r.Host = "app.example.com"
	w := httptest.NewRecorder()

	c.HandleLogout(w, r)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "%2Fgoodbye") {
		t.Errorf("redirect should include return_to path: %s", loc)
	}
}

func TestHandleLogout_UnsafeReturnTo(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/logout?return_to=//evil.com", nil)
	r.Host = "app.example.com"
	w := httptest.NewRecorder()

	c.HandleLogout(w, r)

	loc := w.Result().Header.Get("Location")
	// The post_logout_redirect_uri should contain "/" not "//evil.com".
	if strings.Contains(loc, "evil.com") {
		t.Errorf("redirect should not contain evil.com: %s", loc)
	}
}

// --- UserFromRequest ---

func TestUserFromRequest_NoSession(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	u := c.UserFromRequest(w, r)
	if u != nil {
		t.Errorf("expected nil user, got %+v", u)
	}
}

func TestUserFromRequest_ValidToken(t *testing.T) {
	c := testClient(t)

	jwt := makeJWT(map[string]string{"sub": "u1", "email": "a@b.com"})
	wSetup := httptest.NewRecorder()
	c.SetSession(wSetup, &Session{
		AccessToken: jwt,
		Expiry:      time.Now().Add(1 * time.Hour),
	})

	r := httptest.NewRequest("GET", "/", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	u := c.UserFromRequest(w, r)
	if u == nil {
		t.Fatal("expected user, got nil")
	}
	if u.Sub != "u1" || u.Email != "a@b.com" {
		t.Errorf("user = %+v", u)
	}
}

func TestUserFromRequest_ExpiredTokenRefreshSuccess(t *testing.T) {
	newJWT := makeJWT(map[string]string{"sub": "u1", "email": "refreshed@test.com"})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  newJWT,
			"token_type":    "Bearer",
			"refresh_token": "new-rt",
			"expires_in":    3600,
		})
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	}
	c := New(cfg)

	oldJWT := makeJWT(map[string]string{"sub": "u1", "email": "old@test.com"})
	wSetup := httptest.NewRecorder()
	c.SetSession(wSetup, &Session{
		AccessToken:  oldJWT,
		RefreshToken: "old-rt",
		Expiry:       time.Now().Add(-1 * time.Hour), // expired
	})

	r := httptest.NewRequest("GET", "/", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	u := c.UserFromRequest(w, r)
	if u == nil {
		t.Fatal("expected user after refresh")
	}
	if u.Email != "refreshed@test.com" {
		t.Errorf("email = %q, want refreshed@test.com", u.Email)
	}

	// Session cookie should be updated with the new token.
	var sessCookie *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == SessionCookieName {
			sessCookie = ck
		}
	}
	if sessCookie == nil {
		t.Fatal("refreshed session cookie not set")
	}
}

func TestUserFromRequest_ExpiredTokenRefreshFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	}
	c := New(cfg)

	jwt := makeJWT(map[string]string{"sub": "u1", "email": "a@b.com"})
	wSetup := httptest.NewRecorder()
	c.SetSession(wSetup, &Session{
		AccessToken:  jwt,
		RefreshToken: "bad-rt",
		Expiry:       time.Now().Add(-1 * time.Hour),
	})

	r := httptest.NewRequest("GET", "/", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	u := c.UserFromRequest(w, r)
	if u != nil {
		t.Errorf("expected nil user when refresh fails, got %+v", u)
	}
}

func TestUserFromRequest_ExpiredNoRefreshToken(t *testing.T) {
	c := testClient(t)

	jwt := makeJWT(map[string]string{"sub": "u1", "email": "a@b.com"})
	wSetup := httptest.NewRecorder()
	c.SetSession(wSetup, &Session{
		AccessToken: jwt,
		Expiry:      time.Now().Add(-1 * time.Hour),
		// No refresh token.
	})

	r := httptest.NewRequest("GET", "/", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	u := c.UserFromRequest(w, r)
	// With no refresh token but expired access token, it should still
	// try to decode the JWT (the expiry check is for refresh, not rejection).
	// The JWT itself is decodable, so user is returned.
	if u == nil {
		t.Fatal("expected user (JWT is still decodable)")
	}
}

func TestUserFromRequest_BadJWT(t *testing.T) {
	c := testClient(t)

	wSetup := httptest.NewRecorder()
	c.SetSession(wSetup, &Session{
		AccessToken: "not-a-jwt",
		Expiry:      time.Now().Add(1 * time.Hour),
	})

	r := httptest.NewRequest("GET", "/", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	u := c.UserFromRequest(w, r)
	if u != nil {
		t.Errorf("expected nil user for bad JWT, got %+v", u)
	}
}

// --- HandleLogin encrypt error ---

func TestHandleLogin_FlowStateError(t *testing.T) {
	orig := aesGCMEncrypt
	t.Cleanup(func() { aesGCMEncrypt = orig })
	aesGCMEncrypt = func(key, plaintext []byte) ([]byte, error) {
		return nil, fmt.Errorf("injected error")
	}

	c := testClient(t)
	r := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()

	c.HandleLogin(w, r)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Result().StatusCode)
	}
}

// --- HandleCallback session set error ---

func TestHandleCallback_SetSessionError(t *testing.T) {
	jwt := makeJWT(map[string]string{"sub": "u1", "email": "a@b.com"})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  jwt,
			"token_type":    "Bearer",
			"refresh_token": "rt",
			"expires_in":    3600,
		})
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/callback",
	}
	c := New(cfg)

	wSetup := httptest.NewRecorder()
	c.SetFlowState(wSetup, &FlowState{
		CodeVerifier: "v",
		State:        "s",
		ReturnTo:     "/",
	})

	// Break encryption after the flow state is set up.
	orig := aesGCMEncrypt
	t.Cleanup(func() { aesGCMEncrypt = orig })

	r := httptest.NewRequest("GET", "/callback?code=x&state=s", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	// Inject encrypt error right before HandleCallback runs SetSession.
	aesGCMEncrypt = func(key, plaintext []byte) ([]byte, error) {
		return nil, fmt.Errorf("injected error")
	}

	c.HandleCallback(w, r)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Result().StatusCode)
	}
}

// --- HandleCallback unsafe returnTo ---

func TestHandleCallback_UnsafeReturnTo(t *testing.T) {
	jwt := makeJWT(map[string]string{"sub": "u1", "email": "a@b.com"})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  jwt,
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/callback",
	}
	c := New(cfg)

	wSetup := httptest.NewRecorder()
	c.SetFlowState(wSetup, &FlowState{
		CodeVerifier: "v",
		State:        "s",
		ReturnTo:     "https://evil.com", // unsafe
	})

	r := httptest.NewRequest("GET", "/callback?code=x&state=s", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	c.HandleCallback(w, r)

	loc := w.Result().Header.Get("Location")
	if loc != "/" {
		t.Errorf("redirect = %q, want / for unsafe returnTo", loc)
	}
}

// --- UserFromRequest refresh persist error ---

func TestUserFromRequest_RefreshPersistError(t *testing.T) {
	newJWT := makeJWT(map[string]string{"sub": "u1", "email": "a@b.com"})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": newJWT,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	}
	c := New(cfg)

	oldJWT := makeJWT(map[string]string{"sub": "u1", "email": "old@test.com"})
	wSetup := httptest.NewRecorder()
	c.SetSession(wSetup, &Session{
		AccessToken:  oldJWT,
		RefreshToken: "rt",
		Expiry:       time.Now().Add(-1 * time.Hour),
	})

	// Break encryption so SetSession fails during refresh persist.
	orig := aesGCMEncrypt
	t.Cleanup(func() { aesGCMEncrypt = orig })
	aesGCMEncrypt = func(key, plaintext []byte) ([]byte, error) {
		return nil, fmt.Errorf("injected error")
	}

	r := httptest.NewRequest("GET", "/", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()

	// Should still return the user even if persist fails.
	u := c.UserFromRequest(w, r)
	if u == nil {
		t.Fatal("expected user even when persist fails")
	}
}

// --- Fuzz tests ---

func FuzzDecodeJWTClaims(f *testing.F) {
	f.Add("header.eyJzdWIiOiJ1MSIsImVtYWlsIjoiYUBiLmNvbSJ9.sig")
	f.Add("")
	f.Add("no-dots")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		// Should never panic.
		decodeJWTClaims(token)
	})
}

func FuzzIsSafeRedirect(f *testing.F) {
	f.Add("/")
	f.Add("//evil.com")
	f.Add("")
	f.Add("https://evil.com")
	f.Add("/dashboard")

	f.Fuzz(func(t *testing.T, target string) {
		got := isSafeRedirect(target)
		if got && (target == "" || target[0] != '/') {
			t.Errorf("isSafeRedirect(%q) = true, but does not start with /", target)
		}
		if got && len(target) > 1 && target[1] == '/' {
			t.Errorf("isSafeRedirect(%q) = true, but starts with //", target)
		}
	})
}
