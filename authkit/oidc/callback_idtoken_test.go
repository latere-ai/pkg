// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// idTokenIssuer serves the auth service's fixed layout: /token returns an
// access token plus an ID token signed for the given nonce, and
// /.well-known/jwks.json publishes the key.
func idTokenIssuer(t *testing.T, clientID, nonce string) *httptest.Server {
	t.Helper()
	return issuerWithIDToken(t, clientID, nonce, map[string]any{
		"access_token": makeJWT(map[string]string{"sub": "user1", "email": "user@test.com"}),
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

// issuerWithIDToken is idTokenIssuer with the rest of the token response
// given: /token answers resp plus an ID token for clientID and nonce.
func issuerWithIDToken(t *testing.T, clientID, nonce string, resp map[string]any) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		body := maps.Clone(resp)
		body["id_token"] = signWith(t, key, "kid-1", "RS256", map[string]any{
			"iss": srv.URL, "aud": clientID, "sub": "user1", "nonce": nonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		})
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "kid-1",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func callbackWithNonce(t *testing.T, issuedNonce, flowNonce string) *http.Response {
	t.Helper()
	return callbackAt(t, idTokenIssuer(t, "cid", issuedNonce).URL, flowNonce)
}

func hasSessionCookie(resp *http.Response) bool {
	for _, ck := range resp.Cookies() {
		if ck.Name == SessionCookieName && ck.Value != "" {
			return true
		}
	}
	return false
}

// TestHandleCallback_IDTokenNonceMismatchRejected pins that an ID token bound
// to another login is refused: no session, and the user is sent back with
// invalid_id_token. Before the callback verified ID tokens, this login
// succeeded.
func TestHandleCallback_IDTokenNonceMismatchRejected(t *testing.T) {
	resp := callbackWithNonce(t, "other-login", "this-login")
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "auth_error=invalid_id_token") {
		t.Fatalf("status = %d, location = %q; want 302 to invalid_id_token", resp.StatusCode, resp.Header.Get("Location"))
	}
	if hasSessionCookie(resp) {
		t.Fatal("a session was set for a login whose ID token failed verification")
	}
}

func TestHandleCallback_IDTokenVerifiedSetsSession(t *testing.T) {
	resp := callbackWithNonce(t, "this-login", "this-login")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/dashboard" {
		t.Fatalf("status = %d, location = %q; want 302 to /dashboard", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !hasSessionCookie(resp) {
		t.Fatal("no session set after a verified ID token")
	}
}

// TestHandleCallback_MissingIDTokenRejected pins that a token response
// without an ID token signs nobody in. Before the callback required one, the
// session was built from the access token's claims, which nothing verified.
func TestHandleCallback_MissingIDTokenRejected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": makeJWT(map[string]string{"sub": "user1", "email": "user@test.com"}),
			"token_type":   "Bearer",
			"expires_in":   3600,
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	}))
	t.Cleanup(ts.Close)
	resp := callbackAt(t, ts.URL, "this-login")
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "auth_error=invalid_id_token") {
		t.Fatalf("status = %d, location = %q; want 302 to invalid_id_token", resp.StatusCode, resp.Header.Get("Location"))
	}
	if hasSessionCookie(resp) {
		t.Fatal("a session was set for a login with no ID token")
	}
}

// TestHandleCallback_OversizedSessionRefused pins that a session a browser
// would drop is refused with a named error instead. Before the bound, the
// callback wrote the cookie, the browser discarded it, and the person landed
// signed out with nothing said.
func TestHandleCallback_OversizedSessionRefused(t *testing.T) {
	roles := make([]string, 300)
	for i := range roles {
		roles[i] = fmt.Sprintf("org-%04d:admin", i)
	}
	ts := issuerWithIDToken(t, "cid", "this-login", map[string]any{
		"access_token": makeRichJWT(map[string]any{"sub": "user1", "email": "user@test.com", "roles": roles}),
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
	resp := callbackAt(t, ts.URL, "this-login")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/?auth_error=session_too_large" {
		t.Fatalf("status = %d, location = %q; want 302 to session_too_large", resp.StatusCode, resp.Header.Get("Location"))
	}
	if hasSessionCookie(resp) {
		t.Fatal("a session cookie over the browser limit was written")
	}
}

// TestSetSession_RefusesACookieOverTheLimit pins the bound at the writer, so
// a refreshed session that grows past it is refused the same way and the
// browser keeps the cookie it has.
func TestSetSession_RefusesACookieOverTheLimit(t *testing.T) {
	c := testClient(t)
	w := httptest.NewRecorder()
	err := c.SetSession(w, &Session{AccessToken: strings.Repeat("a", maxCookieBytes)})
	if !errors.Is(err, errCookieTooLarge) {
		t.Fatalf("err = %v, want errCookieTooLarge", err)
	}
	if got := w.Result().Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("Set-Cookie written for a refused session: %d header(s)", len(got))
	}
	if err := c.SetSession(httptest.NewRecorder(), &Session{AccessToken: strings.Repeat("a", 1024)}); err != nil {
		t.Fatalf("a session well under the limit was refused: %v", err)
	}
}

// callbackAt completes a callback against the issuer at authURL for a flow
// that sent nonce.
func callbackAt(t *testing.T, authURL, nonce string) *http.Response {
	t.Helper()
	c := New(Config{AuthURL: authURL, ClientID: "cid", ClientSecret: "sec", RedirectURL: "https://app.example.com/callback"})
	wSetup := httptest.NewRecorder()
	if err := c.SetFlowState(wSetup, &FlowState{CodeVerifier: "verifier", State: "st", ReturnTo: "/dashboard", Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/callback?code=authcode&state=st", nil)
	for _, ck := range wSetup.Result().Cookies() {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	c.HandleCallback(w, r)
	return w.Result()
}
