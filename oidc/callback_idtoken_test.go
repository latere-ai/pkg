// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		idToken := signWith(t, key, "kid-1", "RS256", map[string]any{
			"iss": srv.URL, "aud": clientID, "sub": "user1", "nonce": nonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": makeJWT(map[string]string{"sub": "user1", "email": "user@test.com"}),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
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
	ts := idTokenIssuer(t, "cid", issuedNonce)
	c := New(Config{AuthURL: ts.URL, ClientID: "cid", ClientSecret: "sec", RedirectURL: "https://app.example.com/callback"})
	wSetup := httptest.NewRecorder()
	if err := c.SetFlowState(wSetup, &FlowState{CodeVerifier: "verifier", State: "st", ReturnTo: "/dashboard", Nonce: flowNonce}); err != nil {
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
