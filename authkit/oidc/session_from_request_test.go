// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// refreshClient builds a configured client whose token endpoint is a test server
// that returns newAccessToken on a refresh_token grant.
func refreshClient(t *testing.T, newAccessToken string) *Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", r.FormValue("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": newAccessToken, "token_type": "Bearer", "expires_in": 3600,
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	}))
	t.Cleanup(ts.Close)
	c := New(Config{
		AuthURL: ts.URL, ClientID: "cid", ClientSecret: "sec",
		RedirectURL:     "https://app.example.com/cb",
		CookieName:      "__custom_session",
		SessionTTL:      30 * 24 * time.Hour,
		InsecureCookies: true,
	})
	if c == nil {
		t.Fatal("New returned nil")
	}
	return c
}

// seedCookie writes sess via the client and returns a request carrying the cookie.
func seedCookie(t *testing.T, c *Client, sess *Session) *http.Request {
	t.Helper()
	w := httptest.NewRecorder()
	if err := c.SetSession(w, sess); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, ck := range w.Result().Cookies() {
		r.AddCookie(ck)
	}
	return r
}

func TestSessionFromRequestProactiveRefresh(t *testing.T) {
	// New token has no display_name/avatar_url, proving they're carried forward.
	newJWT := makeRichJWT(map[string]any{"sub": "u1", "email": "a@b.com"})
	c := refreshClient(t, newJWT)

	keepExpiry := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	r := seedCookie(t, c, &Session{
		AccessToken:   "old-at",
		RefreshToken:  "rt-1",
		Expiry:        time.Now().UTC().Add(-time.Minute), // expired → refresh
		SessionExpiry: keepExpiry,
		User:          User{Sub: "u1", DisplayName: "Ali", Picture: "https://p/y", ClientID: "cella", Scopes: []string{"openid"}},
	})

	// /userinfo must not be called; make it explode if it is.
	orig := httpDo
	t.Cleanup(func() { httpDo = orig })
	httpDo = func(*http.Request) (*http.Response, error) { return nil, errors.New("userinfo must not be called") }

	w := httptest.NewRecorder()
	got, err := c.SessionFromRequest(w, r)
	if err != nil {
		t.Fatalf("SessionFromRequest: %v", err)
	}
	if got.AccessToken != newJWT {
		t.Errorf("AccessToken not refreshed: %q", got.AccessToken)
	}
	if got.RefreshToken != "rt-1" {
		t.Errorf("RefreshToken = %q, want carried-forward rt-1", got.RefreshToken)
	}
	if !got.SessionExpiry.Equal(keepExpiry) {
		t.Errorf("SessionExpiry = %v, want preserved %v", got.SessionExpiry, keepExpiry)
	}
	if got.User.DisplayName != "Ali" || got.User.Picture != "https://p/y" {
		t.Errorf("profile not preserved: %+v", got.User)
	}
	if got.User.ClientID != "cella" || len(got.User.Scopes) != 1 {
		t.Errorf("clientID/scopes not preserved: %+v", got.User)
	}
	// The refreshed session must be written back.
	if len(w.Result().Cookies()) != 1 {
		t.Errorf("expected session cookie rewritten, got %d", len(w.Result().Cookies()))
	}
}

// TestSessionFromRequestRefreshPreservesNamePicture: the refreshed JWT omits
// the profile claims, so User.Name and User.Picture must be carried forward,
// otherwise a caller loses the avatar after the first silent refresh.
func TestSessionFromRequestRefreshPreservesNamePicture(t *testing.T) {
	newJWT := makeRichJWT(map[string]any{"sub": "u1", "email": "a@b.com"})
	c := refreshClient(t, newJWT)

	r := seedCookie(t, c, &Session{
		AccessToken:   "old-at",
		RefreshToken:  "rt-1",
		Expiry:        time.Now().UTC().Add(-time.Minute), // expired → refresh
		SessionExpiry: time.Now().UTC().Add(48 * time.Hour),
		User:          User{Sub: "u1", Name: "Ada Lovelace", Picture: "https://pic/a"},
	})

	orig := httpDo
	t.Cleanup(func() { httpDo = orig })
	httpDo = func(*http.Request) (*http.Response, error) { return nil, errors.New("userinfo must not be called") }

	w := httptest.NewRecorder()
	got, err := c.SessionFromRequest(w, r)
	if err != nil {
		t.Fatalf("SessionFromRequest: %v", err)
	}
	if got.User.Name != "Ada Lovelace" || got.User.Picture != "https://pic/a" {
		t.Errorf("Name/Picture not preserved across refresh: %+v", got.User)
	}
}

func TestSessionFromRequestNoRefreshNeeded(t *testing.T) {
	c := refreshClient(t, "unused")
	r := seedCookie(t, c, &Session{
		AccessToken:   "at",
		RefreshToken:  "rt",
		Expiry:        time.Now().UTC().Add(time.Hour), // far from expiry
		SessionExpiry: time.Now().UTC().Add(48 * time.Hour),
	})
	w := httptest.NewRecorder()
	got, err := c.SessionFromRequest(w, r)
	if err != nil {
		t.Fatalf("SessionFromRequest: %v", err)
	}
	if got.AccessToken != "at" {
		t.Errorf("AccessToken changed unexpectedly: %q", got.AccessToken)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("no cookie should be rewritten when no refresh occurs")
	}
}

func TestSessionFromRequestExpiredSession(t *testing.T) {
	c := refreshClient(t, "unused")
	r := seedCookie(t, c, &Session{
		AccessToken:   "at",
		RefreshToken:  "rt",
		Expiry:        time.Now().UTC().Add(time.Hour),
		SessionExpiry: time.Now().UTC().Add(-time.Hour), // dashboard session lapsed
	})
	_, err := c.SessionFromRequest(httptest.NewRecorder(), r)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
}

// TestSessionFromRequestGarbageCookie is the deploy-day contract: an
// undecryptable cookie (e.g. a stale __cella_session from before the cipher
// change) yields an error the caller turns into a clean redirect — never a panic.
func TestSessionFromRequestGarbageCookie(t *testing.T) {
	c := refreshClient(t, "unused")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  "__custom_session",
		Value: base64.RawURLEncoding.EncodeToString([]byte("garbage-from-an-old-cipher")),
	})
	sess, err := c.SessionFromRequest(httptest.NewRecorder(), r)
	if err == nil {
		t.Fatal("expected an error for an undecryptable cookie")
	}
	if errors.Is(err, ErrSessionExpired) {
		t.Error("garbage cookie should be a decrypt error, not ErrSessionExpired")
	}
	if sess != nil {
		t.Error("expected nil session on error")
	}
}

func TestSessionFromRequestNoCookie(t *testing.T) {
	c := refreshClient(t, "unused")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := c.SessionFromRequest(httptest.NewRecorder(), r)
	if err == nil {
		t.Fatal("expected error for missing cookie")
	}
}

func TestSessionFromRequestRefreshFailure(t *testing.T) {
	// Token server that rejects the refresh.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if _, err := w.Write([]byte(`{"error":"invalid_grant"}`)); err != nil {
			t.Errorf("write token endpoint response: %v", err)
		}
	}))
	defer ts.Close()
	c := New(Config{
		AuthURL: ts.URL, ClientID: "cid", ClientSecret: "sec",
		RedirectURL: "https://app.example.com/cb",
		CookieName:  "__custom_session", SessionTTL: 30 * 24 * time.Hour, InsecureCookies: true,
	})
	r := seedCookie(t, c, &Session{
		AccessToken: "at", RefreshToken: "rt",
		Expiry:        time.Now().UTC().Add(-time.Minute),
		SessionExpiry: time.Now().UTC().Add(48 * time.Hour),
	})
	_, err := c.SessionFromRequest(httptest.NewRecorder(), r)
	if err == nil {
		t.Fatal("expected refresh error")
	}
}

func TestSessionFromRequestExpiredNoRefreshToken(t *testing.T) {
	c := refreshClient(t, "unused")
	r := seedCookie(t, c, &Session{
		AccessToken:   "at",
		Expiry:        time.Now().UTC().Add(-time.Minute),
		SessionExpiry: time.Now().UTC().Add(48 * time.Hour),
	})
	_, err := c.SessionFromRequest(httptest.NewRecorder(), r)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
}
