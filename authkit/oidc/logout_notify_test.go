// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// relativeRedirectClient is a client whose RedirectURL names no origin, the
// one case in which HandleLogout still reads the origin off the request.
func relativeRedirectClient(t *testing.T) *Client {
	t.Helper()
	c := New(Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "/callback",
	})
	if c == nil {
		t.Fatal("New returned nil for valid config")
	}
	return c
}

// TestHandleLogoutUsesTheRedirectOrigin verifies the return address is built
// on the configured RedirectURL's origin, whatever Host and
// X-Forwarded-Proto the request claims: a request does not get to say where
// the auth service sends the browser after sign-out.
func TestHandleLogoutUsesTheRedirectOrigin(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest(http.MethodGet, "/logout?return_to=/bye", nil)
	r.Host = "evil.example"
	r.Header.Set("X-Forwarded-Proto", "http")
	w := httptest.NewRecorder()
	c.HandleLogout(w, r)

	loc, err := url.Parse(w.Result().Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location does not parse: %v", err)
	}
	if got, want := loc.Query().Get("post_logout_redirect_uri"), "https://app.example.com/bye"; got != want {
		t.Errorf("post_logout_redirect_uri = %q, want %q", got, want)
	}
}

// TestHandleLogoutPostIsSeeOther verifies a POST sign-out is answered 303,
// so the browser follows it with a GET rather than re-posting to the auth
// service.
func TestHandleLogoutPostIsSeeOther(t *testing.T) {
	c := testClient(t)
	w := httptest.NewRecorder()
	c.HandleLogout(w, httptest.NewRequest(http.MethodPost, "/logout", nil))
	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", w.Code)
	}
}

// TestHandleLogoutForwardedProto verifies X-Forwarded-Proto wins over both the
// localhost heuristic and the https default, since the app runs behind a
// TLS-terminating ingress where r.TLS is nil.
func TestHandleLogoutForwardedProto(t *testing.T) {
	c := relativeRedirectClient(t)

	// XFP=https on a localhost host (which would otherwise pick http).
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	r.Host = "localhost:8080"
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	c.HandleLogout(w, r)
	if loc := w.Result().Header.Get("Location"); !strings.Contains(loc, "https%3A%2F%2Flocalhost%3A8080") {
		t.Errorf("XFP=https not honored over localhost heuristic: %s", loc)
	}

	// XFP=http on a non-localhost host (which would otherwise pick https).
	r2 := httptest.NewRequest(http.MethodGet, "/logout", nil)
	r2.Host = "app.example.com"
	r2.Header.Set("X-Forwarded-Proto", "http")
	w2 := httptest.NewRecorder()
	c.HandleLogout(w2, r2)
	if loc := w2.Result().Header.Get("Location"); !strings.Contains(loc, "http%3A%2F%2Fapp.example.com") {
		t.Errorf("XFP=http not honored: %s", loc)
	}
}

// TestHandleLogoutForwardedProtoList takes the first value of a comma list.
func TestHandleLogoutForwardedProtoList(t *testing.T) {
	c := relativeRedirectClient(t)
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	r.Host = "app.example.com"
	r.Header.Set("X-Forwarded-Proto", "https, http")
	w := httptest.NewRecorder()
	c.HandleLogout(w, r)
	if loc := w.Result().Header.Get("Location"); !strings.Contains(loc, "https%3A%2F%2Fapp.example.com") {
		t.Errorf("first XFP value not used: %s", loc)
	}
}

// TestHandleLogoutNotifyClearsAnd200 verifies the front-channel handler clears
// the configured cookie and returns 200.
func TestHandleLogoutNotifyClearsAnd200(t *testing.T) {
	c := newConfiguredClient(t, 0)
	r := httptest.NewRequest(http.MethodGet, "/logout/notify", nil)
	w := httptest.NewRecorder()
	c.HandleLogoutNotify(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Name != "__custom_session" || cookies[0].MaxAge != -1 {
		t.Errorf("cookie = %+v, want __custom_session cleared", cookies[0])
	}
}

// TestHandleLogoutNotifyAnswersOnlyAFrame verifies a link or an image on
// another page cannot sign a person out: a browser names the destination in
// Sec-Fetch-Dest, and only a frame, or a browser that sends no header, ends
// the session.
func TestHandleLogoutNotifyAnswersOnlyAFrame(t *testing.T) {
	c := newConfiguredClient(t, 0)
	for _, tc := range []struct {
		dest  string
		code  int
		clear bool
	}{
		{"iframe", http.StatusOK, true},
		{"frame", http.StatusOK, true},
		{"", http.StatusOK, true},
		{"document", http.StatusBadRequest, false},
		{"image", http.StatusBadRequest, false},
	} {
		r := httptest.NewRequest(http.MethodGet, "/logout/notify", nil)
		if tc.dest != "" {
			r.Header.Set("Sec-Fetch-Dest", tc.dest)
		}
		w := httptest.NewRecorder()
		c.HandleLogoutNotify(w, r)
		if w.Code != tc.code {
			t.Errorf("Sec-Fetch-Dest %q: status = %d, want %d", tc.dest, w.Code, tc.code)
		}
		if cleared := len(w.Result().Cookies()) > 0; cleared != tc.clear {
			t.Errorf("Sec-Fetch-Dest %q: cleared = %v, want %v", tc.dest, cleared, tc.clear)
		}
	}
}
