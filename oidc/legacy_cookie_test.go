package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetSession_LegacyFallback verifies that a client configured with
// LegacyCookieNames falls back through the list when the primary cookie is
// absent, and prefers the primary when both are present.
func TestGetSession_LegacyFallback(t *testing.T) {
	// Client used to write the legacy cookie. CookieName is the legacy name.
	legacyWriter := New(Config{
		AuthURL:         "https://auth.example.com",
		ClientID:        "cid",
		ClientSecret:    "sec",
		RedirectURL:     "https://app.example.com/cb",
		CookieName:      "__legacy_session",
		InsecureCookies: true,
	})
	if legacyWriter == nil {
		t.Fatal("legacyWriter nil")
	}
	rec := httptest.NewRecorder()
	if err := legacyWriter.SetSession(rec, &Session{AccessToken: "from-legacy"}); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	legacyCookie := rec.Result().Cookies()[0]
	if legacyCookie.Name != "__legacy_session" {
		t.Fatalf("wrote name = %q", legacyCookie.Name)
	}

	// Client used to read with the new primary name + legacy fallback. The
	// cookie key matches the writer so decryption succeeds.
	reader := New(Config{
		AuthURL:           "https://auth.example.com",
		ClientID:          "cid",
		ClientSecret:      "sec",
		RedirectURL:       "https://app.example.com/cb",
		CookieName:        "__new_session",
		LegacyCookieNames: []string{"__legacy_session"},
		InsecureCookies:   true,
	})

	t.Run("legacy only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(legacyCookie)
		sess, err := reader.GetSession(req)
		if err != nil {
			t.Fatalf("GetSession (legacy only): %v", err)
		}
		if sess == nil || sess.AccessToken != "from-legacy" {
			t.Fatalf("got %+v, want AccessToken=from-legacy", sess)
		}
	})

	// Now write a primary cookie and verify it wins over the legacy.
	primaryRec := httptest.NewRecorder()
	if err := reader.SetSession(primaryRec, &Session{AccessToken: "from-primary"}); err != nil {
		t.Fatalf("SetSession (primary): %v", err)
	}
	primaryCookie := primaryRec.Result().Cookies()[0]
	if primaryCookie.Name != "__new_session" {
		t.Fatalf("primary cookie name = %q", primaryCookie.Name)
	}

	t.Run("primary wins over legacy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(primaryCookie)
		req.AddCookie(legacyCookie)
		sess, err := reader.GetSession(req)
		if err != nil {
			t.Fatalf("GetSession (both): %v", err)
		}
		if sess == nil || sess.AccessToken != "from-primary" {
			t.Fatalf("got %+v, want AccessToken=from-primary", sess)
		}
	})

	t.Run("neither name present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if _, err := reader.GetSession(req); err == nil {
			t.Fatal("expected error when no cookie is present")
		}
	})
}
