package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetSessionByName_LegacyNameRoundtrips writes a session under a legacy
// cookie name (simulating a relying party that previously overrode CookieName)
// and asserts a client configured for a different default name can still read
// it via GetSessionByName. This is the legacy-cookie-fallback shape used
// during cookie-name migrations.
func TestGetSessionByName_LegacyNameRoundtrips(t *testing.T) {
	// Write the cookie using a client configured for the LEGACY name.
	legacyClient := newConfiguredClient(t, 0) // CookieName: "__custom_session"
	rec := httptest.NewRecorder()
	if err := legacyClient.SetSession(rec, &Session{AccessToken: "tok-legacy"}); err != nil {
		t.Fatalf("SetSession (legacy): %v", err)
	}
	cookie := rec.Result().Cookies()[0]
	if cookie.Name != "__custom_session" {
		t.Fatalf("legacy cookie name = %q, want __custom_session", cookie.Name)
	}

	// Read with a client configured for a DIFFERENT default name. Plain
	// GetSession should miss; GetSessionByName with the legacy name should
	// resolve.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	sess, err := legacyClient.GetSessionByName(req, "__custom_session")
	if err != nil {
		t.Fatalf("GetSessionByName: %v", err)
	}
	if sess == nil || sess.AccessToken != "tok-legacy" {
		t.Fatalf("session via legacy name: %+v", sess)
	}
}

// TestGetSessionByName_NotPresent ensures a non-existent cookie name reports an
// error so callers can fall through to the next candidate.
func TestGetSessionByName_NotPresent(t *testing.T) {
	c := newConfiguredClient(t, 0)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := c.GetSessionByName(req, "no-such-cookie")
	if err == nil {
		t.Fatal("expected error when cookie absent, got nil")
	}
}

// TestGetSession_DelegatesToGetSessionByName guarantees the public default-name
// reader keeps producing the same result as the by-name reader configured to the
// client's CookieName — i.e. that refactoring GetSession into a thin wrapper
// preserved its semantics.
func TestGetSession_DelegatesToGetSessionByName(t *testing.T) {
	c := newConfiguredClient(t, 0)
	rec := httptest.NewRecorder()
	if err := c.SetSession(rec, &Session{AccessToken: "tok"}); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	cookie := rec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	a, err := c.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(cookie)
	b, err := c.GetSessionByName(req2, "__custom_session")
	if err != nil {
		t.Fatalf("GetSessionByName: %v", err)
	}

	if a.AccessToken != b.AccessToken {
		t.Fatalf("GetSession vs GetSessionByName diverged: %q vs %q", a.AccessToken, b.AccessToken)
	}
}
