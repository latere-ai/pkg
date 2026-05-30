package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleLogoutForwardedProto verifies X-Forwarded-Proto wins over both the
// localhost heuristic and the https default, since the app runs behind a
// TLS-terminating ingress where r.TLS is nil.
func TestHandleLogoutForwardedProto(t *testing.T) {
	c := testClient(t)

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
	c := testClient(t)
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
