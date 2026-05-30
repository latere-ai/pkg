package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newConfiguredClient builds a Client with a non-default cookie name, TTL, and
// insecure flag — the shape a relying party like cella uses.
func newConfiguredClient(t *testing.T, ttl time.Duration) *Client {
	t.Helper()
	c := New(Config{
		AuthURL:         "https://auth.example.com",
		ClientID:        "cid",
		ClientSecret:    "sec",
		RedirectURL:     "https://app.example.com/cb",
		CookieName:      "__custom_session",
		SessionTTL:      ttl,
		InsecureCookies: true,
	})
	if c == nil {
		t.Fatal("New returned nil for configured client")
	}
	return c
}

// TestSetSessionDefaultConfigUnchanged is the zero-change guard rail: an
// unconfigured client must write the same cookie name, MaxAge, and Secure flag
// it did before this feature, and must NOT stamp SessionExpiry.
func TestSetSessionDefaultConfigUnchanged(t *testing.T) {
	c := testClient(t)
	w := httptest.NewRecorder()
	sess := &Session{AccessToken: "tok"}
	if err := c.SetSession(w, sess); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	ck := cookies[0]
	if ck.Name != SessionCookieName {
		t.Errorf("name = %q, want %q", ck.Name, SessionCookieName)
	}
	if ck.MaxAge != SessionMaxAge {
		t.Errorf("MaxAge = %d, want %d", ck.MaxAge, SessionMaxAge)
	}
	if !ck.Secure {
		t.Error("expected Secure cookie for default config")
	}
	if !sess.SessionExpiry.IsZero() {
		t.Errorf("SessionExpiry = %v, want zero for default config", sess.SessionExpiry)
	}
}

// TestSetSessionConfigurableCookie verifies a configured client honors a custom
// cookie name, derives MaxAge from the TTL, drops Secure, and stamps SessionExpiry.
func TestSetSessionConfigurableCookie(t *testing.T) {
	const ttl = 30 * 24 * time.Hour
	c := newConfiguredClient(t, ttl)
	w := httptest.NewRecorder()
	sess := &Session{AccessToken: "tok"}
	if err := c.SetSession(w, sess); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	ck := cookies[0]
	if ck.Name != "__custom_session" {
		t.Errorf("name = %q, want __custom_session", ck.Name)
	}
	if ck.Secure {
		t.Error("expected Secure dropped for InsecureCookies")
	}
	wantSecs := int(ttl.Seconds())
	if ck.MaxAge < wantSecs-5 || ck.MaxAge > wantSecs {
		t.Errorf("MaxAge = %d, want ~%d", ck.MaxAge, wantSecs)
	}
	if sess.SessionExpiry.IsZero() {
		t.Error("SessionExpiry should be stamped for a configured TTL")
	}

	// Round-trip under the custom name.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	got, err := c.GetSession(r)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.AccessToken != "tok" {
		t.Errorf("round-trip AccessToken = %q", got.AccessToken)
	}
}

// TestSessionExpiryPreservedAcrossSet verifies a refresh (a second SetSession)
// never extends the dashboard session window.
func TestSessionExpiryPreservedAcrossSet(t *testing.T) {
	c := newConfiguredClient(t, 30*24*time.Hour)
	fixed := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	sess := &Session{AccessToken: "tok", SessionExpiry: fixed}

	if err := c.SetSession(httptest.NewRecorder(), sess); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	if !sess.SessionExpiry.Equal(fixed) {
		t.Fatalf("SessionExpiry changed on first set: got %v, want %v", sess.SessionExpiry, fixed)
	}
	if err := c.SetSession(httptest.NewRecorder(), sess); err != nil {
		t.Fatalf("SetSession (2nd): %v", err)
	}
	if !sess.SessionExpiry.Equal(fixed) {
		t.Errorf("SessionExpiry extended on re-set: got %v, want %v", sess.SessionExpiry, fixed)
	}
}

// TestNewDefaultsCookieName confirms New fills CookieName when unset.
func TestNewDefaultsCookieName(t *testing.T) {
	c := testClient(t)
	if c.cfg.CookieName != SessionCookieName {
		t.Errorf("CookieName = %q, want %q", c.cfg.CookieName, SessionCookieName)
	}
}
