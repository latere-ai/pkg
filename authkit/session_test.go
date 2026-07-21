package authkit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"latere.ai/x/pkg/oidc"
)

// newSessionTestClient returns an *oidc.Client wired to a real cookie key so
// SetSession/GetSession round-trips work. The client never makes outbound
// network calls in these tests.
func newSessionTestClient(t *testing.T) *oidc.Client {
	t.Helper()
	c := oidc.New(oidc.Config{
		AuthURL:         "https://auth.example.test",
		ClientID:        "test",
		ClientSecret:    "test-secret",
		RedirectURL:     "https://app.example.test/callback",
		CookieKey:       "00112233445566778899aabbccddeeff",
		InsecureCookies: true,
		CookieName:      "test-session",
	})
	if c == nil {
		t.Fatal("oidc.New returned nil")
	}
	return c
}

func TestSessionAuthenticator_NilClient(t *testing.T) {
	var a *SessionAuthenticator
	_, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil receiver: got %v, want ErrUnauthenticated", err)
	}

	a = NewSessionAuthenticator(nil)
	_, err = a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil client: got %v, want ErrUnauthenticated", err)
	}
}

func TestSessionAuthenticator_NoCookie(t *testing.T) {
	c := newSessionTestClient(t)
	a := NewSessionAuthenticator(c)
	_, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("no cookie: got %v, want ErrUnauthenticated", err)
	}
}

func TestSessionAuthenticator_HappyPath(t *testing.T) {
	c := newSessionTestClient(t)

	// Write a session cookie via the real SetSession path so we exercise the
	// same encryption that GetSession will read.
	rec := httptest.NewRecorder()
	sess := &oidc.Session{
		AccessToken: "at-1",
		Expiry:      time.Now().Add(1 * time.Hour),
		User: oidc.User{
			Sub:          "u-1",
			Email:        "u@example.test",
			OrgID:        "org-1",
			ClientID:     "cli-x",
			Scopes:       []string{"read:projects"},
			OrgRoles:     []string{"admin"},
			IsSuperadmin: false,
		},
	}
	if err := c.SetSession(rec, sess); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	cookie := rec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	a := NewSessionAuthenticator(c)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Sub != "u-1" || id.OrgID != "org-1" || id.Email != "u@example.test" {
		t.Fatalf("identity fields: %+v", id)
	}
	if id.PrincipalType != "user" {
		t.Fatalf("PrincipalType = %q, want user", id.PrincipalType)
	}
	if id.ClientID != "cli-x" {
		t.Fatalf("ClientID = %q", id.ClientID)
	}
	if id.TokenID != "u-1" {
		t.Fatalf("TokenID = %q", id.TokenID)
	}
	if id.AuthMethod != MethodCookie {
		t.Fatalf("AuthMethod = %q, want %q", id.AuthMethod, MethodCookie)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "admin" {
		t.Fatalf("Roles = %v, want [admin]", id.Roles)
	}
}

func TestSessionAuthenticator_TamperedCookie(t *testing.T) {
	c := newSessionTestClient(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "test-session", Value: "not-base64-or-garbage"})
	a := NewSessionAuthenticator(c)
	_, err := a.Authenticate(req)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("tampered cookie: got %v, want ErrUnauthenticated", err)
	}
}

func TestSessionAuthenticator_RejectsInvalidLifecycle(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		sess oidc.Session
	}{
		{
			name: "empty subject",
			sess: oidc.Session{Expiry: now.Add(time.Hour)},
		},
		{
			name: "missing access token expiry",
			sess: oidc.Session{User: oidc.User{Sub: "u-1"}},
		},
		{
			name: "expired access token",
			sess: oidc.Session{Expiry: now.Add(-time.Minute), User: oidc.User{Sub: "u-1"}},
		},
		{
			name: "expired session window",
			sess: oidc.Session{
				Expiry:        now.Add(time.Hour),
				SessionExpiry: now.Add(-time.Minute),
				User:          oidc.User{Sub: "u-1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newSessionTestClient(t)
			rec := httptest.NewRecorder()
			if err := c.SetSession(rec, &tt.sess); err != nil {
				t.Fatalf("SetSession: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(rec.Result().Cookies()[0])
			_, err := NewSessionAuthenticator(c).Authenticate(req)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Authenticate error = %v, want ErrUnauthenticated", err)
			}
		})
	}
}
