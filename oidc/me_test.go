package oidc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInitials(t *testing.T) {
	cases := []struct{ name, email, want string }{
		{"Ada Lovelace", "a@b.c", "AL"},
		{"Ada", "a@b.c", "A"},
		{"", "hi@changkun.de", "H"},
		{"   ", "", "?"},
		{"grace b hopper", "x@y.z", "GH"},
	}
	for _, tc := range cases {
		if got := Initials(tc.name, tc.email); got != tc.want {
			t.Errorf("Initials(%q,%q) = %q, want %q", tc.name, tc.email, got, tc.want)
		}
	}
}

func sessionRequest(t *testing.T, c *Client, sess *Session) (*http.Request, http.ResponseWriter) {
	t.Helper()
	ws := httptest.NewRecorder()
	if err := c.SetSession(ws, sess); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	for _, ck := range ws.Result().Cookies() {
		r.AddCookie(ck)
	}
	return r, httptest.NewRecorder()
}

// TestBuildMe_FullPrincipal pins the shared /me assembly: one /userinfo + one
// /me/orgs call off a single token, with initials + active org name derived.
func TestBuildMe_FullPrincipal(t *testing.T) {
	orig := httpDo
	t.Cleanup(func() { httpDo = orig })
	httpDo = func(req *http.Request) (*http.Response, error) {
		var body string
		switch {
		case strings.HasSuffix(req.URL.Path, "/userinfo"):
			body = `{"sub":"u1","email":"ada@latere.ai","name":"Ada Lovelace","picture":"https://pic/a","org_id":"org-1"}`
		case strings.HasSuffix(req.URL.Path, "/me/orgs"):
			body = `[{"id":"org-1","name":"Acme","slug":"acme","owner":true},{"id":"org-2","name":"Globex"}]`
		default:
			return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	}

	c := testClient(t)
	jwt := makeJWT(map[string]string{"sub": "u1", "email": "ada@latere.ai", "org_id": "org-1"})
	r, w := sessionRequest(t, c, &Session{AccessToken: jwt, Expiry: time.Now().Add(time.Hour)})

	me, err := c.BuildMe(w, r)
	if err != nil {
		t.Fatalf("BuildMe degraded unexpectedly: %v", err)
	}
	if me == nil {
		t.Fatal("BuildMe returned nil for an authenticated request")
	}
	if me.Name != "Ada Lovelace" || me.AvatarURL != "https://pic/a" {
		t.Errorf("profile = %+v", me)
	}
	if me.Initials != "AL" {
		t.Errorf("Initials = %q, want AL", me.Initials)
	}
	if me.OrgID != "org-1" || me.OrgName != "Acme" {
		t.Errorf("org = %q/%q, want org-1/Acme", me.OrgID, me.OrgName)
	}
	if len(me.Orgs) != 2 {
		t.Errorf("orgs = %+v, want 2", me.Orgs)
	}
}

func TestBuildMe_Unauthenticated(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	me, err := c.BuildMe(w, r)
	if me != nil || err != nil {
		t.Errorf("BuildMe(no session) = (%+v, %v), want (nil, nil)", me, err)
	}
}

// TestBuildMe_OrgsDegraded: a 401 on /me/orgs (e.g. aud mismatch) returns a
// populated profile plus a non-nil error so the caller can log it, instead of
// silently showing an empty switcher.
func TestBuildMe_OrgsDegraded(t *testing.T) {
	orig := httpDo
	t.Cleanup(func() { httpDo = orig })
	httpDo = func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/userinfo") {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
				`{"sub":"u1","name":"Ada","email":"ada@latere.ai"}`))}, nil
		}
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(
			`{"error":"unauthorized"}`))}, nil
	}
	c := testClient(t)
	jwt := makeJWT(map[string]string{"sub": "u1", "email": "ada@latere.ai"})
	r, w := sessionRequest(t, c, &Session{AccessToken: jwt, Expiry: time.Now().Add(time.Hour)})

	me, err := c.BuildMe(w, r)
	if me == nil {
		t.Fatal("BuildMe returned nil despite a valid session")
	}
	if err == nil {
		t.Error("BuildMe should surface the /me/orgs degradation as a non-nil error")
	}
	if me.Name != "Ada" {
		t.Errorf("profile should still resolve; Name = %q", me.Name)
	}
	if len(me.Orgs) != 0 {
		t.Errorf("orgs should be empty on 401, got %+v", me.Orgs)
	}
}

// SwitchOrgRedirect clears the session cookie and builds the login URL.
func TestSwitchOrgRedirect(t *testing.T) {
	w := httptest.NewRecorder()
	got := SwitchOrgRedirect(w, "org-9", "/playground")
	if got != "/login?return_to=/playground&org_id=org-9" {
		t.Errorf("url = %q", got)
	}
	if personal := SwitchOrgRedirect(httptest.NewRecorder(), "", "/x"); personal != "/login?return_to=/x" {
		t.Errorf("personal url = %q", personal)
	}
	// session cookie must be cleared (Max-Age<=0).
	var cleared bool
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge < 0 || (ck.MaxAge == 0 && ck.Value == "") {
			cleared = true
		}
	}
	if !cleared {
		t.Error("SwitchOrgRedirect did not clear the session cookie")
	}
}
