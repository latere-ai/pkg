package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// assertNoClientSecret fails if a token request carries client authentication —
// a public client must send client_id in the body and no Authorization header.
func assertNoClientSecret(t *testing.T, r *http.Request) {
	t.Helper()
	if h := r.Header.Get("Authorization"); h != "" {
		t.Errorf("public client sent Authorization header: %q", h)
	}
	if s := r.FormValue("client_secret"); s != "" {
		t.Errorf("public client sent client_secret: %q", s)
	}
	if id := r.FormValue("client_id"); id != "pub-cid" {
		t.Errorf("client_id in body = %q, want pub-cid", id)
	}
}

func newPublicClient(t *testing.T, authURL string) *Client {
	t.Helper()
	c := New(Config{
		AuthURL:     authURL,
		ClientID:    "pub-cid",
		RedirectURL: "https://app.example.com/cb",
		// No ClientSecret → public client.
		CookieKey:       "0123456789abcdef0123456789abcdef",
		CookieName:      "__custom_session",
		SessionTTL:      30 * 24 * time.Hour,
		InsecureCookies: true,
	})
	if c == nil {
		t.Fatal("New returned nil for public client")
	}
	return c
}

// TestPublicClientExchangeSendsNoSecret proves the secret-less authorization_code
// exchange works through pkg/oidc's own provider: client_id rides in the body,
// no Authorization header, and the PKCE verifier is sent.
func TestPublicClientExchangeSendsNoSecret(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", r.FormValue("grant_type"))
		}
		assertNoClientSecret(t, r)
		if r.FormValue("code_verifier") == "" {
			t.Error("PKCE code_verifier missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-1", "token_type": "Bearer", "refresh_token": "rt-1", "expires_in": 3600,
		})
	}))
	defer ts.Close()

	c := newPublicClient(t, ts.URL)
	tok, err := c.ExchangeContext(t.Context(), "the-code", GenerateVerifier())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken != "at-1" || tok.RefreshToken != "rt-1" {
		t.Errorf("tokens = at:%q rt:%q", tok.AccessToken, tok.RefreshToken)
	}
}

// TestPublicClientRefreshRotationRoundTrip is the end-to-end proof the spec
// required: a public client (no secret) refreshes through SessionFromRequest,
// the server ROTATES the refresh token, the rotated token is persisted into the
// session, and a second refresh succeeds presenting the rotated token. The fake
// server revokes (400s) any token it has already rotated away, so a failure to
// persist would surface as a dead session on the second refresh — the exact
// production time-bomb this guards against.
func TestPublicClientRefreshRotationRoundTrip(t *testing.T) {
	rotations := map[string]string{"rt-1": "rt-2", "rt-2": "rt-3"}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q", r.FormValue("grant_type"))
		}
		assertNoClientSecret(t, r)
		in := r.FormValue("refresh_token")
		next, ok := rotations[in]
		if !ok {
			// Reuse of an already-rotated token → family revoked (OAuth 2.1).
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-for-" + next, "token_type": "Bearer", "refresh_token": next, "expires_in": 3600,
		})
	}))
	defer ts.Close()

	c := newPublicClient(t, ts.URL)
	keep := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)

	// First refresh: session holds rt-1 with an expired access token.
	r1 := seedCookie(t, c, &Session{
		AccessToken:   "old-at",
		RefreshToken:  "rt-1",
		Expiry:        time.Now().UTC().Add(-time.Minute),
		SessionExpiry: keep,
	})
	w1 := httptest.NewRecorder()
	s1, err := c.SessionFromRequest(w1, r1)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if s1.RefreshToken != "rt-2" {
		t.Fatalf("rotated refresh token not persisted: got %q, want rt-2", s1.RefreshToken)
	}
	if s1.AccessToken != "at-for-rt-2" {
		t.Errorf("access token = %q, want at-for-rt-2", s1.AccessToken)
	}

	// Second refresh drives off the persisted session (which now holds rt-2),
	// with the access token forced expired again. If persistence were broken the
	// session would still hold rt-1 and the server would 400 on reuse.
	s1.Expiry = time.Now().UTC().Add(-time.Minute)
	r2 := seedCookie(t, c, s1)
	w2 := httptest.NewRecorder()
	s2, err := c.SessionFromRequest(w2, r2)
	if err != nil {
		t.Fatalf("second refresh (rotation persistence broken?): %v", err)
	}
	if s2.RefreshToken != "rt-3" {
		t.Errorf("second rotation = %q, want rt-3", s2.RefreshToken)
	}
}
