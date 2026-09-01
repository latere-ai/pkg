package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func testClient(t *testing.T) *Client {
	t.Helper()
	cfg := Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://app.example.com/callback",
	}
	c := New(cfg)
	if c == nil {
		t.Fatal("New returned nil for valid config")
	}
	return c
}

func TestGetCookieWrapsUnmarshalError(t *testing.T) {
	c := testClient(t)
	// A decryptable cookie whose plaintext is not valid JSON must surface a
	// wrapped, cookie-attributed error like every other getCookie failure.
	ct, err := aesGCMEncrypt(c.cookieKey[:], []byte("not json"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: base64.RawURLEncoding.EncodeToString(ct),
	})
	_, err = c.GetSession(r)
	if err == nil || !strings.Contains(err.Error(), "unmarshal cookie") {
		t.Fatalf("err = %v, want wrapped \"unmarshal cookie\"", err)
	}
}

// --- Config ---

func TestLoadConfig(t *testing.T) {
	t.Setenv("AUTH_URL", "https://auth.test.com")
	t.Setenv("AUTH_CLIENT_ID", "cid")
	t.Setenv("AUTH_CLIENT_SECRET", "csec")
	t.Setenv("AUTH_REDIRECT_URL", "https://app.test.com/cb")
	t.Setenv("AUTH_COOKIE_KEY", "deadbeef")
	t.Setenv("AUTH_AUDIENCE", "https://auth.test.com")
	t.Setenv("AUTH_SCOPES", "openid,email profile offline_access")
	t.Setenv("AUTH_INSECURE_COOKIES", "true")

	cfg := LoadConfig()
	if cfg.AuthURL != "https://auth.test.com" {
		t.Errorf("AuthURL = %q, want %q", cfg.AuthURL, "https://auth.test.com")
	}
	if cfg.ClientID != "cid" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "cid")
	}
	if cfg.ClientSecret != "csec" {
		t.Errorf("ClientSecret = %q, want %q", cfg.ClientSecret, "csec")
	}
	if cfg.RedirectURL != "https://app.test.com/cb" {
		t.Errorf("RedirectURL = %q, want %q", cfg.RedirectURL, "https://app.test.com/cb")
	}
	if cfg.CookieKey != "deadbeef" {
		t.Errorf("CookieKey = %q, want %q", cfg.CookieKey, "deadbeef")
	}
	if cfg.Audience != "https://auth.test.com" {
		t.Errorf("Audience = %q, want %q", cfg.Audience, "https://auth.test.com")
	}
	if got := strings.Join(cfg.Scopes, " "); got != "openid email profile offline_access" {
		t.Errorf("Scopes = %q, want openid email profile offline_access", got)
	}
	if !cfg.InsecureCookies {
		t.Error("InsecureCookies = false, want true from AUTH_INSECURE_COOKIES")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	// AUTH_URL not set, should use default.
	cfg := LoadConfig()
	if cfg.AuthURL != "https://auth.latere.ai" {
		t.Errorf("default AuthURL = %q, want %q", cfg.AuthURL, "https://auth.latere.ai")
	}
}

func TestConfigEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"all set", Config{ClientID: "a", ClientSecret: "b", RedirectURL: "c"}, true},
		{"missing client_id", Config{ClientSecret: "b", RedirectURL: "c"}, false},
		{"public browser (no secret)", Config{ClientID: "a", RedirectURL: "c"}, true},
		{"confidential cc (no redirect)", Config{ClientID: "a", ClientSecret: "b"}, true},
		{"device-only (id only)", Config{ClientID: "a"}, true},
		{"empty", Config{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.Enabled(); got != tt.want {
				t.Errorf("Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- New ---

func TestNewDisabled(t *testing.T) {
	c := New(Config{})
	if c != nil {
		t.Error("New should return nil for disabled config")
	}
}

func TestNewWithHexCookieKey(t *testing.T) {
	cfg := Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
		CookieKey:    "0123456789abcdef0123456789abcdef", // 32 hex = 16 bytes
	}
	c := New(cfg)
	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.cookieKey == [32]byte{} {
		t.Error("cookie key should not be zero")
	}
}

func TestNewWithRawCookieKey(t *testing.T) {
	cfg := Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
		CookieKey:    "not-valid-hex!",
	}
	c := New(cfg)
	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.cookieKey == [32]byte{} {
		t.Error("cookie key should not be zero")
	}
}

func TestNewWithShortHexKey(t *testing.T) {
	// Valid hex but less than 16 bytes, should fall back to raw hashing.
	cfg := Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
		CookieKey:    "aabb", // 2 bytes
	}
	c := New(cfg)
	if c == nil {
		t.Fatal("New returned nil")
	}
}

func TestNewNoCookieKey(t *testing.T) {
	cfg := Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	}
	c := New(cfg)
	if c == nil {
		t.Fatal("New returned nil")
	}
}

// TestNewPublicClientNoCookieKey: a browser-mode public client (no secret) with
// no AUTH_COOKIE_KEY must be refused — proceeding would encrypt session cookies
// under sha256(""), a fixed publicly-known key.
func TestNewPublicClientNoCookieKey(t *testing.T) {
	cfg := Config{
		AuthURL:     "https://auth.example.com",
		ClientID:    "cid",
		RedirectURL: "https://app.example.com/cb",
		// no ClientSecret, no CookieKey
	}
	if c := New(cfg); c != nil {
		t.Error("New should return nil for a public browser client without AUTH_COOKIE_KEY")
	}
}

// TestNewPublicClientWithCookieKey: a public client with a cookie key is valid,
// gets a non-zero key, and uses the in-params auth style (client_id in body, no
// secret) so the token endpoint does not see an empty client_secret_basic.
func TestNewPublicClientWithCookieKey(t *testing.T) {
	cfg := Config{
		AuthURL:     "https://auth.example.com",
		ClientID:    "cid",
		RedirectURL: "https://app.example.com/cb",
		CookieKey:   "0123456789abcdef0123456789abcdef",
	}
	c := New(cfg)
	if c == nil {
		t.Fatal("New returned nil for public client with cookie key")
	}
	if c.cookieKey == [32]byte{} {
		t.Error("cookie key should not be zero")
	}
	if c.oauthCfg.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Errorf("public client AuthStyle = %v, want AuthStyleInParams", c.oauthCfg.Endpoint.AuthStyle)
	}
}

// TestNewConfidentialClientAuthStyle: a confidential client keeps
// client_secret_basic (auth style in header).
func TestNewConfidentialClientAuthStyle(t *testing.T) {
	cfg := Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
		CookieKey:    "0123456789abcdef0123456789abcdef",
	}
	c := New(cfg)
	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.oauthCfg.Endpoint.AuthStyle != oauth2.AuthStyleInHeader {
		t.Errorf("confidential client AuthStyle = %v, want AuthStyleInHeader", c.oauthCfg.Endpoint.AuthStyle)
	}
}

func TestAuthURL(t *testing.T) {
	c := testClient(t)
	if got := c.AuthURL(); got != "https://auth.example.com" {
		t.Errorf("AuthURL() = %q, want %q", got, "https://auth.example.com")
	}
}

// --- PKCE and state ---

func TestGenerateVerifier(t *testing.T) {
	v := GenerateVerifier()
	if v == "" {
		t.Error("verifier is empty")
	}
	if len(v) < 32 {
		t.Errorf("verifier length = %d, want >= 32", len(v))
	}
}

func TestGenerateVerifierUniqueness(t *testing.T) {
	v1 := GenerateVerifier()
	v2 := GenerateVerifier()
	if v1 == v2 {
		t.Error("two calls should produce different verifiers")
	}
}

func TestGenerateState(t *testing.T) {
	s := GenerateState()
	if s == "" {
		t.Error("state is empty")
	}
	// rand.Text yields 26 base32 characters, 128 bits of entropy.
	if len(s) != 26 {
		t.Errorf("state length = %d, want 26", len(s))
	}
}

func TestGenerateStateUniqueness(t *testing.T) {
	s1 := GenerateState()
	s2 := GenerateState()
	if s1 == s2 {
		t.Error("two calls should produce different states")
	}
}

// --- AuthCodeURL ---

func TestAuthCodeURL(t *testing.T) {
	c := testClient(t)
	verifier := GenerateVerifier()
	url := c.AuthCodeURL("test-state", verifier)

	if !strings.Contains(url, "https://auth.example.com/authorize") {
		t.Errorf("URL missing authorize endpoint: %s", url)
	}
	if !strings.Contains(url, "client_id=test-client") {
		t.Errorf("URL missing client_id: %s", url)
	}
	if !strings.Contains(url, "state=test-state") {
		t.Errorf("URL missing state: %s", url)
	}
	if !strings.Contains(url, "code_challenge=") {
		t.Errorf("URL missing code_challenge: %s", url)
	}
	if !strings.Contains(url, "code_challenge_method=S256") {
		t.Errorf("URL missing code_challenge_method: %s", url)
	}
	if !strings.Contains(url, "redirect_uri=") {
		t.Errorf("URL missing redirect_uri: %s", url)
	}
}

// --- FetchUserInfo ---

func TestFetchUserInfoSuccess(t *testing.T) {
	orig := httpDo
	t.Cleanup(func() { httpDo = orig })

	httpDo = func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer tok123" {
			t.Errorf("Authorization header = %q", req.Header.Get("Authorization"))
		}
		body := `{"sub":"u1","email":"a@b.com","name":"Alice","picture":"https://pic.test/a"}`
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}

	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)
	u, err := c.FetchUserInfo(r, "tok123")
	if err != nil {
		t.Fatalf("FetchUserInfo error: %v", err)
	}
	if u.Sub != "u1" || u.Email != "a@b.com" || u.Name != "Alice" || u.Picture != "https://pic.test/a" {
		t.Errorf("unexpected user: %+v", u)
	}
}

func TestFetchUserInfoHTTPError(t *testing.T) {
	orig := httpDo
	t.Cleanup(func() { httpDo = orig })

	httpDo = func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("network error")
	}

	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)
	_, err := c.FetchUserInfo(r, "tok")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "userinfo request") {
		t.Errorf("error = %q, want to contain 'userinfo request'", err.Error())
	}
}

func TestFetchUserInfoNon200(t *testing.T) {
	orig := httpDo
	t.Cleanup(func() { httpDo = orig })

	httpDo = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 403,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)
	_, err := c.FetchUserInfo(r, "tok")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %q, want to contain '403'", err.Error())
	}
}

func TestFetchUserInfoBadJSON(t *testing.T) {
	orig := httpDo
	t.Cleanup(func() { httpDo = orig })

	httpDo = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("not json")),
		}, nil
	}

	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)
	_, err := c.FetchUserInfo(r, "tok")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "decode userinfo") {
		t.Errorf("error = %q, want to contain 'decode userinfo'", err.Error())
	}
}

// --- Cookie round-trips ---

func TestFlowStateCookieRoundTrip(t *testing.T) {
	c := testClient(t)
	w := httptest.NewRecorder()

	want := &FlowState{
		CodeVerifier: "verifier123",
		State:        "state456",
		ReturnTo:     "/dashboard",
	}
	if err := c.SetFlowState(w, want); err != nil {
		t.Fatalf("SetFlowState error: %v", err)
	}

	// Build request with the cookie from the response.
	r := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range w.Result().Cookies() {
		r.AddCookie(cookie)
	}

	got, err := c.GetFlowState(r)
	if err != nil {
		t.Fatalf("GetFlowState error: %v", err)
	}
	if got.CodeVerifier != want.CodeVerifier || got.State != want.State || got.ReturnTo != want.ReturnTo {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestSessionCookieRoundTrip(t *testing.T) {
	c := testClient(t)
	w := httptest.NewRecorder()

	want := &Session{
		AccessToken:  "at-abc",
		RefreshToken: "rt-xyz",
		Expiry:       time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		User:         User{Sub: "u1", Email: "a@b.com", Name: "Alice"},
	}
	if err := c.SetSession(w, want); err != nil {
		t.Fatalf("SetSession error: %v", err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range w.Result().Cookies() {
		r.AddCookie(cookie)
	}

	got, err := c.GetSession(r)
	if err != nil {
		t.Fatalf("GetSession error: %v", err)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Errorf("tokens mismatch: got at=%q rt=%q", got.AccessToken, got.RefreshToken)
	}
	if got.User.Sub != want.User.Sub || got.User.Email != want.User.Email {
		t.Errorf("user mismatch: got %+v", got.User)
	}
	if !got.Expiry.Equal(want.Expiry) {
		t.Errorf("expiry mismatch: got %v, want %v", got.Expiry, want.Expiry)
	}
}

func TestClearFlowState(t *testing.T) {
	w := httptest.NewRecorder()
	ClearFlowState(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Name != FlowCookieName {
		t.Errorf("cookie name = %q", cookies[0].Name)
	}
	if cookies[0].MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cookies[0].MaxAge)
	}
}

func TestClearSession(t *testing.T) {
	w := httptest.NewRecorder()
	ClearSession(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Name != SessionCookieName {
		t.Errorf("cookie name = %q", cookies[0].Name)
	}
	if cookies[0].MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cookies[0].MaxAge)
	}
}

// --- getCookie error paths ---

func TestGetCookieNoCookie(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)

	_, err := c.GetSession(r)
	if err == nil {
		t.Fatal("expected error for missing cookie")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want to contain 'not found'", err.Error())
	}
}

func TestGetCookieBadBase64(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "%%%not-base64"})

	_, err := c.GetSession(r)
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
	if !strings.Contains(err.Error(), "decode cookie") {
		t.Errorf("error = %q, want to contain 'decode cookie'", err.Error())
	}
}

func TestGetCookieBadCiphertext(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)
	// Valid base64 but garbage ciphertext.
	r.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: base64.RawURLEncoding.EncodeToString([]byte("short")),
	})

	_, err := c.GetSession(r)
	if err == nil {
		t.Fatal("expected error for bad ciphertext")
	}
	if !strings.Contains(err.Error(), "decrypt cookie") {
		t.Errorf("error = %q, want to contain 'decrypt cookie'", err.Error())
	}
}

func TestGetCookieBadJSON(t *testing.T) {
	c := testClient(t)

	// Encrypt non-JSON data.
	ciphertext, err := aesGCMEncrypt(c.cookieKey[:], []byte("not-json"))
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: base64.RawURLEncoding.EncodeToString(ciphertext),
	})

	_, err = c.GetSession(r)
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestGetCookieWrongKey(t *testing.T) {
	c1 := testClient(t)
	w := httptest.NewRecorder()
	if err := c1.SetSession(w, &Session{AccessToken: "tok"}); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	// Create a second client with a different key.
	cfg2 := Config{
		AuthURL:      "https://auth.example.com",
		ClientID:     "test-client",
		ClientSecret: "different-secret",
		RedirectURL:  "https://app.example.com/callback",
	}
	c2 := New(cfg2)

	r := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range w.Result().Cookies() {
		r.AddCookie(cookie)
	}

	_, err := c2.GetSession(r)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

// --- setCookie error paths ---

func TestSetCookieEncryptError(t *testing.T) {
	orig := aesGCMEncrypt
	t.Cleanup(func() { aesGCMEncrypt = orig })

	aesGCMEncrypt = func(key, plaintext []byte) ([]byte, error) {
		return nil, fmt.Errorf("injected encrypt error")
	}

	c := testClient(t)
	w := httptest.NewRecorder()
	err := c.SetSession(w, &Session{AccessToken: "tok"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "encrypt cookie") {
		t.Errorf("error = %q, want to contain 'encrypt cookie'", err.Error())
	}
}

// --- AES-GCM ---

func TestAESGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("hello world")

	ct, err := defaultAESGCMEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	pt, err := aesGCMDecrypt(key, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "hello world" {
		t.Errorf("decrypted = %q, want %q", pt, "hello world")
	}
}

func TestAESGCMDecryptShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := aesGCMDecrypt(key, []byte("x"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
	if !strings.Contains(err.Error(), "ciphertext too short") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestAESGCMDecryptTampered(t *testing.T) {
	key := make([]byte, 32)
	ct, _ := defaultAESGCMEncrypt(key, []byte("data"))

	// Flip a byte in the ciphertext portion.
	ct[len(ct)-1] ^= 0xff
	_, err := aesGCMDecrypt(key, ct)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

// --- Cookie attributes ---

func TestSessionCookieAttributes(t *testing.T) {
	c := testClient(t)
	w := httptest.NewRecorder()
	if err := c.SetSession(w, &Session{AccessToken: "tok"}); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	ck := cookies[0]
	if ck.Name != SessionCookieName {
		t.Errorf("name = %q", ck.Name)
	}
	if !ck.HttpOnly {
		t.Error("expected HttpOnly")
	}
	if !ck.Secure {
		t.Error("expected Secure")
	}
	if ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", ck.SameSite)
	}
	if ck.MaxAge != SessionMaxAge {
		t.Errorf("MaxAge = %d, want %d", ck.MaxAge, SessionMaxAge)
	}
	if ck.Path != "/" {
		t.Errorf("Path = %q, want /", ck.Path)
	}
}

func TestFlowCookieAttributes(t *testing.T) {
	c := testClient(t)
	w := httptest.NewRecorder()
	if err := c.SetFlowState(w, &FlowState{CodeVerifier: "v", State: "s"}); err != nil {
		t.Fatalf("SetFlowState: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].MaxAge != FlowMaxAge {
		t.Errorf("MaxAge = %d, want %d", cookies[0].MaxAge, FlowMaxAge)
	}
}

// --- SetCookie marshal error ---

func TestSetCookieMarshalError(t *testing.T) {
	c := testClient(t)
	w := httptest.NewRecorder()

	// json.Marshal fails for channels.
	err := c.setCookie(w, "test", make(chan int), 100)
	if err == nil {
		t.Fatal("expected error for unmarshalable value")
	}
	if !strings.Contains(err.Error(), "marshal cookie") {
		t.Errorf("error = %q, want to contain 'marshal cookie'", err.Error())
	}
}

// --- Exchange (needs a token server) ---

func TestExchange(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if r.FormValue("code") != "authcode" {
			t.Errorf("code = %q", r.FormValue("code"))
		}
		if r.FormValue("code_verifier") != "pkce-verifier" {
			t.Errorf("code_verifier = %q", r.FormValue("code_verifier"))
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-at",
			"token_type":    "Bearer",
			"refresh_token": "new-rt",
			"expires_in":    3600,
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	}
	c := New(cfg)

	r := httptest.NewRequest("GET", "/callback?code=authcode", nil)
	tok, err := c.Exchange(r, "authcode", "pkce-verifier")
	if err != nil {
		t.Fatalf("Exchange error: %v", err)
	}
	if tok.AccessToken != "new-at" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "new-rt" {
		t.Errorf("RefreshToken = %q", tok.RefreshToken)
	}
}

// --- RefreshToken ---

func TestRefreshToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q", r.FormValue("grant_type"))
		}
		if r.FormValue("refresh_token") != "old-rt" {
			t.Errorf("refresh_token = %q", r.FormValue("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "refreshed-at",
			"token_type":    "Bearer",
			"refresh_token": "new-rt",
			"expires_in":    3600,
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	}))
	defer ts.Close()

	cfg := Config{
		AuthURL:      ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	}
	c := New(cfg)

	r := httptest.NewRequest("GET", "/", nil)
	tok, err := c.RefreshToken(r, "old-rt")
	if err != nil {
		t.Fatalf("RefreshToken error: %v", err)
	}
	if tok.AccessToken != "refreshed-at" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
}

// --- rand error paths ---

func TestGenerateVerifierNonEmpty(t *testing.T) {
	v := GenerateVerifier()
	if v == "" {
		t.Fatal("expected non-empty verifier")
	}
}

// --- AES with invalid key sizes ---

func TestAESGCMEncryptBadKey(t *testing.T) {
	_, err := defaultAESGCMEncrypt([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestAESGCMDecryptBadKey(t *testing.T) {
	// 12 bytes nonce + 1 byte ciphertext to pass the length check.
	ct := make([]byte, 13)
	_, err := aesGCMDecrypt([]byte("short"), ct)
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

// --- GetFlowState error path ---

func TestGetFlowStateNoCookie(t *testing.T) {
	c := testClient(t)
	r := httptest.NewRequest("GET", "/", nil)

	_, err := c.GetFlowState(r)
	if err == nil {
		t.Fatal("expected error for missing flow cookie")
	}
}

// --- FetchUserInfo context error ---

func TestFetchUserInfoBadURL(t *testing.T) {
	cfg := Config{
		AuthURL:      "://invalid",
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app.example.com/cb",
	}
	c := New(cfg)
	r := httptest.NewRequest("GET", "/", nil)
	_, err := c.FetchUserInfo(r, "tok")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}

// --- Fuzz tests ---

func FuzzAESGCMRoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add([]byte("a longer plaintext string with various characters!@#$%"))

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		ct, err := defaultAESGCMEncrypt(key, plaintext)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		pt, err := aesGCMDecrypt(key, ct)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if len(plaintext) == 0 && len(pt) == 0 {
			return // both empty is fine
		}
		if string(pt) != string(plaintext) {
			t.Errorf("round-trip mismatch")
		}
	})
}

func TestDeviceOnlyClientCookieHelpersFailClosed(t *testing.T) {
	// A device-only client (no RedirectURL) never derives a cookie key, so the
	// browser cookie helpers must fail closed rather than seal a session under
	// the all-zero, publicly-known AES key.
	c := New(Config{ClientID: "cli"})
	if c == nil {
		t.Fatal("device-only client should be constructed")
	}
	if c.cookieKeyConfigured() {
		t.Fatal("device-only client must not have a configured cookie key")
	}

	w := httptest.NewRecorder()
	if err := c.SetSession(w, &Session{AccessToken: "x"}); !errors.Is(err, errNoCookieKey) {
		t.Errorf("SetSession err = %v, want errNoCookieKey", err)
	}
	if err := c.SetFlowState(w, &FlowState{}); !errors.Is(err, errNoCookieKey) {
		t.Errorf("SetFlowState err = %v, want errNoCookieKey", err)
	}
	if got := len(w.Result().Cookies()); got != 0 {
		t.Errorf("fail-closed path must emit no cookies, got %d", got)
	}

	// Reading also fails closed.
	r := httptest.NewRequest("GET", "/", nil)
	if _, err := c.GetFlowState(r); !errors.Is(err, errNoCookieKey) {
		t.Errorf("GetFlowState err = %v, want errNoCookieKey", err)
	}
}
