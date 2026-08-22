package oidclogin

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// fakeIDP is an httptest OIDC issuer: it serves a discovery document, a JWKS,
// and mints RS256-signed tokens with a test key, so the verify path runs
// end-to-end without a real IDP.
type fakeIDP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	return newFakeIDPServer(t, false)
}

func newFakeTLSIDP(t *testing.T) *fakeIDP {
	return newFakeIDPServer(t, true)
}

func newFakeIDPServer(t *testing.T, tls bool) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	f := &fakeIDP{key: key, kid: "test-kid"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:                f.srv.URL,
			AuthorizationEndpoint: f.srv.URL + "/authorize",
			TokenEndpoint:         f.srv.URL + "/token",
			JWKSURI:               f.srv.URL + "/jwks.json",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Mint an id_token + access_token for the happy-path Exchange test. The
		// nonce is fixed to "flow-nonce" to match TestExchangeAndVerify.
		idToken := f.signRS256(t, baseIDClaims(f, "client-1", "flow-nonce"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "opaque-at",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": f.kid, "n": n, "e": e,
			}},
		})
	})
	if tls {
		f.srv = httptest.NewTLSServer(mux)
	} else {
		f.srv = httptest.NewServer(mux)
	}
	t.Cleanup(f.srv.Close)
	return f
}

// signRS256 mints an RS256 JWT with the given claims and the IDP's kid.
func (f *fakeIDP) signRS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	return signWith(t, f.key, f.kid, "RS256", claims)
}

func signWith(t *testing.T, key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": alg, "typ": "JWT", "kid": kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	if alg == "none" {
		return signingInput + "."
	}
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// tokenWithID wraps an id_token (and optional access token) into an oauth2.Token.
func tokenWithID(idToken, accessToken string) *oauth2.Token {
	tok := &oauth2.Token{AccessToken: accessToken}
	return tok.WithExtra(map[string]any{"id_token": idToken})
}

func baseIDClaims(idp *fakeIDP, clientID, nonce string) map[string]any {
	return map[string]any{
		"iss":   idp.srv.URL,
		"sub":   "user-123",
		"aud":   clientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"nonce": nonce,
		"email": "u@example.com",
		"name":  "Test User",
	}
}

func newAuth(t *testing.T, idp *fakeIDP, clientID, provider string) *Authenticator {
	t.Helper()
	a, err := New(context.Background(), Config{
		Issuer:      idp.srv.URL,
		ClientID:    clientID,
		RedirectURL: "https://app.example.com/cb",
		Provider:    provider,
		HTTPClient:  idp.srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestNew_RequiresFields(t *testing.T) {
	if _, err := New(context.Background(), Config{ClientID: "c", RedirectURL: "r"}); err == nil {
		t.Error("missing issuer should error")
	}
}

func TestNew_UnknownProvider(t *testing.T) {
	idp := newFakeIDP(t)
	_, err := New(context.Background(), Config{
		Issuer: idp.srv.URL, ClientID: "c", RedirectURL: "r", Provider: "nope", HTTPClient: idp.srv.Client(),
	})
	if err == nil {
		t.Error("unknown provider should error")
	}
}

func TestAuthCodeURL_PKCEandNonce(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	u := a.AuthCodeURL("state-1", "nonce-1", GenerateVerifier())
	for _, want := range []string{"code_challenge=", "code_challenge_method=S256", "nonce=nonce-1", "state=state-1", "client_id=client-1"} {
		if !strings.Contains(u, want) {
			t.Errorf("AuthCodeURL missing %q: %s", want, u)
		}
	}
}

func TestVerifyIDToken_HappyPath(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	idToken := idp.signRS256(t, baseIDClaims(idp, "client-1", "nonce-1"))

	id, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, ""), "nonce-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Subject != "user-123" || id.Email != "u@example.com" || id.Name != "Test User" {
		t.Errorf("identity = %+v", id)
	}
	if id.Raw["sub"] != "user-123" {
		t.Error("Raw claims not populated")
	}
}

func TestVerifyIDToken_UsesConfiguredHTTPClientForJWKS(t *testing.T) {
	idp := newFakeTLSIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	idToken := idp.signRS256(t, baseIDClaims(idp, "client-1", "nonce-1"))
	if _, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, ""), "nonce-1"); err != nil {
		t.Fatalf("VerifyIDToken through configured TLS client: %v", err)
	}
}

func TestVerifyIDToken_MissingIDToken(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	if _, err := a.VerifyIDToken(context.Background(), &oauth2.Token{}, "n"); err == nil {
		t.Error("missing id_token must error")
	}
}

func TestVerifyIDToken_NonceMismatch(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	idToken := idp.signRS256(t, baseIDClaims(idp, "client-1", "real-nonce"))
	if _, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, ""), "attacker-nonce"); err == nil {
		t.Error("nonce mismatch must be rejected")
	}
}

func TestVerifyIDToken_IssuerMismatch(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	claims := baseIDClaims(idp, "client-1", "nonce-1")
	claims["iss"] = "https://evil.example.com"
	idToken := idp.signRS256(t, claims)
	if _, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, ""), "nonce-1"); err == nil {
		t.Error("issuer mismatch must be rejected")
	}
}

func TestVerifyIDToken_AudienceMismatch(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	claims := baseIDClaims(idp, "other-client", "nonce-1")
	idToken := idp.signRS256(t, claims)
	if _, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, ""), "nonce-1"); err == nil {
		t.Error("audience mismatch must be rejected")
	}
}

// TestVerifyIDToken_AlgNoneRejected proves the verified path cannot be bypassed
// with an unsigned (alg=none) token — the core security guarantee of this layer.
func TestVerifyIDToken_AlgNoneRejected(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	idToken := signWith(t, idp.key, idp.kid, "none", baseIDClaims(idp, "client-1", "nonce-1"))
	if _, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, ""), "nonce-1"); err == nil {
		t.Error("alg=none token must be rejected")
	}
}

// TestVerifyIDToken_WrongKeyRejected proves a token signed by a different key
// (a forged/HS-style confusion stand-in) is rejected.
func TestVerifyIDToken_WrongKeyRejected(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	idToken := signWith(t, other, idp.kid, "RS256", baseIDClaims(idp, "client-1", "nonce-1"))
	if _, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, ""), "nonce-1"); err == nil {
		t.Error("token signed by an unknown key must be rejected")
	}
}

func TestVerifyIDToken_ExpiredRejected(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	claims := baseIDClaims(idp, "client-1", "nonce-1")
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	idToken := idp.signRS256(t, claims)
	if _, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, ""), "nonce-1"); err == nil {
		t.Error("expired token must be rejected")
	}
}

// TestLatereMapper_RolesFromAccessToken proves the verify-before-trust access
// path: a valid access token's roles are unioned in.
func TestLatereMapper_RolesFromAccessToken(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	idToken := idp.signRS256(t, baseIDClaims(idp, "client-1", "nonce-1"))
	atClaims := map[string]any{
		"iss": idp.srv.URL, "sub": "user-123", "exp": time.Now().Add(time.Hour).Unix(),
		"roles": []any{"admin", "member"},
	}
	at := idp.signRS256(t, atClaims)
	id, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, at), "nonce-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(id.Roles) != 2 {
		t.Errorf("roles = %v, want [admin member]", id.Roles)
	}
}

// TestVerifyIDToken_OpaqueAccessTokenIgnored proves an unverifiable (opaque)
// access token degrades to nil roles, not an error.
func TestVerifyIDToken_OpaqueAccessTokenIgnored(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	idToken := idp.signRS256(t, baseIDClaims(idp, "client-1", "nonce-1"))
	id, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, "opaque-access-token"), "nonce-1")
	if err != nil {
		t.Fatalf("opaque access token must not fail login: %v", err)
	}
	if len(id.Roles) != 0 {
		t.Errorf("roles = %v, want none", id.Roles)
	}
}

func TestFetchDiscovery_Errors(t *testing.T) {
	// Non-200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := New(context.Background(), Config{Issuer: srv.URL, ClientID: "c", RedirectURL: "r", HTTPClient: srv.Client()}); err == nil {
		t.Error("discovery non-200 should error")
	}

	// Missing endpoints.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryDoc{Issuer: "x"})
	}))
	defer srv2.Close()
	if _, err := New(context.Background(), Config{Issuer: srv2.URL, ClientID: "c", RedirectURL: "r", HTTPClient: srv2.Client()}); err == nil {
		t.Error("discovery missing endpoints should error")
	}
}

func TestIssuerOK(t *testing.T) {
	cases := []struct {
		got, want string
		ok        bool
	}{
		{"https://accounts.google.com", "https://accounts.google.com", true},
		{"accounts.google.com", "https://accounts.google.com", true},
		{"https://accounts.google.com", "accounts.google.com", true},
		{"https://evil.com", "https://auth.latere.ai", false},
		{"", "x", false},
		{"x", "", false},
	}
	for _, c := range cases {
		if got := issuerOK(c.got, c.want); got != c.ok {
			t.Errorf("issuerOK(%q,%q) = %v, want %v", c.got, c.want, got, c.ok)
		}
	}
}

// TestExchangeAndVerify drives the full flow: Exchange against the fake token
// endpoint, then VerifyIDToken on the result.
func TestExchangeAndVerify(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	tok, err := a.Exchange(context.Background(), "the-code", GenerateVerifier())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	id, err := a.VerifyIDToken(context.Background(), tok, "flow-nonce")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Subject != "user-123" {
		t.Errorf("subject = %q", id.Subject)
	}
}

func TestExchange_Error(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	// Point the token URL at a dead address to force an exchange error.
	a.oauth.Endpoint.TokenURL = "http://127.0.0.1:0/token"
	if _, err := a.Exchange(context.Background(), "c", "v"); err == nil {
		t.Error("exchange against dead endpoint should error")
	}
}

func TestVerifyIDToken_MalformedIDToken(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "latere")
	if _, err := a.VerifyIDToken(context.Background(), tokenWithID("not-a-jwt", ""), "n"); err == nil {
		t.Error("malformed id_token must error")
	}
}

func TestDecodeJWTPayload_Errors(t *testing.T) {
	if _, err := decodeJWTPayload("only.two"); err == nil {
		t.Error("two segments should error")
	}
	if _, err := decodeJWTPayload("a.!!!.c"); err == nil {
		t.Error("bad base64 should error")
	}
	if _, err := decodeJWTPayload("a." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c"); err == nil {
		t.Error("bad json should error")
	}
}

func TestStringsClaim(t *testing.T) {
	if got := stringsClaim([]any{"a", "b", 3, ""}); len(got) != 2 {
		t.Errorf("[]any → %v", got)
	}
	if got := stringsClaim("solo"); len(got) != 1 || got[0] != "solo" {
		t.Errorf("string → %v", got)
	}
	if got := stringsClaim(""); got != nil {
		t.Errorf("empty string → %v, want nil", got)
	}
	if got := stringsClaim(42); got != nil {
		t.Errorf("non-string → %v, want nil", got)
	}
}

func TestUnionStrings(t *testing.T) {
	got := unionStrings([]string{"a", "b"}, []string{"b", "c"})
	if len(got) != 3 {
		t.Errorf("union = %v, want [a b c]", got)
	}
}
