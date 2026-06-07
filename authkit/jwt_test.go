package authkit

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"latere.ai/x/pkg/jwtauth"
)

// ── clientIDFromJWT ──────────────────────────────────────────────────────────

func encodePayload(t *testing.T, payload string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return header + "." + body + "." + sig
}

func TestClientIDFromJWTHappyPath(t *testing.T) {
	tok := encodePayload(t, `{"client_id":"agent-client"}`)
	if got := clientIDFromJWT(tok); got != "agent-client" {
		t.Fatalf("got %q", got)
	}
}

func TestClientIDFromJWTMissingClaim(t *testing.T) {
	tok := encodePayload(t, `{"sub":"u"}`)
	if got := clientIDFromJWT(tok); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestClientIDFromJWTNotThreeParts(t *testing.T) {
	if got := clientIDFromJWT("not.a.valid.token.at.all"); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := clientIDFromJWT("only"); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := clientIDFromJWT(""); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestClientIDFromJWTBadBase64(t *testing.T) {
	if got := clientIDFromJWT("a.!!notbase64!!.c"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestClientIDFromJWTBadJSON(t *testing.T) {
	body := base64.RawURLEncoding.EncodeToString([]byte("{not json"))
	tok := strings.Join([]string{"hdr", body, "sig"}, ".")
	if got := clientIDFromJWT(tok); got != "" {
		t.Fatalf("got %q", got)
	}
}

// ── firstNonEmpty ────────────────────────────────────────────────────────────

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty(); got != "" {
		t.Fatalf("empty input: %q", got)
	}
	if got := firstNonEmpty("", "", ""); got != "" {
		t.Fatalf("all empty: %q", got)
	}
	if got := firstNonEmpty("", "a", "b"); got != "a" {
		t.Fatalf("first non-empty: %q", got)
	}
	if got := firstNonEmpty("only"); got != "only" {
		t.Fatalf("single: %q", got)
	}
}

// ── constantEq ───────────────────────────────────────────────────────────────

func TestConstantEq(t *testing.T) {
	if !constantEq("hello", "hello") {
		t.Fatal("equal strings should match")
	}
	if constantEq("hello", "world") {
		t.Fatal("different strings should not match")
	}
	if constantEq("short", "longer") {
		t.Fatal("different lengths should not match")
	}
	// empty == empty is true (length 0 == 0, no bytes, v == 0)
	if !constantEq("", "") {
		t.Fatal("empty == empty should be true")
	}
}

// ── JWT.Authenticate (via fake validator) ────────────────────────────────────

// fakeValidator implements the validator interface.
type fakeValidator struct {
	claims *jwtauth.Claims
	err    error
}

func (f *fakeValidator) Validate(string) (*jwtauth.Claims, error) {
	return f.claims, f.err
}

func newJWTWithFakeValidator(v validator, ti *TokenInfoClient) *JWT {
	return &JWT{V: v, TokenInfo: ti}
}

func TestNewJWT(t *testing.T) {
	// NewJWT accepts a *jwtauth.Validator and *TokenInfoClient.
	// We use a nil validator to verify the constructor doesn't panic and
	// returns a non-nil *JWT with fields wired correctly.
	ti := NewTokenInfoClient("https://auth.test/tokeninfo")
	j := NewJWT(nil, ti)
	if j == nil {
		t.Fatal("NewJWT returned nil")
	}
	// V field is assigned (even if nil *jwtauth.Validator, interface holds it).
	if j.TokenInfo != ti {
		t.Fatal("TokenInfo not wired")
	}
}

func TestJWTAuthenticateMissingHeader(t *testing.T) {
	j := newJWTWithFakeValidator(&fakeValidator{}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := j.Authenticate(r)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("got %v, want ErrUnauthenticated", err)
	}
}

func TestJWTAuthenticateValidateError(t *testing.T) {
	sentinel := errors.New("bad token")
	j := newJWTWithFakeValidator(&fakeValidator{err: sentinel}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer sometoken")
	_, err := j.Authenticate(r)
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want sentinel", err)
	}
}

func TestJWTAuthenticateLocalToken(t *testing.T) {
	claims := &jwtauth.Claims{
		Sub:           "u-1",
		OrgID:         "org-1",
		Email:         "a@b.com",
		PrincipalType: jwtauth.PrincipalUser,
		IsSuperadmin:  false,
		Scopes:        []string{"read:projects"},
	}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims}, nil)
	// Encode a payload with no client_id claim.
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u-1"}`))
	raw := "hdr." + payload + ".sig"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	id, err := j.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Sub != "u-1" || id.OrgID != "org-1" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if id.TokenID != "u-1" {
		t.Fatalf("TokenID = %q, want u-1", id.TokenID)
	}
	if id.AuthMethod != MethodBearer {
		t.Fatalf("AuthMethod = %q, want %q", id.AuthMethod, MethodBearer)
	}
}

func TestJWTAuthenticateLocalTokenWithClientID(t *testing.T) {
	claims := &jwtauth.Claims{
		Sub:           "u-1",
		PrincipalType: jwtauth.PrincipalUser,
	}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims}, nil)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u-1","client_id":"cli-abc"}`))
	raw := "hdr." + payload + ".sig"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	id, err := j.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.ClientID != "cli-abc" {
		t.Fatalf("ClientID = %q, want cli-abc", id.ClientID)
	}
}

func TestJWTAuthenticateStrictAgentNoTokenInfoClient(t *testing.T) {
	claims := &jwtauth.Claims{
		Sub:           "agent-1",
		PrincipalType: jwtauth.PrincipalAgent,
		Validation:    jwtauth.ValidationStrict,
	}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims}, nil)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"agent-1"}`))
	raw := "hdr." + payload + ".sig"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	_, err := j.Authenticate(r)
	if err == nil || !strings.Contains(err.Error(), "tokeninfo client not configured") {
		t.Fatalf("expected tokeninfo error, got %v", err)
	}
}

func TestJWTAuthenticateStrictAgentWithTokenInfo(t *testing.T) {
	claims := &jwtauth.Claims{
		Sub:           "agent-1",
		PrincipalType: jwtauth.PrincipalAgent,
		Validation:    jwtauth.ValidationStrict,
	}
	// Serve a fake tokeninfo endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sub":"agent-1","principal_type":"agent","org_id":"org-1","scopes":["read:x"],"client_id":"cli-1","roles":[]}`))
	}))
	defer srv.Close()

	ti := NewTokenInfoClient(srv.URL)
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims}, ti)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"agent-1","client_id":"cli-1"}`))
	raw := "hdr." + payload + ".sig"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	id, err := j.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Sub != "agent-1" || id.OrgID != "org-1" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	// tokeninfo client_id wins over JWT client_id (firstNonEmpty)
	if id.ClientID != "cli-1" {
		t.Fatalf("ClientID = %q, want cli-1", id.ClientID)
	}
	if id.IsSuperadmin {
		t.Fatal("IsSuperadmin must be false for strict agent via tokeninfo")
	}
	if id.AuthMethod != MethodBearer {
		t.Fatalf("AuthMethod = %q, want %q", id.AuthMethod, MethodBearer)
	}
}

func TestJWTAuthenticateStrictAgentPreservesActorClaims(t *testing.T) {
	// The strict path rebuilds Identity from /tokeninfo (which has no
	// Kind/ActorID), but the actor binding lives in the signature-verified JWT
	// and must survive — matching the non-strict path.
	claims := &jwtauth.Claims{
		Sub:           "agent-1",
		PrincipalType: jwtauth.PrincipalAgent,
		Validation:    jwtauth.ValidationStrict,
		Kind:          "sandbox",
		ActorID:       "sb-abc123",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sub":"agent-1","principal_type":"agent","org_id":"org-1","scopes":["read:x"]}`))
	}))
	defer srv.Close()

	ti := NewTokenInfoClient(srv.URL)
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims}, ti)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"agent-1"}`))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer hdr."+payload+".sig")
	id, err := j.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Kind != "sandbox" || id.ActorID != "sb-abc123" {
		t.Fatalf("strict path dropped actor binding: Kind=%q ActorID=%q", id.Kind, id.ActorID)
	}
}

func TestJWTAuthenticateStrictAgentTokenInfoError(t *testing.T) {
	claims := &jwtauth.Claims{
		Sub:           "agent-1",
		PrincipalType: jwtauth.PrincipalAgent,
		Validation:    jwtauth.ValidationStrict,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	ti := NewTokenInfoClient(srv.URL)
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims}, ti)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"agent-1"}`))
	raw := "hdr." + payload + ".sig"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	_, err := j.Authenticate(r)
	if !errors.Is(err, ErrRevoked) && !strings.Contains(err.Error(), "tokeninfo") {
		t.Fatalf("expected tokeninfo error, got %v", err)
	}
}

// ── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzClientIDFromJWT(f *testing.F) {
	// Seed corpus.
	f.Add("")
	f.Add("only")
	f.Add("a.b")
	f.Add("a.b.c.d")
	f.Add(encodePayloadFuzz(`{"client_id":"x"}`))
	f.Add(encodePayloadFuzz(`{"sub":"u"}`))
	f.Add("a.!!notbase64!!.c")
	f.Add(encodePayloadFuzz(`{not json`))
	f.Add(encodePayloadFuzz(`null`))
	f.Add(encodePayloadFuzz(`[]`))

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic; return value is always a string (possibly empty).
		_ = clientIDFromJWT(input)
	})
}

func encodePayloadFuzz(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return header + "." + body + "." + sig
}

func TestJWTAuthenticateCarriesActorClaims(t *testing.T) {
	claims := &jwtauth.Claims{
		Sub:           "u-1",
		OrgID:         "org-1",
		PrincipalType: jwtauth.PrincipalUser,
		Kind:          "sandbox",
		ActorID:       "sb-abc123",
	}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims}, nil)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u-1"}`))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer hdr."+payload+".sig")
	id, err := j.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.ActorID != "sb-abc123" || id.Kind != "sandbox" {
		t.Fatalf("identity missing actor claims: %+v", id)
	}
	// Attribution unchanged.
	if id.Sub != "u-1" || id.OrgID != "org-1" {
		t.Fatalf("attribution changed: %+v", id)
	}
}
