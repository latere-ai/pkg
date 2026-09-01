package authkit

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"latere.ai/x/pkg/jwtauth"
)

// ── JWT.Authenticate (via fake validator) ────────────────────────────────────

// fakeValidator implements the validator interface.
type fakeValidator struct {
	claims *jwtauth.Claims
	err    error
}

func (f *fakeValidator) Validate(string) (*jwtauth.Claims, error) {
	return f.claims, f.err
}

func newJWTWithFakeValidator(v validator, ti TokenInfoLookup) *JWT {
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
	// jwtauth.Validator populates Claims.ClientID from the verified token; the
	// authenticator reads it directly (no second decode).
	claims := &jwtauth.Claims{
		Sub:           "u-1",
		PrincipalType: jwtauth.PrincipalUser,
		ClientID:      "cli-abc",
	}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims}, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer hdr.payload.sig")
	id, err := j.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.ClientID != "cli-abc" {
		t.Fatalf("ClientID = %q, want cli-abc", id.ClientID)
	}
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

func TestJWTAuthenticateCarriesRoles(t *testing.T) {
	// The org-scoped "roles" claim flows onto Identity.Roles so a consumer
	// can derive org authority (e.g. an org admin holds "owner"/"admin")
	// without a product-specific scope.
	claims := &jwtauth.Claims{
		Sub:           "u-1",
		OrgID:         "org-1",
		PrincipalType: jwtauth.PrincipalUser,
		Roles:         []string{"admin"},
	}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims}, nil)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u-1"}`))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer hdr."+payload+".sig")
	id, err := j.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "admin" {
		t.Fatalf("Roles = %v, want [admin]", id.Roles)
	}
}
