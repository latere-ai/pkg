// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"latere.ai/x/pkg/authkit"
)

// ── JWT.Authenticate (via fake validator) ────────────────────────────────────

// fakeValidator implements the validator interface.
type fakeValidator struct {
	claims *Claims
	err    error
}

func (f *fakeValidator) Validate(string) (*Claims, error) {
	return f.claims, f.err
}

func newJWTWithFakeValidator(v validator) *Authenticator {
	return &Authenticator{V: v}
}

func TestNewJWT(t *testing.T) {
	// NewAuthenticator takes the validator and nothing else. A nil
	// *Validator proves the constructor neither panics nor returns nil,
	// and that the interface field holds what it was given.
	j := NewAuthenticator(nil)
	if j == nil {
		t.Fatal("NewAuthenticator returned nil")
	}
	if j.V == nil {
		t.Fatal("V not wired")
	}
}

func TestJWTAuthenticateMissingHeader(t *testing.T) {
	j := newJWTWithFakeValidator(&fakeValidator{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := j.Authenticate(r)
	if !errors.Is(err, authkit.ErrUnauthenticated) {
		t.Fatalf("got %v, want authkit.ErrUnauthenticated", err)
	}
}

func TestJWTAuthenticateValidateError(t *testing.T) {
	sentinel := errors.New("bad token")
	j := newJWTWithFakeValidator(&fakeValidator{err: sentinel})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer sometoken")
	_, err := j.Authenticate(r)
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want sentinel", err)
	}
}

func TestJWTAuthenticateLocalToken(t *testing.T) {
	claims := &Claims{
		Sub:           "u-1",
		OrgID:         "org-1",
		Email:         "a@b.com",
		PrincipalType: PrincipalUser}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims})
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
	if id.AuthMethod != authkit.MethodBearer {
		t.Fatalf("authkit.AuthMethod = %q, want %q", id.AuthMethod, authkit.MethodBearer)
	}
}

func TestJWTAuthenticateLocalTokenWithClientID(t *testing.T) {
	// Validator populates Claims.ClientID from the verified token; the
	// authenticator reads it directly (no second decode).
	claims := &Claims{
		Sub:           "u-1",
		PrincipalType: PrincipalUser,
		ClientID:      "cli-abc"}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims})
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
	claims := &Claims{
		Sub:           "u-1",
		OrgID:         "org-1",
		PrincipalType: PrincipalUser,
		Kind:          "sandbox",
		ActorID:       "sb-abc123"}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims})
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
	// The org-scoped "roles" claim flows onto authkit.Identity.Roles so a consumer
	// can derive org authority (e.g. an org admin holds "owner"/"admin")
	// without a product-specific scope.
	claims := &Claims{
		Sub:           "u-1",
		OrgID:         "org-1",
		PrincipalType: PrincipalUser,
		Roles:         []string{"admin"}}
	j := newJWTWithFakeValidator(&fakeValidator{claims: claims})
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
