package oidc

import (
	"context"
	"testing"
	"time"
)

func TestMapperForProvider_All(t *testing.T) {
	for _, p := range []string{"", "latere", "keycloak", "google", "cognito"} {
		if _, err := mapperForKind(p); err != nil {
			t.Errorf("provider %q: %v", p, err)
		}
	}
}

func TestKeycloakMapper(t *testing.T) {
	id, _ := KeycloakMapper{}.Map(
		map[string]any{
			"sub": "kc-1", "email": "k@example.com", "preferred_username": "kuser",
			"realm_access": map[string]any{"roles": []any{"dashboard-admin"}},
		},
		map[string]any{"realm_access": map[string]any{"roles": []any{"offline_access", "dashboard-admin"}}},
	)
	if id.Subject != "kc-1" {
		t.Errorf("subject = %q", id.Subject)
	}
	if id.Name != "kuser" {
		t.Errorf("name fallback to preferred_username failed: %q", id.Name)
	}
	// Union of ID-token and access-token realm roles, de-duplicated.
	if len(id.Roles) != 2 {
		t.Errorf("roles = %v, want 2 unioned", id.Roles)
	}
}

func TestKeycloakMapper_NoRealmAccess(t *testing.T) {
	id, _ := KeycloakMapper{}.Map(map[string]any{"sub": "kc-2"}, nil)
	if len(id.Roles) != 0 {
		t.Errorf("roles = %v, want none", id.Roles)
	}
}

func TestGoogleMapper_IdentityOnly(t *testing.T) {
	id, _ := GoogleMapper{}.Map(map[string]any{
		"sub": "g-1", "email": "g@example.com", "name": "G User", "hd": "example.com",
	}, nil)
	if id.Subject != "g-1" || id.Email != "g@example.com" || id.Name != "G User" {
		t.Errorf("identity = %+v", id)
	}
	if len(id.Roles) != 0 {
		t.Error("Google must yield no roles")
	}
}

func TestCognitoMapper(t *testing.T) {
	id, _ := CognitoMapper{}.Map(
		map[string]any{"sub": "c-1", "cognito:username": "cuser", "cognito:groups": []any{"admins"}},
		map[string]any{"cognito:groups": []any{"admins", "billing"}},
	)
	if id.Name != "cuser" {
		t.Errorf("name fallback to cognito:username failed: %q", id.Name)
	}
	if len(id.Roles) != 2 {
		t.Errorf("groups = %v, want 2 unioned", id.Roles)
	}
}

// TestProviderEndToEnd_Keycloak runs a Keycloak login through the full verify
// surface, proving the adapter wiring resolves realm roles from a verified
// access token.
func TestProviderEndToEnd_Keycloak(t *testing.T) {
	idp := newFakeIDP(t)
	a := newAuth(t, idp, "client-1", "keycloak")
	idToken := idp.signRS256(t, baseIDClaims(idp, "client-1", "nonce-1"))
	atClaims := map[string]any{
		"iss": idp.srv.URL, "sub": "user-123", "exp": time.Now().Add(time.Hour).Unix(),
		"realm_access": map[string]any{"roles": []any{"dashboard-admin"}},
	}
	at := idp.signRS256(t, atClaims)
	id, err := a.VerifyIDToken(context.Background(), tokenWithID(idToken, at), "nonce-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "dashboard-admin" {
		t.Errorf("roles = %v, want [dashboard-admin]", id.Roles)
	}
}
