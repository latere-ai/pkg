// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
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
	if id.Sub != "kc-1" {
		t.Errorf("sub = %q", id.Sub)
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
	if id.Sub != "g-1" || id.Email != "g@example.com" || id.Name != "G User" {
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

// FuzzMappers feeds arbitrary claim shapes to every built-in mapper: none may
// panic, and VerifyIDToken's contract that a mapped user without a subject
// is rejected is pinned on the mapper output.
func FuzzMappers(f *testing.F) {
	f.Add(`{"sub":"u1","email":"a@b","name":"A","realm_access":{"roles":["r"]},"cognito:groups":["g"]}`, `{"roles":["x"]}`)
	f.Add(`{"sub":1,"realm_access":"nope","cognito:groups":"g"}`, `null`)
	f.Add(`[]`, `{}`)
	f.Fuzz(func(t *testing.T, idJSON, atJSON string) {
		var id, at map[string]any
		_ = json.Unmarshal([]byte(idJSON), &id)
		_ = json.Unmarshal([]byte(atJSON), &at)
		if id == nil {
			id = map[string]any{}
		}
		for _, m := range []ClaimsMapper{LatereMapper{}, KeycloakMapper{}, GoogleMapper{}, CognitoMapper{}} {
			u, err := m.Map(id, at)
			if err != nil {
				continue
			}
			if want, _ := id["sub"].(string); u.Sub != want {
				t.Fatalf("%T: Sub = %q, want %q", m, u.Sub, want)
			}
		}
	})
}
