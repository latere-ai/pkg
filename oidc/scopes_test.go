// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestScopesFromJWT(t *testing.T) {
	tests := []struct {
		name   string
		claims *jwtClaims
		want   []string
	}{
		{"nil", nil, nil},
		{"empty", &jwtClaims{}, nil},
		{"scope string", &jwtClaims{Scope: "openid email"}, []string{"openid", "email"}},
		{"scopes array", &jwtClaims{Scopes: []string{"openid", "cella:run"}}, []string{"openid", "cella:run"}},
		{"scope string wins over array", &jwtClaims{Scope: "a b", Scopes: []string{"c"}}, []string{"a", "b"}},
		{"scp array", &jwtClaims{SCP: []string{"openid", "drive:read"}}, []string{"openid", "drive:read"}},
		{"scp wins over scope and scopes", &jwtClaims{SCP: []string{"a"}, Scope: "b", Scopes: []string{"c"}}, []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scopesFromJWT(tt.claims); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("scopesFromJWT = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSessionFromTokenScopesArray exercises the scopes-array branch end-to-end.
func TestSessionFromTokenScopesArray(t *testing.T) {
	jwt := makeRichJWT(map[string]any{"sub": "u1", "scopes": []string{"openid", "cella:admin"}})
	u := SessionFromToken(&oauth2.Token{AccessToken: jwt}, 0).User
	if len(u.Scopes) != 2 || u.Scopes[1] != "cella:admin" {
		t.Errorf("Scopes = %v", u.Scopes)
	}
}
