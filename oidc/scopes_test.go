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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scopesFromJWT(tt.claims); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("scopesFromJWT = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"a b c", []string{"a", "b", "c"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"a b a c b", []string{"a", "b", "c"}}, // dedup, order-preserving
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := splitScopes(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitScopes(%q) = %v, want %v", tt.in, got, tt.want)
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
