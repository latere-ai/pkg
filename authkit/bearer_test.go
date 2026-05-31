package authkit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerTokenAuth(t *testing.T) {
	a := NewBearerToken("secret", "dev-user")
	cases := []struct {
		name   string
		header string
		ok     bool
	}{
		{"missing", "", false},
		{"wrong scheme", "Basic secret", false},
		{"wrong token", "Bearer nope", false},
		{"correct", "Bearer secret", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			_, err := a.Authenticate(r)
			if tc.ok && err != nil {
				t.Fatalf("want ok; got err %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("want err; got nil")
			}
		})
	}
}

func TestNewBearerTokenDefaultDevSub(t *testing.T) {
	a := NewBearerToken("secret", "")
	if a.id.Sub != "dev-local" {
		t.Fatalf("default devSub: %q", a.id.Sub)
	}
	if !a.id.IsSuperadmin {
		t.Fatal("dev token must be superadmin")
	}
	if a.id.TokenID != "dev" {
		t.Fatalf("TokenID = %q, want dev", a.id.TokenID)
	}
	if a.id.PrincipalType != "dev" {
		t.Fatalf("PrincipalType = %q, want dev", a.id.PrincipalType)
	}
}

func TestBearerTokenIdentityFields(t *testing.T) {
	a := NewBearerToken("tok", "my-sub")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer tok")
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if id.Sub != "my-sub" {
		t.Fatalf("Sub = %q", id.Sub)
	}
	if !id.IsSuperadmin {
		t.Fatal("IsSuperadmin must be true")
	}
	if id.AuthMethod != MethodBearer {
		t.Fatalf("AuthMethod = %q, want %q", id.AuthMethod, MethodBearer)
	}
}
