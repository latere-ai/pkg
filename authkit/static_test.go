// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStaticTokenAuthenticator_NilReceiver(t *testing.T) {
	var a *StaticTokenAuthenticator
	_, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil receiver: got %v", err)
	}
}

func TestStaticTokenAuthenticator_EmptyMap(t *testing.T) {
	a := NewStaticToken(nil)
	_, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil map: got %v", err)
	}
	a = NewStaticToken(map[string]Identity{})
	_, err = a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty map: got %v", err)
	}
}

func TestStaticTokenAuthenticator_MissingHeader(t *testing.T) {
	a := NewStaticToken(map[string]Identity{"tok": {Sub: "u-1"}})
	_, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("missing header: got %v", err)
	}
}

func TestStaticTokenAuthenticator_LowercaseScheme(t *testing.T) {
	a := NewStaticToken(map[string]Identity{"tok": {Sub: "u-1"}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "bearer tok")
	id, err := a.Authenticate(r)
	if err != nil || id.Sub != "u-1" {
		t.Fatalf("lowercase scheme: id=%+v err=%v", id, err)
	}
}

func TestStaticTokenAuthenticator_WrongScheme(t *testing.T) {
	a := NewStaticToken(map[string]Identity{"tok": {Sub: "u-1"}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic tok")
	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong scheme: got %v", err)
	}
}

func TestStaticTokenAuthenticator_UnknownToken(t *testing.T) {
	a := NewStaticToken(map[string]Identity{"alice-tok": {Sub: "alice"}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer bob-tok")
	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unknown token: got %v", err)
	}
}

func TestStaticTokenAuthenticator_DistinctIdentities(t *testing.T) {
	a := NewStaticToken(map[string]Identity{
		"alice-tok": {Sub: "alice", OrgID: "org-a"},
		"bob-tok":   {Sub: "bob", OrgID: "org-b"},
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer alice-tok")
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if id.Sub != "alice" || id.OrgID != "org-a" {
		t.Fatalf("alice: %+v", id)
	}
	if id.AuthMethod != MethodStatic {
		t.Fatalf("AuthMethod = %q, want %q", id.AuthMethod, MethodStatic)
	}

	r.Header.Set("Authorization", "Bearer bob-tok")
	id, err = a.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if id.Sub != "bob" || id.OrgID != "org-b" {
		t.Fatalf("bob: %+v", id)
	}
}

func TestStaticTokenAuthenticator_AuthMethodOverwrite(t *testing.T) {
	// Caller-supplied AuthMethod must be overwritten with MethodStatic.
	a := NewStaticToken(map[string]Identity{"tok": {Sub: "u-1", AuthMethod: MethodBearer}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer tok")
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if id.AuthMethod != MethodStatic {
		t.Fatalf("AuthMethod = %q, want %q (constructor must overwrite)", id.AuthMethod, MethodStatic)
	}
}
