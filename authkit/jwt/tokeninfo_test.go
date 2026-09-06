// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenInfoLookupOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mytoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"sub":"u-1","principal_type":"user","org_id":"org-1","scopes":["read:x"],"roles":[]}`)); err != nil {
			t.Errorf("write tokeninfo body: %v", err)
		}
	}))
	defer srv.Close()

	c := NewTokenInfoClient(srv.URL)
	ti, err := c.Lookup(context.Background(), "mytoken")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ti.Sub != "u-1" {
		t.Fatalf("Sub = %q", ti.Sub)
	}
	if ti.OrgID != "org-1" {
		t.Fatalf("OrgID = %q", ti.OrgID)
	}
}

func TestTokenInfoLookup401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewTokenInfoClient(srv.URL)
	_, err := c.Lookup(context.Background(), "tok")
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v, want ErrRevoked", err)
	}
}

func TestTokenInfoLookup403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewTokenInfoClient(srv.URL)
	_, err := c.Lookup(context.Background(), "tok")
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v, want ErrRevoked", err)
	}
}

func TestTokenInfoLookup500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("server error")); err != nil {
			t.Errorf("write tokeninfo body: %v", err)
		}
	}))
	defer srv.Close()

	c := NewTokenInfoClient(srv.URL)
	_, err := c.Lookup(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestTokenInfoLookupEmptySub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"sub":"","principal_type":"user","scopes":[],"roles":[]}`)); err != nil {
			t.Errorf("write tokeninfo body: %v", err)
		}
	}))
	defer srv.Close()

	c := NewTokenInfoClient(srv.URL)
	_, err := c.Lookup(context.Background(), "tok")
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v, want ErrRevoked (empty sub)", err)
	}
}

func TestTokenInfoLookupMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{not json`)); err != nil {
			t.Errorf("write tokeninfo body: %v", err)
		}
	}))
	defer srv.Close()

	c := NewTokenInfoClient(srv.URL)
	_, err := c.Lookup(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestTokenInfoLookupNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close() // close before request

	c := NewTokenInfoClient(url)
	_, err := c.Lookup(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestTokenInfoLookupBadURL(t *testing.T) {
	c := NewTokenInfoClient("://bad-url")
	_, err := c.Lookup(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
