// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// tokenEndpoint is an issuer's /token for the client_credentials grant: it
// checks the client's Basic credentials and the form, and answers a token
// whose value records what was asked.
func tokenEndpoint(t *testing.T, mints *atomic.Int32, expiresIn int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/token" {
			http.Error(w, "not the token endpoint", http.StatusNotFound)
			return
		}
		id, secret, ok := r.BasicAuth()
		if !ok || id != "wallfacer" || secret != "s3cret" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		if aud := r.Form.Get("audience"); aud != "" && aud != "sandboxd" {
			http.Error(w, `{"error":"invalid_target"}`, http.StatusBadRequest)
			return
		}
		mints.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"svc-` + r.Form.Get("audience") + "-" + r.Form.Get("scope") + `","token_type":"Bearer","expires_in":` + itoa(expiresIn) + `}`))
	}))
}

func itoa(n int64) string { return strings.TrimSpace(strings.Repeat(" ", 0) + fmtInt(n)) }

func fmtInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestClientCredentialsMintsForTheAudienceWithBasicAuth(t *testing.T) {
	var mints atomic.Int32
	srv := tokenEndpoint(t, &mints, 900)
	defer srv.Close()
	tok, exp, err := ClientCredentials(context.Background(), srv.URL, "wallfacer", "s3cret", "sandboxd", []string{"github:mint-token", "read:sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	if tok != "svc-sandboxd-github:mint-token read:sandbox" {
		t.Fatalf("token = %q", tok)
	}
	if until := time.Until(exp); until < 890*time.Second || until > 900*time.Second {
		t.Fatalf("expiry %v from now, want about 900s", until)
	}
	if _, _, err := ClientCredentials(context.Background(), srv.URL, "wallfacer", "wrong", "", nil); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a wrong secret must surface the issuer's refusal: %v", err)
	}
	if _, _, err := ClientCredentials(context.Background(), srv.URL, "wallfacer", "s3cret", "lux", nil); err == nil || !strings.Contains(err.Error(), "invalid_target") {
		t.Fatalf("an unregistered audience must surface invalid_target: %v", err)
	}
	if _, _, err := ClientCredentials(context.Background(), srv.URL, "", "", "", nil); err == nil {
		t.Fatal("no client credentials must be refused before any request")
	}
}

func TestClientCredentialsRefusesAnEmptyGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"","expires_in":0}`))
	}))
	defer srv.Close()
	if _, _, err := ClientCredentials(context.Background(), srv.URL, "c", "s", "", nil); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("an empty grant must be an error: %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) }))
	defer bad.Close()
	if _, _, err := ClientCredentials(context.Background(), bad.URL, "c", "s", "", nil); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("a malformed body must be an error: %v", err)
	}
}

func TestServiceTokenSourceReusesUntilTheMargin(t *testing.T) {
	var mints atomic.Int32
	srv := tokenEndpoint(t, &mints, 300)
	defer srv.Close()
	src := NewServiceTokenSource(srv.URL, "wallfacer", "s3cret", "sandboxd", nil)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	src.now = func() time.Time { return now }

	ctx := context.Background()
	for range 3 {
		if _, err := src.Token(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if mints.Load() != 1 {
		t.Fatalf("three calls inside the lifetime minted %d times", mints.Load())
	}
	now = now.Add(269 * time.Second)
	if _, err := src.Token(ctx); err != nil || mints.Load() != 1 {
		t.Fatalf("just inside the margin must reuse: err=%v mints=%d", err, mints.Load())
	}
	now = now.Add(2 * time.Second)
	if _, err := src.Token(ctx); err != nil || mints.Load() != 2 {
		t.Fatalf("past the margin must mint again: err=%v mints=%d", err, mints.Load())
	}
}

func TestServiceTokenSourceSurfacesTheIssuerAndNil(t *testing.T) {
	var nilSrc *ServiceTokenSource
	if _, err := nilSrc.Token(context.Background()); err == nil {
		t.Fatal("a nil source must not hand out a token")
	}
	src := NewServiceTokenSource("http://127.0.0.1:1", "c", "s", "", nil)
	src.mint = func(context.Context) (string, time.Duration, error) { return "", 0, errors.New("issuer down") }
	if _, err := src.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "issuer down") {
		t.Fatalf("the issuer's error must reach the caller: %v", err)
	}
}
