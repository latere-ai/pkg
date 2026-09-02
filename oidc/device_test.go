// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestDeviceAuth_HappyPath asserts the /device/code request and the
// returned struct round-trip end-to-end. Every CLI / headless flow
// that signs in against auth.latere.ai depends on this contract.
func TestDeviceAuth_HappyPath(t *testing.T) {
	var sawForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/device/code" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		sawForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dev-xyz",
			"user_code":                 "ABCD-1234",
			"verification_uri":          "https://auth.example.com/device",
			"verification_uri_complete": "https://auth.example.com/device?user_code=ABCD-1234",
			"expires_in":                900,
			"interval":                  5,
		})
	}))
	defer srv.Close()

	c := New(Config{
		AuthURL:  srv.URL,
		ClientID: "cli-public",
		// no ClientSecret — public device-flow client
	})
	if c == nil {
		t.Fatal("New returned nil for device-only client")
	}

	resp, err := c.DeviceAuth(context.Background(), url.Values{"org_id": {"org-1"}})
	if err != nil {
		t.Fatalf("DeviceAuth: %v", err)
	}
	if resp.UserCode != "ABCD-1234" {
		t.Errorf("UserCode = %q, want ABCD-1234", resp.UserCode)
	}
	if !strings.HasSuffix(resp.VerificationURIComplete, "user_code=ABCD-1234") {
		t.Errorf("VerificationURIComplete = %q", resp.VerificationURIComplete)
	}
	if got := sawForm.Get("client_id"); got != "cli-public" {
		t.Errorf("client_id = %q, want cli-public", got)
	}
	if got := sawForm.Get("org_id"); got != "org-1" {
		t.Errorf("org_id = %q, want org-1 (extra param dropped)", got)
	}
}

// TestDeviceAccessToken_HonorsAuthorizationPending pins the polling
// behaviour: the first call returns authorization_pending; the next
// call (after the configured interval) returns the token. Callers
// downstream rely on this to render "Waiting for approval..." once
// before the token comes back.
func TestDeviceAccessToken_HonorsAuthorizationPending(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		n := calls.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "authorization_pending",
				"error_description": "the user has not yet acted",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-abc",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	c := New(Config{AuthURL: srv.URL, ClientID: "cli-public"})
	resp := mustDeviceResp("dev-1", time.Now().Add(time.Minute), 1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := c.DeviceAccessToken(ctx, resp)
	if err != nil {
		t.Fatalf("DeviceAccessToken: %v", err)
	}
	if tok.AccessToken != "tok-abc" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("polled %d times, want 2 (one pending + one success)", got)
	}
}

// TestDeviceAccessToken_AccessDeniedSurfaces makes sure the user-denial
// path returns a real error rather than silently re-polling forever.
// CLI UX renders this as "user denied the request".
func TestDeviceAccessToken_AccessDeniedSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "access_denied",
			"error_description": "the user denied the request",
		})
	}))
	defer srv.Close()

	c := New(Config{AuthURL: srv.URL, ClientID: "cli-public"})
	resp := mustDeviceResp("dev-deny", time.Now().Add(time.Minute), 1)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.DeviceAccessToken(ctx, resp)
	if err == nil {
		t.Fatal("DeviceAccessToken accepted access_denied silently")
	}
	if !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("err = %q, want to mention access_denied", err.Error())
	}
}

// TestEnabled_DeviceOnly confirms a public client (ClientSecret +
// RedirectURL empty) is recognised as enabled — required so CLIs can
// instantiate a Client without supplying browser-flow plumbing they
// don't need.
func TestEnabled_DeviceOnly(t *testing.T) {
	cfg := Config{AuthURL: "https://auth.example.com", ClientID: "cli"}
	if !cfg.Enabled() {
		t.Fatal("device-only config is not Enabled()")
	}
	if got := New(cfg); got == nil {
		t.Fatal("New returned nil for device-only config")
	}
}

func mustDeviceResp(deviceCode string, expiry time.Time, intervalSec int64) *deviceAuthResp {
	return &deviceAuthResp{DeviceCode: deviceCode, Expiry: expiry, Interval: intervalSec}
}

// deviceAuthResp is a local alias of oauth2.DeviceAuthResponse so the
// test fixture stays narrow without re-importing the package's full
// surface.
type deviceAuthResp = oauth2.DeviceAuthResponse
