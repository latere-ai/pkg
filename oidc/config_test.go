// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"reflect"
	"testing"
)

// authEnvVars are the AUTH_* keys read by LoadConfig and shadowed by
// LoadConfigWithPrefix. Listed once so tests stay in sync if the set evolves.
var authEnvVars = []string{
	"AUTH_URL",
	"AUTH_CLIENT_ID",
	"AUTH_CLIENT_SECRET",
	"AUTH_REDIRECT_URL",
	"AUTH_COOKIE_KEY",
	"AUTH_AUDIENCE",
	"AUTH_SCOPES",
}

// clearAuthEnv unsets every AUTH_* (and prefixed) variable that any test in
// this file might mutate, so each subtest starts from a clean state.
func clearAuthEnv(t *testing.T, prefixes ...string) {
	t.Helper()
	all := append([]string{}, authEnvVars...)
	for _, p := range prefixes {
		for _, k := range authEnvVars {
			all = append(all, p+"_"+k)
		}
	}
	for _, k := range all {
		t.Setenv(k, "")
	}
}

func TestLoadConfigWithPrefix_EmptyPrefix(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("AUTH_CLIENT_ID", "from-plain")
	cfg := LoadConfigWithPrefix("")
	if cfg.ClientID != "from-plain" {
		t.Fatalf("ClientID = %q, want from-plain", cfg.ClientID)
	}
}

func TestLoadConfigWithPrefix_PrefixOverrides(t *testing.T) {
	clearAuthEnv(t, "SVC")
	t.Setenv("AUTH_CLIENT_ID", "from-plain")
	t.Setenv("SVC_AUTH_CLIENT_ID", "from-svc")
	cfg := LoadConfigWithPrefix("SVC")
	if cfg.ClientID != "from-svc" {
		t.Fatalf("ClientID = %q, want from-svc", cfg.ClientID)
	}
}

func TestLoadConfigWithPrefix_FallbackToPlain(t *testing.T) {
	clearAuthEnv(t, "SVC")
	t.Setenv("AUTH_CLIENT_ID", "from-plain")
	// SVC_AUTH_CLIENT_ID intentionally unset.
	cfg := LoadConfigWithPrefix("SVC")
	if cfg.ClientID != "from-plain" {
		t.Fatalf("ClientID = %q, want plain fallback", cfg.ClientID)
	}
}

func TestLoadConfigWithPrefix_PerVarMix(t *testing.T) {
	clearAuthEnv(t, "SVC")
	t.Setenv("AUTH_URL", "https://plain.example")
	t.Setenv("SVC_AUTH_CLIENT_ID", "svc-client")
	t.Setenv("SVC_AUTH_AUDIENCE", "svc-aud")
	cfg := LoadConfigWithPrefix("SVC")
	if cfg.AuthURL != "https://plain.example" {
		t.Fatalf("AuthURL = %q, want plain fallback", cfg.AuthURL)
	}
	if cfg.ClientID != "svc-client" {
		t.Fatalf("ClientID = %q, want svc-client", cfg.ClientID)
	}
	if cfg.Audience != "svc-aud" {
		t.Fatalf("Audience = %q, want svc-aud", cfg.Audience)
	}
}

func TestLoadConfigWithPrefix_AllFieldsCovered(t *testing.T) {
	clearAuthEnv(t, "SVC")
	t.Setenv("SVC_AUTH_URL", "https://svc.example")
	t.Setenv("SVC_AUTH_CLIENT_ID", "cid")
	t.Setenv("SVC_AUTH_CLIENT_SECRET", "csec")
	t.Setenv("SVC_AUTH_REDIRECT_URL", "https://svc.example/cb")
	t.Setenv("SVC_AUTH_COOKIE_KEY", "key")
	t.Setenv("SVC_AUTH_AUDIENCE", "aud")
	t.Setenv("SVC_AUTH_SCOPES", "read:x,write:y read:x")
	cfg := LoadConfigWithPrefix("SVC")
	if cfg.AuthURL != "https://svc.example" {
		t.Errorf("AuthURL = %q", cfg.AuthURL)
	}
	if cfg.ClientID != "cid" {
		t.Errorf("ClientID = %q", cfg.ClientID)
	}
	if cfg.ClientSecret != "csec" {
		t.Errorf("ClientSecret = %q", cfg.ClientSecret)
	}
	if cfg.RedirectURL != "https://svc.example/cb" {
		t.Errorf("RedirectURL = %q", cfg.RedirectURL)
	}
	if cfg.CookieKey != "key" {
		t.Errorf("CookieKey = %q", cfg.CookieKey)
	}
	if cfg.Audience != "aud" {
		t.Errorf("Audience = %q", cfg.Audience)
	}
	want := []string{"read:x", "write:y"}
	if !reflect.DeepEqual(cfg.Scopes, want) {
		t.Errorf("Scopes = %v, want %v (deduped)", cfg.Scopes, want)
	}
}
