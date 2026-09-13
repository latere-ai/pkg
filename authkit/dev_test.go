// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"errors"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestNewDevAuthenticator_LoopbackActivates(t *testing.T) {
	d, err := NewDevAuthenticator(DevConfig{PostureHost: "localhost:8080"})
	if err != nil {
		t.Fatalf("loopback host should activate: %v", err)
	}
	id, err := d.Authenticate(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Sub != "dev-local" {
		t.Errorf("Sub = %q, want dev-local (default)", id.Sub)
	}
	if id.PrincipalType != "dev" {
		t.Errorf("PrincipalType = %q, want dev", id.PrincipalType)
	}
	if id.AuthMethod != MethodDev {
		t.Errorf("AuthMethod = %q, want dev", id.AuthMethod)
	}
	if id.Has(RolePlatformAdmin) {
		t.Error("default identity must NOT carry platform_admin")
	}
}

func TestNewDevAuthenticator_CustomIdentity(t *testing.T) {
	d, err := NewDevAuthenticator(DevConfig{
		Subject:       "u-1",
		Email:         "dev@local",
		Org:           "org-1",
		PlatformAdmin: true,
		PostureHost:   "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	id, _ := d.Authenticate(httptest.NewRequest("GET", "/", nil))
	if id.Sub != "u-1" || id.Email != "dev@local" || id.OrgID != "org-1" {
		t.Errorf("identity not carried: %+v", id)
	}
	if !slices.Equal(id.Roles, []string{RolePlatformAdmin}) {
		t.Errorf("Roles = %v, want [platform_admin]: PlatformAdmin is a role grant", id.Roles)
	}
}

func TestNewDevAuthenticator_NonLoopbackRefused(t *testing.T) {
	cases := []string{"app.example.com", "app.example.com:443", "10.0.0.5", "", "::not-an-ip::"}
	for _, host := range cases {
		t.Run(host, func(t *testing.T) {
			if _, err := NewDevAuthenticator(DevConfig{PostureHost: host}); err == nil {
				t.Errorf("host %q must fail closed without insecure override", host)
			}
		})
	}
}

func TestNewDevAuthenticator_InsecureOverride(t *testing.T) {
	d, err := NewDevAuthenticator(DevConfig{PostureHost: "app.example.com", Insecure: true})
	if err != nil {
		t.Fatalf("insecure override should permit non-loopback: %v", err)
	}
	if d == nil {
		t.Fatal("nil authenticator")
	}
}

func TestDevAuthenticatorFromEnv_OffByDefault(t *testing.T) {
	// AUTH_DEV_BYPASS unset → (nil, nil), bypass absent from any chain.
	t.Setenv("AUTH_DEV_BYPASS", "")
	d, err := DevAuthenticatorFromEnv()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d != nil {
		t.Error("bypass must be nil when AUTH_DEV_BYPASS is unset")
	}
}

func TestDevAuthenticatorFromEnv_LoopbackFromRedirect(t *testing.T) {
	t.Setenv("AUTH_DEV_BYPASS", "true")
	t.Setenv("AUTH_REDIRECT_URL", "http://localhost:3000/callback")
	t.Setenv("AUTH_DEV_SUBJECT", "env-dev")
	d, err := DevAuthenticatorFromEnv()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d == nil {
		t.Fatal("expected an authenticator")
	}
	id, _ := d.Authenticate(httptest.NewRequest("GET", "/", nil))
	if id.Sub != "env-dev" {
		t.Errorf("Sub = %q", id.Sub)
	}
	if len(id.Roles) != 0 {
		t.Errorf("Roles = %v, want none without AUTH_DEV_SUPERADMIN", id.Roles)
	}
}

func TestDevAuthenticatorFromEnv_NonLoopbackFailsClosed(t *testing.T) {
	t.Setenv("AUTH_DEV_BYPASS", "true")
	t.Setenv("AUTH_REDIRECT_URL", "https://app.example.com/callback")
	t.Setenv("AUTH_URL", "")
	if _, err := DevAuthenticatorFromEnv(); err == nil {
		t.Error("non-loopback posture must fail closed")
	}
}

func TestDevAuthenticatorFromEnv_InsecureOnNonLoopback(t *testing.T) {
	t.Setenv("AUTH_DEV_BYPASS", "true")
	t.Setenv("AUTH_DEV_BYPASS_INSECURE", "true")
	t.Setenv("AUTH_REDIRECT_URL", "https://staging.example.com/callback")
	t.Setenv("AUTH_DEV_SUPERADMIN", "true")
	d, err := DevAuthenticatorFromEnv()
	if err != nil {
		t.Fatalf("insecure override: %v", err)
	}
	id, _ := d.Authenticate(httptest.NewRequest("GET", "/", nil))
	if !id.Has(RolePlatformAdmin) {
		t.Error("AUTH_DEV_SUPERADMIN must grant the platform_admin role")
	}
}

func TestDevAuthenticator_NilReceiverUnauthenticated(t *testing.T) {
	var d *DevAuthenticator
	if _, err := d.Authenticate(httptest.NewRequest("GET", "/", nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("nil receiver err = %v, want ErrUnauthenticated", err)
	}
}

func TestDevAuthenticatorFromEnv_PostureFromIssuerFallback(t *testing.T) {
	t.Setenv("AUTH_DEV_BYPASS", "true")
	t.Setenv("AUTH_REDIRECT_URL", "")
	t.Setenv("AUTH_URL", "http://127.0.0.1:9000")
	d, err := DevAuthenticatorFromEnv()
	if err != nil {
		t.Fatalf("issuer-host fallback should activate on loopback: %v", err)
	}
	if d == nil {
		t.Fatal("nil authenticator")
	}
}
