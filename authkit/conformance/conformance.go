// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package conformance turns the family's token-verification rules into a
// test a service runs: the service verifies aud = self, reads one
// authkit.Identity, and performs no HTTP call to the issuer on the request
// path; and access is by role, so a token carrying the retired is_superadmin flag and no platform_admin
// role holds no authority. A repository calls Run from one of its tests
// with the authenticator it installs in production, built against the stub
// issuer the suite hands it, and the suite fails the build when any of the
// six checks does not hold.
package conformance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"latere.ai/x/pkg/authkit"
	"latere.ai/x/pkg/authkit/issuertest"
)

// Service is what a repository declares: the audience it verifies and how
// it builds the authenticator it runs in production, given the issuer to
// trust. New receives the stub's URL as issuer and its JWKS URL, exactly
// what the deployment's variables carry.
type Service struct {
	// Audience is the aud the service accepts, the value its identity block
	// in .lateregate.yaml names.
	Audience string
	// New builds the production authenticator against the given issuer.
	New func(t testing.TB, issuerURL, jwksURL string) authkit.Authenticator
}

// TB is the part of testing.TB the checks use, so a test of this package
// can record failures instead of failing.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Run runs every check as a subtest. It is the one call a repository makes.
func Run(t *testing.T, s Service) {
	t.Helper()
	if s.Audience == "" || s.New == nil {
		t.Fatalf("conformance: Service needs an Audience and a New")
	}
	t.Run("admits its own audience", func(t *testing.T) { AdmitsOwnAudience(t, s) })
	t.Run("refuses the issuer audience", func(t *testing.T) { RefusesIssuerAudience(t, s) })
	t.Run("refuses another audience", func(t *testing.T) { RefusesOtherAudience(t, s) })
	t.Run("refuses a token with no subject", func(t *testing.T) { RefusesNoSubject(t, s) })
	t.Run("calls nothing but the key set", func(t *testing.T) { CallsOnlyTheKeySet(t, s) })
	t.Run("reads no flag in place of a role", func(t *testing.T) { RefusesTheFlag(t, s) })
}

func setup(t TB, s Service) (*issuertest.Server, authkit.Authenticator) {
	t.Helper()
	tb, ok := t.(testing.TB)
	if !ok {
		t.Fatalf("conformance: the TB is not a testing.TB")
	}
	iss := issuertest.New(tb)
	return iss, s.New(tb, iss.URL(), iss.JWKSURL())
}

func request(token string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// AdmitsOwnAudience: a token for the service's audience yields an Identity
// carrying sub, org_id, roles and principal_type.
func AdmitsOwnAudience(t TB, s Service) {
	t.Helper()
	iss, a := setup(t, s)
	tok := iss.Mint(issuertest.Claims{
		Sub: "user_1", Aud: issuertest.StringList{s.Audience}, OrgID: "org_1",
		Roles: []string{"member"}, PrincipalType: string(authkit.PrincipalUser),
	})
	id, err := a.Authenticate(request(tok))
	if err != nil {
		t.Fatalf("a token for %q was refused: %v", s.Audience, err)
	}
	if id.Sub != "user_1" {
		t.Errorf("Identity.Sub = %q, want user_1", id.Sub)
	}
	if id.OrgID != "org_1" {
		t.Errorf("Identity.OrgID = %q, want org_1", id.OrgID)
	}
	if !slices.Equal(id.Roles, []string{"member"}) {
		t.Errorf("Identity.Roles = %v, want [member]", id.Roles)
	}
	if id.PrincipalType != authkit.PrincipalUser {
		t.Errorf("Identity.PrincipalType = %q, want user", id.PrincipalType)
	}
}

// RefusesIssuerAudience: a login token, addressed to the issuer alone, is
// not accepted by a product.
func RefusesIssuerAudience(t TB, s Service) {
	t.Helper()
	iss, a := setup(t, s)
	tok := iss.Mint(issuertest.Claims{Sub: "user_1", Aud: issuertest.StringList{iss.URL()}})
	if _, err := a.Authenticate(request(tok)); err == nil {
		t.Errorf("a token addressed to the issuer was admitted; the service does not check aud = %q", s.Audience)
	}
}

// RefusesOtherAudience: a token minted for another service is refused.
func RefusesOtherAudience(t TB, s Service) {
	t.Helper()
	iss, a := setup(t, s)
	tok := iss.Mint(issuertest.Claims{Sub: "user_1", Aud: issuertest.StringList{"another-service"}})
	if _, err := a.Authenticate(request(tok)); err == nil {
		t.Errorf("a token for another-service was admitted; the service does not check aud = %q", s.Audience)
	}
}

// RefusesNoSubject: a token that names nobody is refused.
func RefusesNoSubject(t TB, s Service) {
	t.Helper()
	iss, a := setup(t, s)
	tok := iss.Mint(issuertest.Claims{Aud: issuertest.StringList{s.Audience}, Omit: []string{"sub"}})
	if _, err := a.Authenticate(request(tok)); err == nil {
		t.Errorf("a token with no sub was admitted")
	}
}

// RefusesTheFlag: a token carrying is_superadmin: true and no platform_admin
// role yields an Identity on which Has(platform_admin) is false, so no admin
// route gated on the role opens to it (identity id-09). A token that names
// the role in roles is the one that holds it, and Has reports it.
func RefusesTheFlag(t TB, s Service) {
	t.Helper()
	iss, a := setup(t, s)
	flagged := iss.Mint(issuertest.Claims{
		Sub: "user_1", Aud: issuertest.StringList{s.Audience}, OrgID: "org_1",
		Roles: []string{authkit.RoleMember}, PrincipalType: string(authkit.PrincipalUser),
		Extra: map[string]any{"is_superadmin": true},
	})
	id, err := a.Authenticate(request(flagged))
	if err != nil {
		t.Fatalf("a token for %q was refused: %v", s.Audience, err)
	}
	if id.Has(authkit.RolePlatformAdmin) {
		t.Errorf("a token carrying is_superadmin and no platform_admin role reads as the platform admin; access is by role (R9)")
	}
	admin := iss.Mint(issuertest.Claims{
		Sub: "user_2", Aud: issuertest.StringList{s.Audience}, OrgID: "org_1",
		Roles: []string{authkit.RolePlatformAdmin, authkit.RoleOwner}, PrincipalType: string(authkit.PrincipalUser),
	})
	id, err = a.Authenticate(request(admin))
	if err != nil {
		t.Fatalf("a token for %q was refused: %v", s.Audience, err)
	}
	if !id.Has(authkit.RolePlatformAdmin) {
		t.Errorf("Identity.Roles = %v: the platform_admin role in roles is not reported by Has", id.Roles)
	}
}

// CallsOnlyTheKeySet: while authenticating, the service reaches the issuer
// for its discovery document and key set and for nothing else.
func CallsOnlyTheKeySet(t TB, s Service) {
	t.Helper()
	iss, a := setup(t, s)
	tok := iss.Mint(issuertest.Claims{Sub: "user_1", Aud: issuertest.StringList{s.Audience}, OrgID: "org_1", PrincipalType: "user"})
	iss.ResetRequests()
	for range 3 {
		if _, err := a.Authenticate(request(tok)); err != nil {
			t.Fatalf("authenticate: %v", err)
		}
	}
	allowed := []string{"GET /jwks", "GET /.well-known/openid-configuration"}
	for _, req := range iss.Requests() {
		if !slices.Contains(allowed, req) {
			t.Errorf("the service called the issuer on the request path: %s", req)
		}
	}
}
