// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"testing"
	"time"

	"latere.ai/x/pkg/authkit/issuertest"
)

// mintWorkloadToken signs a sandbox-shaped workload token: the audience,
// scope, kind and subject TokenAuth checks, with the issued-at and expiry
// the caller names, so a test ages a token without waiting.
func mintWorkloadToken(srv *issuertest.Server, iat, exp time.Time) string {
	return srv.Mint(issuertest.Claims{
		Sub: "sbx-7f3a",
		Aud: issuertest.StringList{testAudience},
		Iat: iat.Unix(),
		Exp: exp.Unix(),
		Extra: map[string]any{
			"kind": testKind,
			"scp":  []string{testScope},
		},
	})
}

// workloadAuth builds a TokenAuth over the stub issuer with the policy the
// sandbox gateway runs. opts carries the fields under test; the rest are
// filled from the issuer.
func workloadAuth(t *testing.T, srv *issuertest.Server, maxAge time.Duration) *TokenAuth {
	t.Helper()
	a, err := NewTokenAuth(TokenAuthOptions{
		JWKSURL:     srv.JWKSURL(),
		Issuer:      srv.URL(),
		Audience:    testAudience,
		Scope:       testScope,
		Kind:        testKind,
		MaxTokenAge: maxAge,
	})
	if err != nil {
		t.Fatalf("NewTokenAuth: %v", err)
	}
	return a
}

// TestTokenAuth_WorkloadTokenIsBoundedByExp: a workload credential lives as
// long as its "exp" says, and the issuing plane re-mints it on its own
// schedule, so an age bound at the gateway refuses a token the issuer still
// vouches for. A sandbox token lives seven days and is re-minted on a daily
// tick, so the routine case is a token about a day old; two days old is the
// same case after one missed tick.
//
// The fresh token is the control: it carries the identical claim set, so a
// refusal of the aged token can only be its age.
func TestTokenAuth_WorkloadTokenIsBoundedByExp(t *testing.T) {
	srv := issuertest.New(t)
	a := workloadAuth(t, srv, 0)
	now := time.Now()

	fresh := mintWorkloadToken(srv, now, now.Add(5*24*time.Hour))
	if _, ok := a.Authenticate("Bearer " + fresh); !ok {
		_, err := a.v.Validate(fresh)
		t.Fatalf("a freshly minted workload token was refused: %v", err)
	}

	aged := mintWorkloadToken(srv, now.Add(-48*time.Hour), now.Add(5*24*time.Hour))
	principal, ok := a.Authenticate("Bearer " + aged)
	if !ok {
		_, err := a.v.Validate(aged)
		t.Fatalf("a two-day-old workload token with five days left was refused: %v", err)
	}
	if principal != "sbx-7f3a" {
		t.Fatalf("principal = %q, want %q", principal, "sbx-7f3a")
	}
}

// TestTokenAuth_ExpiredWorkloadTokenIsRefused: dropping the age bound leaves
// "exp" doing the whole job, so a token past it is refused.
func TestTokenAuth_ExpiredWorkloadTokenIsRefused(t *testing.T) {
	srv := issuertest.New(t)
	a := workloadAuth(t, srv, 0)
	now := time.Now()

	expired := mintWorkloadToken(srv, now.Add(-8*24*time.Hour), now.Add(-time.Hour))
	if _, ok := a.Authenticate("Bearer " + expired); ok {
		t.Fatal("an expired workload token was accepted")
	}
}

// TestTokenAuth_MaxTokenAgeOptionBounds: a deployment whose issuer re-mints
// faster than its tokens expire asks for the age bound back, and the
// gateway then refuses a token older than it whatever "exp" it carries.
func TestTokenAuth_MaxTokenAgeOptionBounds(t *testing.T) {
	srv := issuertest.New(t)
	a := workloadAuth(t, srv, time.Hour)
	now := time.Now()

	aged := mintWorkloadToken(srv, now.Add(-48*time.Hour), now.Add(5*24*time.Hour))
	if _, ok := a.Authenticate("Bearer " + aged); ok {
		t.Fatal("a two-day-old token was accepted under a one-hour MaxTokenAge")
	}
	fresh := mintWorkloadToken(srv, now, now.Add(5*24*time.Hour))
	if _, ok := a.Authenticate("Bearer " + fresh); !ok {
		_, err := a.v.Validate(fresh)
		t.Fatalf("a fresh token was refused under a one-hour MaxTokenAge: %v", err)
	}
}
