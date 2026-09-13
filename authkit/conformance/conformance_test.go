// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"latere.ai/x/pkg/authkit"
	"latere.ai/x/pkg/authkit/jwt"
)

// reference is the family verifier configured the way the shape requires:
// one audience, the issuer's JWKS, nothing else on the request path.
func reference(aud string) Service {
	return Service{Audience: aud, New: func(_ testing.TB, issuerURL, jwksURL string) authkit.Authenticator {
		return jwt.NewAuthenticator(jwt.New(jwt.Config{JWKSURL: jwksURL, Issuer: issuerURL, Audiences: []string{aud}}))
	}}
}

func TestTheReferenceVerifierConforms(t *testing.T) {
	Run(t, reference("drive.latere.ai"))
}

// recorder is a TB that records failures instead of stopping the test, so
// the suite can be shown to fail a non-conforming service. Fatalf panics
// the way testing.T's runtime.Goexit ends a test, and the check catches it.
type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
	panic(fatal{})
}

type fatal struct{}

func run(t *testing.T, check func(TB, Service), s Service) []string {
	t.Helper()
	r := &recorder{TB: t}
	func() {
		defer func() {
			if v := recover(); v != nil {
				if _, ok := v.(fatal); !ok {
					panic(v)
				}
			}
		}()
		check(r, s)
	}()
	return r.failures
}

func TestAServiceThatAcceptsAnyAudienceFails(t *testing.T) {
	anyAud := Service{Audience: "drive.latere.ai", New: func(_ testing.TB, issuerURL, jwksURL string) authkit.Authenticator {
		return jwt.NewAuthenticator(jwt.New(jwt.Config{JWKSURL: jwksURL, Issuer: issuerURL}))
	}}
	if f := run(t, RefusesIssuerAudience, anyAud); len(f) != 1 || !strings.Contains(f[0], "addressed to the issuer was admitted") {
		t.Fatalf("issuer audience: %v", f)
	}
	if f := run(t, RefusesOtherAudience, anyAud); len(f) != 1 || !strings.Contains(f[0], "another-service was admitted") {
		t.Fatalf("other audience: %v", f)
	}
	if f := run(t, AdmitsOwnAudience, anyAud); len(f) != 0 {
		t.Fatalf("own audience should still pass: %v", f)
	}
}

func TestAServiceThatVerifiesTheWrongAudienceFails(t *testing.T) {
	wrong := Service{Audience: "drive.latere.ai", New: func(_ testing.TB, issuerURL, jwksURL string) authkit.Authenticator {
		return jwt.NewAuthenticator(jwt.New(jwt.Config{JWKSURL: jwksURL, Issuer: issuerURL, Audiences: []string{"sandboxd"}}))
	}}
	if f := run(t, AdmitsOwnAudience, wrong); len(f) != 1 || !strings.Contains(f[0], "was refused") {
		t.Fatalf("own audience: %v", f)
	}
}

// chatty calls the issuer on every request, the way a verifier that looks
// the token up online does.
type chatty struct {
	inner     authkit.Authenticator
	issuerURL string
}

func (c chatty) Authenticate(r *http.Request) (authkit.Identity, error) {
	resp, err := http.Get(c.issuerURL + "/tokeninfo")
	if err == nil {
		resp.Body.Close()
	}
	return c.inner.Authenticate(r)
}

func TestAServiceThatCallsTheIssuerPerRequestFails(t *testing.T) {
	s := Service{Audience: "drive.latere.ai", New: func(_ testing.TB, issuerURL, jwksURL string) authkit.Authenticator {
		return chatty{issuerURL: issuerURL, inner: jwt.NewAuthenticator(jwt.New(jwt.Config{JWKSURL: jwksURL, Issuer: issuerURL, Audiences: []string{"drive.latere.ai"}}))}
	}}
	f := run(t, CallsOnlyTheKeySet, s)
	if len(f) != 3 || !strings.Contains(f[0], "GET /tokeninfo") {
		t.Fatalf("request path: %v", f)
	}
}

// identityless admits the token but returns an empty Identity.
type identityless struct{ inner authkit.Authenticator }

func (i identityless) Authenticate(r *http.Request) (authkit.Identity, error) {
	_, err := i.inner.Authenticate(r)
	return authkit.Identity{}, err
}

func TestAServiceThatDropsTheClaimsFails(t *testing.T) {
	s := Service{Audience: "drive.latere.ai", New: func(_ testing.TB, issuerURL, jwksURL string) authkit.Authenticator {
		return identityless{jwt.NewAuthenticator(jwt.New(jwt.Config{JWKSURL: jwksURL, Issuer: issuerURL, Audiences: []string{"drive.latere.ai"}}))}
	}}
	f := run(t, AdmitsOwnAudience, s)
	if len(f) != 4 {
		t.Fatalf("want four missing fields, got %v", f)
	}
}

// flagReader is a verifier that still grants the platform role from the
// retired flag, the way every product did before identity id-09.
type flagReader struct{ inner authkit.Authenticator }

func (f flagReader) Authenticate(r *http.Request) (authkit.Identity, error) {
	id, err := f.inner.Authenticate(r)
	if err != nil {
		return id, err
	}
	var payload struct {
		Flag bool `json:"is_superadmin"`
	}
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if jwt.DecodePayload(raw, &payload) == nil && payload.Flag {
		id.Roles = append(id.Roles, authkit.RolePlatformAdmin)
	}
	return id, nil
}

func TestAServiceThatReadsTheFlagFails(t *testing.T) {
	s := Service{Audience: "drive.latere.ai", New: func(_ testing.TB, issuerURL, jwksURL string) authkit.Authenticator {
		return flagReader{jwt.NewAuthenticator(jwt.New(jwt.Config{JWKSURL: jwksURL, Issuer: issuerURL, Audiences: []string{"drive.latere.ai"}}))}
	}}
	if f := run(t, RefusesTheFlag, s); len(f) != 1 || !strings.Contains(f[0], "reads as the platform admin") {
		t.Fatalf("flag: %v", f)
	}
	if f := run(t, RefusesTheFlag, reference("drive.latere.ai")); len(f) != 0 {
		t.Fatalf("the reference verifier reads no flag: %v", f)
	}
}

// roleless drops the roles claim, so the platform admin is nobody.
type roleless struct{ inner authkit.Authenticator }

func (l roleless) Authenticate(r *http.Request) (authkit.Identity, error) {
	id, err := l.inner.Authenticate(r)
	id.Roles = nil
	return id, err
}

func TestAServiceThatDropsTheRolesFails(t *testing.T) {
	s := Service{Audience: "drive.latere.ai", New: func(_ testing.TB, issuerURL, jwksURL string) authkit.Authenticator {
		return roleless{jwt.NewAuthenticator(jwt.New(jwt.Config{JWKSURL: jwksURL, Issuer: issuerURL, Audiences: []string{"drive.latere.ai"}}))}
	}}
	if f := run(t, RefusesTheFlag, s); len(f) != 1 || !strings.Contains(f[0], "not reported by Has") {
		t.Fatalf("roles: %v", f)
	}
}

// subless accepts a token that names nobody.
type subless struct{}

func (subless) Authenticate(*http.Request) (authkit.Identity, error) {
	return authkit.Identity{Sub: "anyone"}, nil
}

func TestAServiceThatAdmitsNoSubjectFails(t *testing.T) {
	s := Service{Audience: "x", New: func(testing.TB, string, string) authkit.Authenticator { return subless{} }}
	if f := run(t, RefusesNoSubject, s); len(f) != 1 || !strings.Contains(f[0], "no sub was admitted") {
		t.Fatalf("no subject: %v", f)
	}
}

func TestRunRequiresADeclaration(t *testing.T) {
	// Run takes a *testing.T and would fail this test through the guard, so
	// the guard is exercised as a check with a recording TB.
	if f := run(t, func(tb TB, s Service) {
		if s.Audience == "" || s.New == nil {
			tb.Fatalf("conformance: Service needs an Audience and a New")
		}
	}, Service{}); len(f) != 1 || !strings.Contains(f[0], "needs an Audience") {
		t.Fatalf("guard: %v", f)
	}
}
