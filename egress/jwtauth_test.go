// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"latere.ai/x/pkg/authkit/jwt"
)

const (
	testAudience = "acme-egress"
	testScope    = "trust-plane:egress"
	testKind     = "workload"
)

type fakeValidator struct {
	claims *jwt.Claims
	err    error
}

func (f fakeValidator) Validate(string) (*jwt.Claims, error) { return f.claims, f.err }

// authWith builds a TokenAuth over a fake validator with the sandbox-shaped
// policy: audience, scope, kind, and a custom subject claim.
func authWith(c *jwt.Claims, err error) *TokenAuth {
	return &TokenAuth{v: fakeValidator{claims: c, err: err}, scope: testScope, aud: testAudience, kind: testKind, subject: "workload_id"}
}

// goodClaims returns a claim set that passes every check.
func goodClaims(actor string) *jwt.Claims {
	return &jwt.Claims{Kind: testKind, ActorID: actor, Scopes: []string{testScope}, Aud: []string{testAudience}}
}

// rawJWT builds a syntactically valid RS256 token with the given kid. The
// signature is nonsense: it only has to survive header parsing so Validate
// reaches the JWKS fetch, and payload decoding so the subject claim is read.
func rawJWT(kid, payload string) string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"RS256","kid":"`+kid+`"}`) + "." + enc(payload) + "." + enc("sig")
}

// tok is a bearer header carrying a token whose payload names the principal
// under the custom subject claim.
func tok(principal string) string { return "Bearer " + rawJWT("k1", `{"workload_id":"`+principal+`"}`) }

func TestTokenAuth_Accepts(t *testing.T) {
	a := authWith(goodClaims("w-1"), nil)
	id, ok := a.Authenticate(tok("w-1"))
	if !ok || id != "w-1" {
		t.Fatalf("expected w-1/ok, got %q/%v", id, ok)
	}
	// scheme is case-insensitive
	if _, ok := a.Authenticate("bearer " + rawJWT("k1", `{"workload_id":"w-1"}`)); !ok {
		t.Fatal("lowercase bearer should work")
	}
	// Basic auth carries the JWT as the password (HTTPS_PROXY userinfo).
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x:"+rawJWT("k1", `{"workload_id":"w-1"}`)))
	if id, ok := a.Authenticate(basic); !ok || id != "w-1" {
		t.Fatalf("basic-auth token should authenticate, got %q/%v", id, ok)
	}
	// aud may be a list (RFC 7519 array form) as long as it contains ours.
	multi := goodClaims("w-1")
	multi.Aud = []string{"other-audience", testAudience}
	if _, ok := authWith(multi, nil).Authenticate(tok("w-1")); !ok {
		t.Fatal("multi-audience token containing ours should authenticate")
	}
}

// The principal comes from the configured subject claim, not from a fixed
// field: the same verified claims yield different principals under different
// claim names, and "sub" is the default.
func TestTokenAuth_SubjectClaim(t *testing.T) {
	raw := "Bearer " + rawJWT("k1", `{"sub":"user-9","workload_id":"w-1","n":7}`)
	for claim, want := range map[string]string{"sub": "user-9", "workload_id": "w-1"} {
		a := &TokenAuth{v: fakeValidator{claims: goodClaims("x")}, aud: testAudience, subject: claim}
		if id, ok := a.Authenticate(raw); !ok || id != want {
			t.Fatalf("claim %q: got %q/%v want %q", claim, id, ok, want)
		}
	}
	// A claim that is missing, empty, or not a string rejects the token.
	for _, claim := range []string{"missing", "n"} {
		a := &TokenAuth{v: fakeValidator{claims: goodClaims("x")}, aud: testAudience, subject: claim}
		if id, ok := a.Authenticate(raw); ok {
			t.Fatalf("claim %q: expected reject, got %q", claim, id)
		}
	}
	empty := "Bearer " + rawJWT("k1", `{"workload_id":""}`)
	if _, ok := authWith(goodClaims("x"), nil).Authenticate(empty); ok {
		t.Fatal("empty subject claim must reject")
	}
	// A verified token whose payload is not decodable cannot name a principal.
	a := &TokenAuth{v: fakeValidator{claims: goodClaims("x")}, aud: testAudience, subject: "sub"}
	if _, ok := a.Authenticate("Bearer not.a.jwt"); ok {
		t.Fatal("undecodable payload must reject")
	}
}

// Scope and kind are enforced only when configured.
func TestTokenAuth_OptionalChecks(t *testing.T) {
	c := &jwt.Claims{Kind: "other", Aud: []string{testAudience}}
	a := &TokenAuth{v: fakeValidator{claims: c}, aud: testAudience, subject: "workload_id"}
	if _, ok := a.Authenticate(tok("w-1")); !ok {
		t.Fatal("no scope or kind configured: token should authenticate")
	}
}

func TestBearerToken_Malformed(t *testing.T) {
	a := authWith(goodClaims("w"), nil)
	for _, h := range []string{"Basic !!!notbase64", "Basic " + base64.StdEncoding.EncodeToString([]byte("nopasswordhere")), "Bearer", "justtoken", "Digest abc"} {
		if _, ok := a.Authenticate(h); ok {
			t.Fatalf("malformed header %q should not authenticate", h)
		}
	}
}

// bearerToken never panics, and a Basic header yields exactly the password
// half of the decoded userinfo.
func FuzzBearerToken(f *testing.F) {
	f.Add("Bearer abc")
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte("x:secret")))
	f.Add("Digest abc")
	f.Fuzz(func(t *testing.T, header string) {
		got := bearerToken(header)
		scheme, rest, ok := strings.Cut(strings.TrimSpace(header), " ")
		if !ok {
			if got != "" {
				t.Fatalf("no scheme separator but token %q", got)
			}
			return
		}
		switch {
		case strings.EqualFold(scheme, "Bearer"):
			if got != strings.TrimSpace(rest) {
				t.Fatalf("bearer: got %q want %q", got, strings.TrimSpace(rest))
			}
		case strings.EqualFold(scheme, "Basic"):
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
			if err != nil {
				if got != "" {
					t.Fatalf("bad base64 but token %q", got)
				}
				return
			}
			_, pass, has := strings.Cut(string(raw), ":")
			if has && got != pass {
				t.Fatalf("basic: got %q want %q", got, pass)
			}
			if !has && got != "" {
				t.Fatalf("basic without password but token %q", got)
			}
		default:
			if got != "" {
				t.Fatalf("unknown scheme %q but token %q", scheme, got)
			}
		}
	})
}

func TestTokenAuth_Rejects(t *testing.T) {
	wrongKind := goodClaims("w")
	wrongKind.Kind = "user"
	wrongScope := goodClaims("w")
	wrongScope.Scopes = []string{"other"}
	wrongAud := goodClaims("w")
	wrongAud.Aud = []string{"other.example"}
	missingAud := goodClaims("w")
	missingAud.Aud = nil
	cases := []struct {
		name   string
		header string
		auth   *TokenAuth
	}{
		{"empty header", "", authWith(goodClaims("w"), nil)},
		{"no bearer scheme", "Basic abc", authWith(goodClaims("w"), nil)},
		{"validate error", tok("w"), authWith(nil, errors.New("bad sig"))},
		{"nil claims", tok("w"), authWith(nil, nil)},
		{"wrong kind", tok("w"), authWith(wrongKind, nil)},
		{"missing scope", tok("w"), authWith(wrongScope, nil)},
		{"wrong audience", tok("w"), authWith(wrongAud, nil)},
		{"missing audience", tok("w"), authWith(missingAud, nil)},
	}
	for _, c := range cases {
		if id, ok := c.auth.Authenticate(c.header); ok {
			t.Fatalf("%s: expected reject, got %q", c.name, id)
		}
	}
}

// The constructor refuses a configuration with no key set or no audience:
// there is no unscoped mode.
func TestNewTokenAuth_RequiresJWKSAndAudience(t *testing.T) {
	if _, err := NewTokenAuth(TokenAuthOptions{Audience: testAudience}); err == nil {
		t.Fatal("missing JWKSURL should error")
	}
	if _, err := NewTokenAuth(TokenAuthOptions{JWKSURL: "https://issuer.test/keys"}); err == nil {
		t.Fatal("missing Audience should error")
	}
	a, err := NewTokenAuth(TokenAuthOptions{JWKSURL: "https://issuer.test/keys", Audience: testAudience})
	if err != nil {
		t.Fatal(err)
	}
	if a.subject != DefaultSubjectClaim {
		t.Fatalf("default subject claim = %q", a.subject)
	}
}

// mapValidator resolves each raw token string to its own claim set, so one
// gateway can see tokens of different shapes in a single test.
type mapValidator struct{ byTok map[string]*jwt.Claims }

func (m mapValidator) Validate(raw string) (*jwt.Claims, error) {
	if c, ok := m.byTok[raw]; ok {
		return c, nil
	}
	return nil, errors.New("unknown token")
}

// End-to-end audience enforcement at the CONNECT layer: a token that is valid
// in every way except its audience is rejected with 407 before any tunnel is
// opened; the correctly-audienced token proceeds through substitution.
func TestGateway_AudienceEnforcedOnConnect(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("w-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	wrongAud := goodClaims("w-1")
	wrongAud.Aud = []string{"other.example"}
	right := rawJWT("k1", `{"workload_id":"w-1","v":"right"}`)
	wrong := rawJWT("k1", `{"workload_id":"w-1","v":"wrong"}`)
	auth := &TokenAuth{
		v: mapValidator{byTok: map[string]*jwt.Claims{
			right: goodClaims("w-1"),
			wrong: wrongAud,
		}},
		scope:   testScope,
		aud:     testAudience,
		kind:    testKind,
		subject: "workload_id",
	}
	proxy := newGateway(t, reg, ca, up, auth)

	// Wrong audience: CONNECT is refused with 407.
	bad := clientThrough(t, proxy.URL, "Bearer "+wrong, bothRoots(ca, up))
	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	badResp, err := bad.Do(req)
	if badResp != nil {
		defer badResp.Body.Close()
	}
	if err == nil {
		t.Fatal("wrong-audience token should fail the CONNECT")
	} else if !strings.Contains(err.Error(), "407") && !strings.Contains(err.Error(), "Proxy Authentication") {
		t.Fatalf("expected 407 proxy auth error, got %v", err)
	}

	// Right audience: the tunnel opens and substitution happens.
	good := clientThrough(t, proxy.URL, "Bearer "+right, bothRoots(ca, up))
	req2, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req2.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := good.Do(req2)
	if err != nil {
		t.Fatalf("right-audience request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "auth=Bearer sk-realsecret") {
		t.Fatalf("substitution did not happen for right-audience token: %q", body)
	}
}

// recordSpans installs a real SDK tracer provider with an in-memory recorder
// and the composite propagator the platform uses, restoring the previous
// globals afterwards. Asserting on recorded spans is the only way to see what
// a wrapped client actually exports; a type assertion on a Transport field
// passes even in a process where no provider is registered and nothing is ever
// recorded.
func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(sr),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return sr
}

func newJWKSAuth(t *testing.T, jwksURL string) *TokenAuth {
	t.Helper()
	a, err := NewTokenAuth(TokenAuthOptions{JWKSURL: jwksURL, Issuer: "https://issuer.test", Audience: testAudience, Scope: testScope, Kind: testKind})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// The JWKS fetch is the gateway's own outbound call, so it must carry the otel
// transport: without it the key refresh is invisible, and a JWKS endpoint that
// is slow or failing looks like an unexplained rise in 407s at the proxy.
func TestTokenAuth_JWKSFetchIsTraced(t *testing.T) {
	sr := recordSpans(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(jwks.Close)

	a := newJWKSAuth(t, jwks.URL+"/v1/keys")
	if _, ok := a.Authenticate("Bearer " + rawJWT("k1", `{"sub":"s"}`)); ok {
		t.Fatal("an unsigned token must not authenticate")
	}

	var client int
	for _, s := range sr.Ended() {
		if s.SpanKind() == trace.SpanKindClient {
			client++
		}
	}
	if client == 0 {
		t.Fatal("JWKS fetch recorded no client span; the validator is not using the instrumented transport")
	}
}

// The token under validation must never reach a span. It is a live workload
// credential, and the JWKS fetch happens while the gateway holds it.
func TestTokenAuth_JWKSSpanOmitsTheToken(t *testing.T) {
	sr := recordSpans(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(jwks.Close)

	const sentinel = "planted-workload-token-2f7c1e"
	a := newJWKSAuth(t, jwks.URL+"/v1/keys")
	if _, ok := a.Authenticate("Bearer " + rawJWT("k1", `{"sub":"`+sentinel+`"}`)); ok {
		t.Fatal("an unsigned token must not authenticate")
	}

	for _, s := range sr.Ended() {
		for _, kv := range s.Attributes() {
			if strings.Contains(kv.Value.String(), sentinel) {
				t.Fatalf("span attribute %s leaked the token: %s", kv.Key, kv.Value.String())
			}
		}
		if strings.Contains(s.Name(), sentinel) {
			t.Fatalf("span name leaked the token: %s", s.Name())
		}
	}
}

// A supplied HTTP client is the one the JWKS fetch uses.
func TestNewTokenAuth_UsesSuppliedClient(t *testing.T) {
	var hits int
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(jwks.Close)
	a, err := NewTokenAuth(TokenAuthOptions{JWKSURL: jwks.URL, Audience: testAudience, HTTPClient: jwks.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Authenticate("Bearer " + rawJWT("k1", `{"sub":"s"}`)); ok {
		t.Fatal("an unsigned token must not authenticate")
	}
	if hits == 0 {
		t.Fatal("the JWKS was never fetched through the supplied client")
	}
}
