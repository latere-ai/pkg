// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package issuertest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit/jwt"
	"latere.ai/x/pkg/authkit/oidc"
)

func decode(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func validator(s *Server, aud string) *jwt.Validator {
	return jwt.New(jwt.Config{JWKSURL: s.JWKSURL(), Issuer: s.URL(), Audiences: []string{aud}})
}

func TestMintedTokenVerifiesWithTheFamilyValidator(t *testing.T) {
	s := New(t)
	tok := s.Mint(Claims{Sub: "u1", Aud: StringList{"drive"}, OrgID: "org1", Roles: []string{"member"}, PrincipalType: "user"})
	c, err := validator(s, "drive").Validate(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.Sub != "u1" || c.OrgID != "org1" || c.Roles[0] != "member" || c.PrincipalType != "user" || c.Iss != s.URL() {
		t.Fatalf("claims = %+v", c)
	}
}

func TestES256SignsWithAP256KeyAndServesAnECKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
	}{{"generated", []Option{WithES256()}}, {"given", func() []Option {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return []Option{WithKey(key)}
	}()}} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(t, tc.opts...)
			tok := s.Mint(Claims{Aud: StringList{"x"}})
			parts := strings.Split(tok, ".")
			hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
			var h map[string]string
			_ = json.Unmarshal(hdr, &h)
			if h["alg"] != "ES256" || h["kid"] != s.KID() {
				t.Fatalf("header = %v", h)
			}
			resp, err := http.Get(s.JWKSURL())
			if err != nil {
				t.Fatal(err)
			}
			var set struct {
				Keys []map[string]string `json:"keys"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&set)
			resp.Body.Close()
			if len(set.Keys) != 1 || set.Keys[0]["kty"] != "EC" || set.Keys[0]["crv"] != "P-256" {
				t.Fatalf("jwks = %v", set.Keys)
			}
			if sig, _ := base64.RawURLEncoding.DecodeString(parts[2]); len(sig) != 64 {
				t.Fatalf("ES256 signature is %d bytes", len(sig))
			}
		})
	}
}

func TestWithRS256UndoesES256(t *testing.T) {
	s := New(t, WithES256(), WithRS256())
	if _, err := validator(s, "x").Validate(s.Mint(Claims{Aud: StringList{"x"}})); err != nil {
		t.Fatalf("the later RS256 option must win: %v", err)
	}
}

func TestDefaultsAndOmit(t *testing.T) {
	fixed := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	s := New(t, WithClock(func() time.Time { return fixed }), WithDefaultAudience("svc"))
	m := decode(t, s.Mint(Claims{}))
	if m["sub"] != DefaultSubject {
		t.Fatalf("sub = %v", m["sub"])
	}
	if aud, _ := m["aud"].([]any); len(aud) != 1 || aud[0] != "svc" {
		t.Fatalf("aud = %v", m["aud"])
	}
	if int64(m["exp"].(float64)) != fixed.Add(DefaultLifetime).Unix() || int64(m["iat"].(float64)) != fixed.Unix() {
		t.Fatalf("exp/iat = %v/%v", m["exp"], m["iat"])
	}
	m = decode(t, s.Mint(Claims{Omit: []string{"sub", "aud"}, Extra: map[string]any{"act": "svc"}, Nbf: fixed.Unix()}))
	if _, ok := m["sub"]; ok {
		t.Fatal("sub was not omitted")
	}
	if _, ok := m["aud"]; ok {
		t.Fatal("aud was not omitted")
	}
	if m["act"] != "svc" || int64(m["nbf"].(float64)) != fixed.Unix() {
		t.Fatalf("extra/nbf = %v/%v", m["act"], m["nbf"])
	}
	// No default audience configured: no aud claim at all.
	bare := New(t)
	if _, ok := decode(t, bare.Mint(Claims{}))["aud"]; ok {
		t.Fatal("a server without a default audience minted an aud")
	}
}

func TestDiscoveryAndJWKS(t *testing.T) {
	s := New(t)
	resp, err := http.Get(s.URL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var disc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	if disc["issuer"] != s.URL() || disc["jwks_uri"] != s.JWKSURL() {
		t.Fatalf("discovery = %v", disc)
	}
	resp, err = http.Get(s.JWKSURL())
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&set)
	resp.Body.Close()
	if len(set.Keys) != 1 || set.Keys[0]["kid"] != s.KID() || set.Keys[0]["kty"] != "RSA" || set.Keys[0]["alg"] != "RS256" {
		t.Fatalf("jwks = %v", set.Keys)
	}
}

func TestRotateDropsTheOldKey(t *testing.T) {
	s := New(t, WithDefaultAudience("svc"))
	old := s.Mint(Claims{})
	v := validator(s, "svc")
	if _, err := v.Validate(old); err != nil {
		t.Fatalf("before rotate: %v", err)
	}
	s.Rotate()
	fresh := jwt.New(jwt.Config{JWKSURL: s.JWKSURL(), Issuer: s.URL(), Audiences: []string{"svc"}})
	if _, err := fresh.Validate(old); err == nil {
		t.Fatal("a token signed by the dropped key verified")
	}
	if _, err := fresh.Validate(s.Mint(Claims{})); err != nil {
		t.Fatalf("after rotate: %v", err)
	}
}

func TestHangBlocksUntilResumeOrClose(t *testing.T) {
	s := New(t)
	s.Hang()
	done := make(chan int, 1)
	go func() {
		resp, err := http.Get(s.JWKSURL())
		if err != nil {
			done <- -1
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	select {
	case <-done:
		t.Fatal("the JWKS answered while hung")
	case <-time.After(100 * time.Millisecond):
	}
	s.Resume()
	if code := <-done; code != http.StatusOK {
		t.Fatalf("after resume: %d", code)
	}
	s.Hang()
	go func() {
		resp, err := http.Get(s.JWKSURL())
		if err != nil {
			done <- -1
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	time.Sleep(50 * time.Millisecond)
	s.Close()
	if code := <-done; code != http.StatusServiceUnavailable && code != -1 {
		t.Fatalf("after close: %d", code)
	}
}

func TestControlAPIMintsAndRotates(t *testing.T) {
	s := New(t)
	body, _ := json.Marshal(Claims{Sub: "u9", Aud: StringList{"x"}})
	resp, err := http.Post(s.URL()+"/mint", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if decode(t, out["token"])["sub"] != "u9" {
		t.Fatalf("minted sub = %v", decode(t, out["token"])["sub"])
	}
	// A field Claims does not name is minted as an extra claim, so a
	// verification table can ask for a token carrying a retired one.
	resp, err = http.Post(s.URL()+"/mint", "application/json", strings.NewReader(`{"sub":"svc","act":"alice","aud":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if m := decode(t, out["token"]); m["act"] != "alice" || m["sub"] != "svc" {
		t.Fatalf("extra claim not minted: %v", m)
	}
	resp, err = http.Post(s.URL()+"/mint", "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad json = %d", resp.StatusCode)
	}
	before := s.KID()
	for _, p := range []string{"/rotate", "/hang", "/resume"} {
		resp, err := http.Post(s.URL()+p, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s = %d", p, resp.StatusCode)
		}
	}
	if s.KID() == before {
		t.Fatal("rotate did not change the key")
	}
}

func TestActorTokensMintForTheBearer(t *testing.T) {
	s := New(t)
	login := s.Mint(Claims{Sub: "u1", Aud: StringList{s.URL()}, OrgID: "org1", Roles: []string{"owner"}, PrincipalType: "user", Email: "u@example.com"})
	post := func(bearer, body string) (*http.Response, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, s.URL()+"/actor-tokens", strings.NewReader(body))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp, m
	}
	resp, m := post(login, `{"audience":"drive","ttl_seconds":60}`)
	if resp.StatusCode != http.StatusOK || m["expires_in"] != float64(60) || m["token_type"] != "Bearer" {
		t.Fatalf("mint = %d %v", resp.StatusCode, m)
	}
	c, err := validator(s, "drive").Validate(m["actor_token"].(string))
	if err != nil {
		t.Fatalf("actor token: %v", err)
	}
	if c.Sub != "u1" || c.OrgID != "org1" || c.Roles[0] != "owner" || c.PrincipalType != "user" || c.Email != "u@example.com" {
		t.Fatalf("actor claims = %+v", c)
	}
	if resp, m := post(login, `{"audience":"drive","ttl_seconds":9999}`); m["expires_in"] != float64(300) || resp.StatusCode != http.StatusOK {
		t.Fatalf("ttl cap: %v", m)
	}
	for _, tc := range []struct {
		name, bearer, body string
		want               int
	}{
		{"no bearer", "", `{"audience":"drive"}`, http.StatusUnauthorized},
		{"not a token", "abc", `{"audience":"drive"}`, http.StatusUnauthorized},
		{"no audience", login, `{}`, http.StatusBadRequest},
		{"bad json", login, `{`, http.StatusBadRequest},
	} {
		if resp, _ := post(tc.bearer, tc.body); resp.StatusCode != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
}

func TestHandlerRecordsRequests(t *testing.T) {
	s := NewHandler(WithIssuer("http://issuer.test"))
	defer s.Close()
	if s.URL() != "http://issuer.test" {
		t.Fatalf("issuer = %s", s.URL())
	}
	h := s.Handler()
	for _, p := range []string{"/jwks", "/.well-known/openid-configuration"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s = %d", p, rr.Code)
		}
	}
	got := s.Requests()
	if len(got) != 2 || got[0] != "GET /jwks" || got[1] != "GET /.well-known/openid-configuration" {
		t.Fatalf("requests = %v", got)
	}
	s.ResetRequests()
	if len(s.Requests()) != 0 {
		t.Fatal("reset kept requests")
	}
}

func TestStringListDecodesBothShapes(t *testing.T) {
	var one, many, bad StringList
	if err := json.Unmarshal([]byte(`"a"`), &one); err != nil || len(one) != 1 {
		t.Fatalf("one = %v %v", one, err)
	}
	if err := json.Unmarshal([]byte(`["a","b"]`), &many); err != nil || len(many) != 2 {
		t.Fatalf("many = %v %v", many, err)
	}
	if err := json.Unmarshal([]byte(`7`), &bad); err == nil {
		t.Fatal("a number decoded as a string list")
	}
}

// TestTokenEndpointMintsAServiceTokenForARegisteredClient is the
// client_credentials grant end to end through the family's own client:
// oidc.ClientCredentials asks, the stub answers a token addressed to the
// issuer for the account the client stands for, and /actor-tokens narrows
// that token only to the audiences the client's row names.
func TestTokenEndpointMintsAServiceTokenForARegisteredClient(t *testing.T) {
	s := New(t, WithServiceClient("topos-org1", ServiceClient{
		Secret: "s3cret", Sub: "sa-org1", OrgID: "org1", ActorAudiences: []string{"lux.latere.ai", "drive.latere.ai"},
	}))
	ctx := context.Background()

	tok, exp, err := oidc.ClientCredentials(ctx, s.URL(), "topos-org1", "s3cret", "", nil)
	if err != nil {
		t.Fatalf("client_credentials: %v", err)
	}
	if until := time.Until(exp); until < ServiceTokenLifetime-10*time.Second || until > ServiceTokenLifetime {
		t.Fatalf("expiry %v from now, want about %v", until, ServiceTokenLifetime)
	}
	c, err := validator(s, s.URL()).Validate(tok)
	if err != nil {
		t.Fatalf("the service token must verify for the issuer's own audience: %v", err)
	}
	if c.Sub != "sa-org1" || c.OrgID != "org1" || c.PrincipalType != "service" || c.ClientID != "topos-org1" {
		t.Fatalf("service token claims = %+v", c)
	}

	// The grant is refused for a wrong secret, an unknown client, the wrong
	// grant type, and an audience that is not the issuer.
	for _, tc := range []struct{ name, id, secret, aud string }{
		{"wrong secret", "topos-org1", "nope", ""},
		{"unknown client", "nobody", "s3cret", ""},
		{"product audience on the grant", "topos-org1", "s3cret", "lux.latere.ai"},
	} {
		if _, _, err := oidc.ClientCredentials(ctx, s.URL(), tc.id, tc.secret, tc.aud, nil); err == nil {
			t.Errorf("%s: the grant must be refused", tc.name)
		}
	}
	form := url.Values{"grant_type": {"authorization_code"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.URL()+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("topos-org1", "s3cret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("another grant type = %d, want 400", resp.StatusCode)
	}

	// The registry gate: the service token narrows to a listed audience and
	// to nothing else.
	narrow := func(aud string) int {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.URL()+"/actor-tokens", strings.NewReader(`{"audience":"`+aud+`"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var m map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&m)
			ac, err := validator(s, aud).Validate(m["actor_token"].(string))
			if err != nil || ac.Sub != "sa-org1" || ac.PrincipalType != "service" || ac.OrgID != "org1" {
				t.Fatalf("actor token for %s: %+v, %v", aud, ac, err)
			}
		}
		return resp.StatusCode
	}
	if got := narrow("lux.latere.ai"); got != http.StatusOK {
		t.Fatalf("a listed audience = %d, want 200", got)
	}
	if got := narrow("sandboxd"); got != http.StatusBadRequest {
		t.Fatalf("an unlisted audience = %d, want 400 invalid_target", got)
	}
	// A person's bearer names no client and is not gated by the registry.
	person := s.Mint(Claims{Sub: "u1", Aud: StringList{s.URL()}, OrgID: "org1", Roles: []string{"member"}})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, s.URL()+"/actor-tokens", strings.NewReader(`{"audience":"sandboxd"}`))
	req.Header.Set("Authorization", "Bearer "+person)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a person's bearer is not registry-gated by the stub: %d", resp.StatusCode)
	}
}

// TestTokenEndpointWithNoClientsRefusesEveryGrant: a stub that registered
// nothing answers invalid_client, so a test that forgot WithServiceClient
// fails loudly rather than minting for anyone.
func TestTokenEndpointWithNoClientsRefusesEveryGrant(t *testing.T) {
	s := New(t)
	if _, _, err := oidc.ClientCredentials(context.Background(), s.URL(), "any", "thing", "", nil); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want invalid_client 401, got %v", err)
	}
}
