// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const localIssuer = "https://node.example"

// signES256 signs a token with a P-256 key, r and s as the JWS form.
func signES256(t *testing.T, key *ecdsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	input := b64(header) + "." + b64(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, hashSHA256([]byte(input)))
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// localToken is a token the node minted for itself: its own issuer, its own
// key, the kid the configuration names.
func localToken(t *testing.T, key *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	p := defaultPayload()
	p["iss"] = localIssuer
	return signES256(t, key, map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid}, p)
}

func localKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// countingJWKS serves the key set and counts what was asked of it.
func countingJWKS(t *testing.T, key *rsa.PrivateKey, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	data := jwksJSON(t, key)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if _, err := w.Write(data); err != nil {
			t.Errorf("write JWKS: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestLocalIssuerVerifiesWithoutAFetch: a token the node minted for itself
// is verified against the configured key, and the key set is never asked.
// This is how a test or a stub verifies with no issuer to reach.
func TestLocalIssuerVerifiesWithoutAFetch(t *testing.T) {
	remote := genKey(t)
	var hits atomic.Int64
	srv := countingJWKS(t, remote, &hits)
	key := localKey(t)
	v := New(Config{
		JWKSURL: srv.URL, CacheTTL: time.Hour,
		Issuer:      "https://auth.latere.ai",
		LocalIssuer: localIssuer, LocalKey: &key.PublicKey, LocalKeyID: "node-1",
	})

	c, err := v.Validate(localToken(t, key, "node-1"))
	if err != nil {
		t.Fatalf("a local token was refused: %v", err)
	}
	if c.Iss != localIssuer || c.Sub != "user-123" {
		t.Fatalf("claims = %+v", c)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the key set was fetched %d times for a local token", n)
	}
}

// TestLocalIssuerLeavesTheConfiguredIssuerAlone: the two modes stand
// together. A token from the configured issuer still fetches and verifies,
// and the local issuer is not a second value Config.Issuer must carry.
func TestLocalIssuerLeavesTheConfiguredIssuerAlone(t *testing.T) {
	remote := genKey(t)
	var hits atomic.Int64
	srv := countingJWKS(t, remote, &hits)
	key := localKey(t)
	v := New(Config{
		JWKSURL: srv.URL, CacheTTL: time.Hour,
		Issuer:      "https://auth.latere.ai",
		LocalIssuer: localIssuer, LocalKey: &key.PublicKey, LocalKeyID: "node-1",
	})

	if _, err := v.Validate(signToken(t, remote, defaultHeader(remote), defaultPayload())); err != nil {
		t.Fatalf("an issuer's token was refused: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatal("an issuer's token did not reach the key set")
	}
	if _, err := v.Validate(localToken(t, key, "node-1")); err != nil {
		t.Fatalf("a local token was refused beside the issuer's: %v", err)
	}
}

// TestLocalIssuerRefusesAnotherKeyAndAnotherKID: the local key is the only
// one that signs for the local issuer, and the kid must name it.
func TestLocalIssuerRefusesAnotherKeyAndAnotherKID(t *testing.T) {
	remote := genKey(t)
	var hits atomic.Int64
	srv := countingJWKS(t, remote, &hits)
	key, other := localKey(t), localKey(t)
	v := New(Config{
		JWKSURL: srv.URL, CacheTTL: time.Hour,
		LocalIssuer: localIssuer, LocalKey: &key.PublicKey, LocalKeyID: "node-1",
	})

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"another key under the right kid", localToken(t, other, "node-1")},
		{"the right key under another kid", localToken(t, key, "node-2")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Validate(tc.token)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("err = %v, want ErrInvalidSignature", err)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("a refused local token fetched the key set %d times", n)
	}
}

// TestLocalIssuerWithNoKeyPanics: a verifier configured with a local issuer
// and no key for it would refuse every local token as a bad signature, which
// is a wiring mistake and not a verdict. It is refused at New.
func TestLocalIssuerWithNoKeyPanics(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no key", Config{LocalIssuer: localIssuer}},
		{"a key of no usable kind", Config{LocalIssuer: localIssuer, LocalKey: "not a key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("New did not panic")
				}
			}()
			New(tc.cfg)
		})
	}
}

// TestLocalIssuerUnsetChangesNothing: with no local issuer configured, a
// token naming one is an ordinary token, checked against Config.Issuer.
func TestLocalIssuerUnsetChangesNothing(t *testing.T) {
	remote := genKey(t)
	v := testValidator(t, remote, func(c *Config) { c.Issuer = "https://auth.latere.ai" })
	p := defaultPayload()
	p["iss"] = localIssuer
	if _, err := v.Validate(signToken(t, remote, defaultHeader(remote), p)); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("err = %v, want ErrInvalidIssuer", err)
	}
}
