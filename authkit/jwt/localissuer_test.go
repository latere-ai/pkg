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
		want  error
	}{
		// The kid names the local key, so that key answers and refuses it.
		{"another key under the right kid", localToken(t, other, "node-1"), ErrInvalidSignature},
		// The kid names no key the node holds, so no key answers at all.
		{"the right key under another kid", localToken(t, key, "node-2"), ErrUnknownKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Validate(tc.token)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
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

// TestLocalKeysHoldARotation: a rotation holds two keys at once, the newer
// signing and the older still verifying, so tokens minted before the
// rotation are read until they expire. A kid that names neither is refused.
func TestLocalKeysHoldARotation(t *testing.T) {
	remote := genKey(t)
	var hits atomic.Int64
	srv := countingJWKS(t, remote, &hits)
	older, newer := localKey(t), localKey(t)
	v := New(Config{
		JWKSURL: srv.URL, CacheTTL: time.Hour, LocalIssuer: localIssuer,
		LocalKeys: []LocalKey{{KeyID: "old", Key: &older.PublicKey}, {KeyID: "new", Key: &newer.PublicKey}},
	})

	for _, tc := range []struct {
		name string
		key  *ecdsa.PrivateKey
		kid  string
	}{
		{"the key that signs now", newer, "new"},
		{"the key it replaced", older, "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Validate(localToken(t, tc.key, tc.kid)); err != nil {
				t.Fatalf("a token under %q was refused: %v", tc.kid, err)
			}
		})
	}

	for _, tc := range []struct {
		name  string
		token string
		want  error
	}{
		// Neither key of the rotation is named, so none answers.
		{"a kid naming neither key", localToken(t, newer, "third"), ErrUnknownKey},
		// The newer key is named and is the only one that may answer, so
		// the key it replaced does not get to verify in its place.
		{"the older key under the newer kid", localToken(t, older, "new"), ErrInvalidSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Validate(tc.token); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("a local token fetched the key set %d times", n)
	}
}

// TestLocalKeysBesideTheOneKeyForm: LocalKey and LocalKeyID are the
// one-key form of the same set, and the two may be given together.
func TestLocalKeysBesideTheOneKeyForm(t *testing.T) {
	remote := genKey(t)
	var hits atomic.Int64
	srv := countingJWKS(t, remote, &hits)
	one, two := localKey(t), localKey(t)
	v := New(Config{
		JWKSURL: srv.URL, CacheTTL: time.Hour, LocalIssuer: localIssuer,
		LocalKey: &one.PublicKey, LocalKeyID: "one",
		LocalKeys: []LocalKey{{KeyID: "two", Key: &two.PublicKey}},
	})

	if _, err := v.Validate(localToken(t, one, "one")); err != nil {
		t.Fatalf("the one-key form was refused: %v", err)
	}
	if _, err := v.Validate(localToken(t, two, "two")); err != nil {
		t.Fatalf("the listed key was refused: %v", err)
	}
}

// TestLocalKeysWithNoKeyIDAnswerAnyKID: a set whose keys declare no kid
// accepts a token whatever kid it names, as the one-key form does.
func TestLocalKeysWithNoKeyIDAnswerAnyKID(t *testing.T) {
	remote := genKey(t)
	var hits atomic.Int64
	srv := countingJWKS(t, remote, &hits)
	key := localKey(t)
	v := New(Config{
		JWKSURL: srv.URL, CacheTTL: time.Hour, LocalIssuer: localIssuer,
		LocalKeys: []LocalKey{{Key: &key.PublicKey}},
	})

	if _, err := v.Validate(localToken(t, key, "anything")); err != nil {
		t.Fatalf("a key that declares no kid refused a token: %v", err)
	}
}

// TestLocalKeysRejectAKeyOfNoUsableKind: the list is wired at New like the
// one-key form.
func TestLocalKeysRejectAKeyOfNoUsableKind(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New did not panic")
		}
	}()
	New(Config{LocalIssuer: localIssuer, LocalKeys: []LocalKey{{KeyID: "x", Key: "not a key"}}})
}

// TestLocalKeyMayBeRSA: a local issuer signs with either kind of key the
// package verifies with, not only a P-256 one.
func TestLocalKeyMayBeRSA(t *testing.T) {
	key := genKey(t)
	v := New(Config{LocalIssuer: localIssuer, LocalKey: &key.PublicKey, LocalKeyID: "rsa-1"})
	p := defaultPayload()
	p["iss"] = localIssuer
	tok := signToken(t, key, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "rsa-1"}, p)

	if _, err := v.Validate(tok); err != nil {
		t.Fatalf("an RSA local key refused its own token: %v", err)
	}
}

// TestNoKeySetConfiguredAtAll: a validator given neither a JWKS URL nor an
// issuer to discover one from has no key to verify with, and says so.
func TestNoKeySetConfiguredAtAll(t *testing.T) {
	key := genKey(t)
	_, err := New(Config{CacheTTL: time.Hour}).Validate(signToken(t, key, defaultHeader(key), defaultPayload()))
	if err == nil {
		t.Fatal("a token was admitted with no key set configured")
	}
}
