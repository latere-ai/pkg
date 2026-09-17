// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// kidHeader is a token header naming kid, whatever the key's own kid is.
func kidHeader(kid string) map[string]any {
	return map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
}

// TestUnknownKIDIsRefusedThoughTheSignatureChecksOut is the hole this
// closes. The token is signed by a key the set really holds, so its
// signature verifies against that key; what it names in "kid" is a key the
// set does not hold. The set answers by kid, so naming a key that is not
// there is refused, and no other key of the set is tried.
func TestUnknownKIDIsRefusedThoughTheSignatureChecksOut(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	tok := signToken(t, key, kidHeader("a-key-the-set-does-not-hold"), defaultPayload())

	_, err := v.Validate(tok)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
	if got := ReasonOf(err); got != ReasonUnknownKey {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonUnknownKey)
	}
	// The same key under the kid the set knows it by is read.
	if _, err := v.Validate(signToken(t, key, defaultHeader(key), defaultPayload())); err != nil {
		t.Fatalf("the same key under its own kid was refused: %v", err)
	}
}

// TestUnknownKIDIsAcceptedAfterARefreshThatHoldsIt: a kid miss still forces
// one refetch, so a key rotated in at the issuer is picked up rather than
// refused for a whole cache TTL. The refusal is for a kid that is absent
// after that refresh, not before it.
func TestUnknownKIDIsAcceptedAfterARefreshThatHoldsIt(t *testing.T) {
	first, rotated := genKey(t), genKey(t)
	var mu sync.Mutex
	current := first
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		k := current
		mu.Unlock()
		if _, err := w.Write(jwksJSON(t, k)); err != nil {
			t.Errorf("write JWKS: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	v := New(Config{JWKSURL: srv.URL, CacheTTL: time.Hour})
	if _, err := v.Validate(signToken(t, first, defaultHeader(first), defaultPayload())); err != nil {
		t.Fatalf("warming the cache: %v", err)
	}
	mu.Lock()
	current = rotated
	mu.Unlock()
	if _, err := v.Validate(signToken(t, rotated, defaultHeader(rotated), defaultPayload())); err != nil {
		t.Fatalf("a rotated key was refused instead of refetched: %v", err)
	}
}

// TestNoKIDIsAnsweredOnlyByASetOfOne: a token that names no kid leaves the
// set to choose, which is a choice only a set of one key can make. A larger
// set is refused rather than tried key by key.
func TestNoKIDIsAnsweredOnlyByASetOfOne(t *testing.T) {
	key, other := genKey(t), genKey(t)
	noKID := map[string]any{"alg": "RS256", "typ": "JWT"}

	one := New(Config{JWKSURL: serveJWKS(t, key).URL, CacheTTL: time.Hour})
	if _, err := one.Validate(signToken(t, key, noKID, defaultPayload())); err != nil {
		t.Fatalf("a set of one key refused a token with no kid: %v", err)
	}

	two := New(Config{JWKSURL: serveJWKS(t, key, other).URL, CacheTTL: time.Hour})
	_, err := two.Validate(signToken(t, key, noKID, defaultPayload()))
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

// TestUnknownKIDOnTheIssuersPath: the rule is the key set's, so it holds
// for a set reached through Config.Issuers as it does for the one JWKS URL.
func TestUnknownKIDOnTheIssuersPath(t *testing.T) {
	key := genKey(t)
	a := serveIssuer(t, key)
	v := New(Config{Issuers: []string{a.URL}, CacheTTL: time.Hour})

	p := defaultPayload()
	p["iss"] = a.URL
	tok := signToken(t, key, kidHeader("absent"), p)
	if _, err := v.Validate(tok); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

// TestLocalKIDMismatchStaysASignature: the local path answers its own way
// and is not changed here. A token naming a kid the local set does not hold
// is refused as a signature, as it has been.
func TestLocalKIDMismatchStaysASignature(t *testing.T) {
	remote := genKey(t)
	srv := serveJWKS(t, remote)
	key := localKey(t)
	v := New(Config{
		JWKSURL: srv.URL, CacheTTL: time.Hour,
		LocalIssuer: localIssuer, LocalKey: &key.PublicKey, LocalKeyID: "node-1",
	})

	if _, err := v.Validate(localToken(t, key, "node-2")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

// signedByEach is a token per key of a two-key set, each naming its own
// kid, so both are read from a set that holds both.
func TestASetOfManyKeysReadsEachByItsKID(t *testing.T) {
	a, b := genKey(t), genKey(t)
	v := New(Config{JWKSURL: serveJWKS(t, a, b).URL, CacheTTL: time.Hour})
	for _, key := range []*rsa.PrivateKey{a, b} {
		if _, err := v.Validate(signToken(t, key, defaultHeader(key), defaultPayload())); err != nil {
			t.Fatalf("a key of the set was refused under its own kid: %v", err)
		}
	}
}
