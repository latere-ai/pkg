// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/rsa"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countedJWKS is countingJWKS with the counter it hands back, so a case
// that only wants the count does not declare one.
func countedJWKS(t *testing.T, key *rsa.PrivateKey) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	return countingJWKS(t, key, &hits), &hits
}

// TestWarmFetchesTheKeySetOnce: a start-up probe warms the validator and
// the first request it precedes does not fetch again. Warming twice
// fetches once, so a probe that runs on a schedule costs one fetch per
// CacheTTL and not one per probe.
func TestWarmFetchesTheKeySetOnce(t *testing.T) {
	key := genKey(t)
	srv, hits := countedJWKS(t, key)
	v := New(Config{JWKSURL: srv.URL, CacheTTL: time.Hour})

	if err := v.Warm(t.Context()); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("the key set was fetched %d times; Warm fetches it once", got)
	}
	if err := v.Warm(t.Context()); err != nil {
		t.Fatalf("the second Warm: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("the key set was fetched %d times; Warm is idempotent inside the cache TTL", got)
	}
	if _, err := v.Validate(signToken(t, key, defaultHeader(key), defaultPayload())); err != nil {
		t.Fatalf("Validate after Warm: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("the key set was fetched %d times; the first request is served from what Warm read", got)
	}
}

// TestWarmFetchesEveryConfiguredIssuer: a validator that trusts several
// issuers warms each one's key set, discovery included, so no issuer is
// left to pay for its first request.
func TestWarmFetchesEveryConfiguredIssuer(t *testing.T) {
	first, second := genKey(t), genKey(t)
	var firstHits, secondHits atomic.Int64
	a := serveIssuer(t, first, &firstHits)
	b := serveIssuer(t, second, &secondHits)
	v := New(Config{Issuers: []string{a.URL, b.URL}, CacheTTL: time.Hour})

	if err := v.Warm(t.Context()); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if firstHits.Load() != 1 || secondHits.Load() != 1 {
		t.Fatalf("key sets fetched %d and %d times; Warm reads every configured issuer once",
			firstHits.Load(), secondHits.Load())
	}
	if _, err := v.Validate(issuerToken(t, first, a.URL)); err != nil {
		t.Fatalf("Validate after Warm: %v", err)
	}
	if firstHits.Load() != 1 {
		t.Fatalf("the first issuer's set was fetched %d times; the request is served from what Warm read", firstHits.Load())
	}
}

// TestWarmCoversTheSingleIssuerBesideTheList: Config.Issuer keeps its own
// JWKSURL and is trusted beside the list, so it is warmed with the rest
// and its tokens verify without a fetch.
func TestWarmCoversTheSingleIssuerBesideTheList(t *testing.T) {
	own, other := genKey(t), genKey(t)
	srv, hits := countedJWKS(t, own)
	var otherHits atomic.Int64
	b := serveIssuer(t, other, &otherHits)
	v := New(Config{
		Issuer: "https://auth.latere.ai", JWKSURL: srv.URL,
		Issuers: []string{b.URL}, CacheTTL: time.Hour,
	})

	if err := v.Warm(t.Context()); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if hits.Load() != 1 || otherHits.Load() != 1 {
		t.Fatalf("key sets fetched %d and %d times; both are configured issuers", hits.Load(), otherHits.Load())
	}
	if _, err := v.Validate(signToken(t, own, defaultHeader(own), defaultPayload())); err != nil {
		t.Fatalf("Validate after Warm: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("the single issuer's set was fetched %d times after Warm", hits.Load())
	}
}

// TestWarmReportsAnIssuerItCouldNotRead: warming is a report and not a
// verdict. The error names the issuer that did not answer, and a
// validator whose warm failed still verifies: the fetch is retried when a
// token arrives.
func TestWarmReportsAnIssuerItCouldNotRead(t *testing.T) {
	key := genKey(t)
	reachable := serveIssuer(t, key)
	const unreachable = "http://127.0.0.1:1"
	v := New(Config{Issuers: []string{reachable.URL, unreachable}, CacheTTL: time.Hour})

	err := v.Warm(t.Context())
	if err == nil {
		t.Fatal("Warm reported nothing; an issuer that did not answer is what a start-up probe exists to find")
	}
	if !strings.Contains(err.Error(), unreachable) {
		t.Fatalf("Warm = %v; the error names the issuer that did not answer", err)
	}
	// The one that did answer is warm, and its tokens verify.
	if _, err := v.Validate(issuerToken(t, key, reachable.URL)); err != nil {
		t.Fatalf("the issuer that answered does not verify: %v", err)
	}
}

// TestWarmWithNoKeySetToFetch: a validator of a local issuer alone
// reaches no network at all, so there is nothing to warm and warming is
// not an error.
func TestWarmWithNoKeySetToFetch(t *testing.T) {
	key := genKey(t)
	v := New(Config{LocalIssuer: "https://local.example", LocalKey: &key.PublicKey, CacheTTL: time.Hour})
	if err := v.Warm(t.Context()); err != nil {
		t.Fatalf("Warm with no configured key set: %v", err)
	}
}

// TestWarmStopsOnACancelledContext: the caller's context bounds the walk,
// so a start-up that is being torn down does not sit through every
// issuer.
func TestWarmStopsOnACancelledContext(t *testing.T) {
	key := genKey(t)
	srv, hits := countedJWKS(t, key)
	v := New(Config{JWKSURL: srv.URL, CacheTTL: time.Hour})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := v.Warm(ctx); err == nil {
		t.Fatal("Warm on a cancelled context reported nothing")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("the key set was fetched %d times on a cancelled context", got)
	}
}
