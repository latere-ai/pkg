// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// serveIssuer stands up one issuer: the discovery document that names its
// key set, and the set itself. It is what a verifier configured with an
// issuer URL and no JWKS URL has to find on its own.
func serveIssuer(t *testing.T, key *rsa.PrivateKey, hits ...*atomic.Int64) *httptest.Server {
	t.Helper()
	data := jwksJSON(t, key)
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, srv.URL, srv.URL+"/jwks"); err != nil {
			t.Errorf("write discovery: %v", err)
		}
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		for _, h := range hits {
			h.Add(1)
		}
		if _, err := w.Write(data); err != nil {
			t.Errorf("write JWKS: %v", err)
		}
	})
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// issuerToken is a token minted by key and claiming iss.
func issuerToken(t *testing.T, key *rsa.PrivateKey, iss string) string {
	t.Helper()
	p := defaultPayload()
	p["iss"] = iss
	return signToken(t, key, defaultHeader(key), p)
}

// TestIssuersAdmitsEachAndRefusesAnyOther: a node that trusts a list of
// issuers reads a token from any of them, and a token from an issuer that
// is not on the list is refused as the issuer, before its signature is
// weighed against anything.
func TestIssuersAdmitsEachAndRefusesAnyOther(t *testing.T) {
	ka, kb, kc := genKey(t), genKey(t), genKey(t)
	a, b, c := serveIssuer(t, ka), serveIssuer(t, kb), serveIssuer(t, kc)
	v := New(Config{Issuers: []string{a.URL, b.URL}, CacheTTL: time.Hour})

	for _, tc := range []struct {
		name string
		key  *rsa.PrivateKey
		iss  string
	}{{"the first issuer", ka, a.URL}, {"the second issuer", kb, b.URL}} {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := v.Validate(issuerToken(t, tc.key, tc.iss))
			if err != nil {
				t.Fatalf("a token from %s was refused: %v", tc.iss, err)
			}
			if claims.Iss != tc.iss {
				t.Fatalf("Claims.Iss = %q, want %q", claims.Iss, tc.iss)
			}
		})
	}

	_, err := v.Validate(issuerToken(t, kc, c.URL))
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("a token from an unlisted issuer: err = %v, want ErrInvalidIssuer", err)
	}
	if got := ReasonOf(err); got != ReasonBadIssuer {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonBadIssuer)
	}
}

// TestIssuersKeepTheirKeySetsApart: each issuer answers for its own tokens
// only. A token naming one issuer and signed by another's key is refused,
// so trusting two issuers is not pooling their keys.
func TestIssuersKeepTheirKeySetsApart(t *testing.T) {
	ka, kb := genKey(t), genKey(t)
	a, b := serveIssuer(t, ka), serveIssuer(t, kb)
	v := New(Config{Issuers: []string{a.URL, b.URL}, CacheTTL: time.Hour})

	if _, err := v.Validate(issuerToken(t, kb, a.URL)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

// TestIssuersFetchEachKeySetOnceAndTrimSlashes: a key set is fetched per
// issuer and cached per issuer, and a trailing slash on either side does
// not make a second issuer.
func TestIssuersFetchEachKeySetOnceAndTrimSlashes(t *testing.T) {
	var ha, hb atomic.Int64
	ka, kb := genKey(t), genKey(t)
	a, b := serveIssuer(t, ka, &ha), serveIssuer(t, kb, &hb)
	v := New(Config{Issuers: []string{a.URL + "/", b.URL}, CacheTTL: time.Hour})

	for range 3 {
		if _, err := v.Validate(issuerToken(t, ka, a.URL)); err != nil {
			t.Fatalf("a token from the first issuer was refused: %v", err)
		}
	}
	if ha.Load() != 1 {
		t.Fatalf("the first key set was fetched %d times, want 1", ha.Load())
	}
	if hb.Load() != 0 {
		t.Fatalf("the second key set was fetched for the first issuer's token")
	}
	// The claim carries the slash the configuration does not, and back.
	if _, err := v.Validate(issuerToken(t, kb, b.URL+"/")); err != nil {
		t.Fatalf("a slash made a second issuer: %v", err)
	}
}

// TestIssuersBesideTheSingleIssuerForm: Issuer with its explicit JWKS URL
// still works, and is trusted beside the discovered ones.
func TestIssuersBesideTheSingleIssuerForm(t *testing.T) {
	ka, kb := genKey(t), genKey(t)
	srv := serveJWKS(t, ka)
	b := serveIssuer(t, kb)
	v := New(Config{
		JWKSURL: srv.URL, Issuer: "https://auth.example",
		Issuers: []string{b.URL}, CacheTTL: time.Hour,
	})

	if _, err := v.Validate(issuerToken(t, ka, "https://auth.example")); err != nil {
		t.Fatalf("the single-issuer form was refused: %v", err)
	}
	if _, err := v.Validate(issuerToken(t, kb, b.URL)); err != nil {
		t.Fatalf("a listed issuer was refused: %v", err)
	}
	if _, err := v.Validate(issuerToken(t, ka, "https://elsewhere.example")); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("err = %v, want ErrInvalidIssuer", err)
	}
}

// TestIssuersDiscoveryFailures: an issuer that does not name a key set is
// an issuer whose tokens cannot be verified, and each way it can fail to
// name one surfaces as a fetch error rather than a verdict on the token.
func TestIssuersDiscoveryFailures(t *testing.T) {
	key := genKey(t)
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"the document is a 404", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}},
		{"the document is not JSON", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}},
		{"the document names no jwks_uri", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"issuer":"https://x"}`))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			t.Cleanup(srv.Close)
			v := New(Config{Issuers: []string{srv.URL}, CacheTTL: time.Hour})

			_, err := v.Validate(issuerToken(t, key, srv.URL))
			if err == nil {
				t.Fatal("a token from an issuer that names no key set was admitted")
			}
			if errors.Is(err, ErrInvalidIssuer) {
				t.Fatalf("err = %v: the issuer is trusted, its key set is what could not be read", err)
			}
		})
	}

	// The issuer does not answer at all.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	v := New(Config{Issuers: []string{url}, CacheTTL: time.Hour})
	if _, err := v.Validate(issuerToken(t, key, url)); err == nil {
		t.Fatal("a token from an unreachable issuer was admitted")
	}
}

// TestIssuersSkipEmptyAndRepeatedEntries: a list written by an operator may
// carry a blank entry or name one issuer twice; both are one key set.
func TestIssuersSkipEmptyAndRepeatedEntries(t *testing.T) {
	var hits atomic.Int64
	key := genKey(t)
	a := serveIssuer(t, key, &hits)
	v := New(Config{Issuers: []string{"", a.URL, a.URL + "/", "/"}, CacheTTL: time.Hour})

	for range 2 {
		if _, err := v.Validate(issuerToken(t, key, a.URL)); err != nil {
			t.Fatalf("refused: %v", err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("the key set was fetched %d times, want 1", hits.Load())
	}
}

// TestIssuersUseTheConfiguredHTTPClient: the client a caller supplies for
// trust roots or a proxy is the one that reaches every listed issuer.
func TestIssuersUseTheConfiguredHTTPClient(t *testing.T) {
	var hits atomic.Int64
	key := genKey(t)
	a := serveIssuer(t, key)
	client := &http.Client{Transport: countingTransport{&hits}}
	v := New(Config{Issuers: []string{a.URL}, CacheTTL: time.Hour, HTTPClient: client})

	if _, err := v.Validate(issuerToken(t, key, a.URL)); err != nil {
		t.Fatalf("refused: %v", err)
	}
	// Discovery and the key set, both through the caller's client.
	if hits.Load() != 2 {
		t.Fatalf("the configured client made %d requests, want 2", hits.Load())
	}
}

// countingTransport counts the requests that go through it.
type countingTransport struct{ n *atomic.Int64 }

func (c countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}
