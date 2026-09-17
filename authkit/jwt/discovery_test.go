// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// serveDiscovery stands up an issuer whose discovery document names the
// given issuer rather than the URL the document is served under, and whose
// jwks_uri points at key's set. It is the shape of a key-substitution
// attempt: a URL the node trusts, handing out somebody else's key set.
func serveDiscovery(t *testing.T, key *rsa.PrivateKey, doc string) *httptest.Server {
	t.Helper()
	jwks := serveJWKS(t, key)
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprintf(w, `{%s"jwks_uri":%q}`, doc, jwks.URL); err != nil {
			t.Errorf("write discovery: %v", err)
		}
	})
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// TestDiscoveryRefusesADocumentNamingAnotherIssuer is OpenID Connect
// Discovery 4.3: the issuer a document names must be the issuer it was
// fetched from. Without the check, a document served under a trusted URL
// hands this node another party's key set, and that set then verifies
// tokens minted in the trusted issuer's name. The token below is exactly
// that substitution: it claims the trusted issuer and is signed by the key
// the document pointed at.
func TestDiscoveryRefusesADocumentNamingAnotherIssuer(t *testing.T) {
	elsewhere, trusted := genKey(t), genKey(t)
	front := serveDiscovery(t, elsewhere, `"issuer":"https://elsewhere.example",`)
	v := New(Config{Issuers: []string{front.URL}, CacheTTL: time.Hour})

	_, err := v.Validate(issuerToken(t, elsewhere, front.URL))
	if !errors.Is(err, ErrBadDiscovery) {
		t.Fatalf("a document naming another issuer: err = %v, want ErrBadDiscovery", err)
	}
	if got := ReasonOf(err); got != ReasonBadIssuer {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonBadIssuer)
	}
	// The substitution is refused for the issuer's own key too: no key set
	// was ever read, so nothing of this issuer verifies.
	if _, err := v.Validate(issuerToken(t, trusted, front.URL)); !errors.Is(err, ErrBadDiscovery) {
		t.Fatalf("err = %v, want ErrBadDiscovery", err)
	}
}

// TestDiscoveryRefusesADocumentNamingNoIssuer: a document that omits
// "issuer" states nothing about who published it, so it cannot be the
// issuer's own statement. It is refused on the same row rather than read
// for its jwks_uri.
func TestDiscoveryRefusesADocumentNamingNoIssuer(t *testing.T) {
	key := genKey(t)
	front := serveDiscovery(t, key, "")
	v := New(Config{Issuers: []string{front.URL}, CacheTTL: time.Hour})

	if _, err := v.Validate(issuerToken(t, key, front.URL)); !errors.Is(err, ErrBadDiscovery) {
		t.Fatalf("a document naming no issuer: err = %v, want ErrBadDiscovery", err)
	}
}

// TestDiscoveryAcceptsTheIssuerItWasFetchedFrom: the check is on the name
// and not on the spelling, so a document naming the issuer with a trailing
// slash the configured URL does not carry is the same issuer.
func TestDiscoveryAcceptsTheIssuerItWasFetchedFrom(t *testing.T) {
	key := genKey(t)
	jwks := serveJWKS(t, key)
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, srv.URL+"/", jwks.URL); err != nil {
			t.Errorf("write discovery: %v", err)
		}
	})
	srv.Start()
	t.Cleanup(srv.Close)

	v := New(Config{Issuers: []string{srv.URL}, CacheTTL: time.Hour})
	if _, err := v.Validate(issuerToken(t, key, srv.URL)); err != nil {
		t.Fatalf("a document naming its own issuer was refused: %v", err)
	}
}
