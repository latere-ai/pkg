// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestIssuerUnavailableWhenDiscoveryDoesNotAnswer: a trusted issuer the
// node cannot reach at all. Nothing is known about its tokens, so the
// refusal names the issuer's reach and not the token.
func TestIssuerUnavailableWhenDiscoveryDoesNotAnswer(t *testing.T) {
	key := genKey(t)
	down := serveIssuer(t, key)
	url := down.URL
	down.Close()

	v := New(Config{Issuers: []string{url}, CacheTTL: time.Hour})
	_, err := v.Validate(issuerToken(t, key, url))
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("an unreachable issuer: err = %v, want ErrIssuerUnavailable", err)
	}
	if got := ReasonOf(err); got != ReasonIssuerUnavailable {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonIssuerUnavailable)
	}
	if string(ReasonIssuerUnavailable) != "issuer_unavailable" {
		t.Fatalf("the wire word is %q, want %q", ReasonIssuerUnavailable, "issuer_unavailable")
	}
}

// TestIssuerUnavailableWhenTheKeySetDoesNotAnswer: the discovery document
// answers and the key set it names does not, which is the same row. The
// token is refused because no key could be read, not because a key
// refused it.
func TestIssuerUnavailableWhenTheKeySetDoesNotAnswer(t *testing.T) {
	key := genKey(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(jwks.Close)

	v := New(Config{JWKSURL: jwks.URL, CacheTTL: time.Hour})
	_, err := v.Validate(signToken(t, key, defaultHeader(key), defaultPayload()))
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("a JWKS endpoint that errors: err = %v, want ErrIssuerUnavailable", err)
	}
	if got := ReasonOf(err); got != ReasonIssuerUnavailable {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonIssuerUnavailable)
	}
}

// TestIssuerUnavailableWhenNothingNamesAKeySet: a validator configured
// with neither a JWKS URL nor an issuer to discover one from has no way
// to reach any key, which reads as the issuer being unavailable rather
// than as an unclassified error.
func TestIssuerUnavailableWhenNothingNamesAKeySet(t *testing.T) {
	key := genKey(t)
	v := New(Config{CacheTTL: time.Hour})
	_, err := v.Validate(signToken(t, key, defaultHeader(key), defaultPayload()))
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("no key source at all: err = %v, want ErrIssuerUnavailable", err)
	}
}

// TestACachedKeySetIsStillAnAnswer: the stale-on-error fallback is
// unchanged by the new row. An issuer that goes down after its set was
// read keeps verifying, so issuer_unavailable is the refusal of a node
// that holds nothing, not of every failed fetch.
func TestACachedKeySetIsStillAnAnswer(t *testing.T) {
	clk := newTestClock()
	key := genKey(t)
	up := true
	data := jwksJSON(t, key)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !up {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if _, err := w.Write(data); err != nil {
			t.Errorf("write JWKS: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	v := New(Config{JWKSURL: srv.URL, CacheTTL: time.Minute, Now: clk.Now})
	if _, err := v.Validate(clockToken(t, key, clk.Now())); err != nil {
		t.Fatalf("the first token was refused: %v", err)
	}

	// The endpoint goes down and the cache goes stale. The cached set is
	// still an answer.
	up = false
	clk.advance(2 * time.Minute)
	if _, err := v.Validate(clockToken(t, key, clk.Now())); err != nil {
		t.Fatalf("a token verified by a stale cached set was refused: %v", err)
	}
}

// TestABadDiscoveryDocumentKeepsItsOwnRow: a document that names another
// issuer is not the issuer being out of reach. The issuer answered; what
// it said was refused, so the refusal stays on the issuer row and does
// not become issuer_unavailable.
func TestABadDiscoveryDocumentKeepsItsOwnRow(t *testing.T) {
	key := genKey(t)
	front := serveDiscovery(t, key, `"issuer":"https://elsewhere.example",`)
	v := New(Config{Issuers: []string{front.URL}, CacheTTL: time.Hour})

	_, err := v.Validate(issuerToken(t, key, front.URL))
	if !errors.Is(err, ErrBadDiscovery) {
		t.Fatalf("err = %v, want ErrBadDiscovery", err)
	}
	if errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("err = %v, want the issuer row and not issuer_unavailable", err)
	}
	if got := ReasonOf(err); got != ReasonBadIssuer {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonBadIssuer)
	}
}
