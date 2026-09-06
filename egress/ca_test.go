// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestGenerateAndLoadCA(t *testing.T) {
	ca, certPEM, keyPEM, err := GenerateCA("")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if len(ca.CertPEM()) == 0 {
		t.Fatal("empty CertPEM")
	}
	if ca.cert.Subject.CommonName != DefaultCACommonName {
		t.Fatalf("default common name = %q", ca.cert.Subject.CommonName)
	}
	// Round-trip through Load.
	loaded, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if string(loaded.CertPEM()) != string(certPEM) {
		t.Fatal("loaded CA cert PEM differs")
	}
}

func TestGenerateCA_CommonName(t *testing.T) {
	ca, _, _, err := GenerateCA("Acme Egress CA")
	if err != nil {
		t.Fatal(err)
	}
	if ca.cert.Subject.CommonName != "Acme Egress CA" {
		t.Fatalf("common name = %q", ca.cert.Subject.CommonName)
	}
}

func TestLoadCA_Rejects(t *testing.T) {
	_, certPEM, keyPEM, _ := GenerateCA("")
	cases := []struct{ cert, key []byte }{
		{[]byte("garbage"), keyPEM},
		{certPEM, []byte("garbage")},
		{keyPEM, keyPEM}, // cert slot is not a CERTIFICATE
	}
	for i, c := range cases {
		if _, err := LoadCA(c.cert, c.key); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

// LoadCA's post-decode error branches: a valid PEM block wrapping invalid DER,
// and a valid-but-non-CA certificate.
func TestLoadCA_ReachableErrors(t *testing.T) {
	ca, certPEM, keyPEM, err := GenerateCA("")
	if err != nil {
		t.Fatal(err)
	}
	badCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-valid-der")})
	if _, err := LoadCA(badCertPEM, keyPEM); err == nil {
		t.Fatal("invalid cert DER should error")
	}
	// A leaf cert is not a CA.
	tc, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tc.Certificate[0]})
	if _, err := LoadCA(leafPEM, keyPEM); err == nil {
		t.Fatal("non-CA cert should error")
	}
	badKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not-valid-der")})
	if _, err := LoadCA(certPEM, badKeyPEM); err == nil {
		t.Fatal("invalid key DER should error")
	}
}

// LoadCA never panics on arbitrary bytes, and only a CA certificate paired
// with a parseable EC key loads.
func FuzzLoadCA(f *testing.F) {
	_, certPEM, keyPEM, _ := GenerateCA("")
	f.Add(certPEM, keyPEM)
	f.Add([]byte("garbage"), keyPEM)
	f.Add(certPEM, []byte("garbage"))
	f.Fuzz(func(t *testing.T, cert, key []byte) {
		ca, err := LoadCA(cert, key)
		if (err == nil) != (ca != nil) {
			t.Fatalf("LoadCA returned ca=%v err=%v", ca != nil, err)
		}
		if ca != nil && !ca.cert.IsCA {
			t.Fatal("LoadCA accepted a non-CA certificate")
		}
	})
}

// Every crypto seam's failure surfaces from GenerateCA rather than being
// swallowed.
func TestGenerateCA_CryptoFailures(t *testing.T) {
	boom := errors.New("boom")
	prevKey, prevCreate, prevMarshal := generateKey, createCertificate, marshalECKey
	t.Cleanup(func() { generateKey, createCertificate, marshalECKey = prevKey, prevCreate, prevMarshal })

	generateKey = func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error) { return nil, boom }
	if _, _, _, err := GenerateCA(""); !errors.Is(err, boom) {
		t.Fatalf("keygen failure not surfaced: %v", err)
	}
	generateKey = prevKey

	createCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
		return nil, boom
	}
	if _, _, _, err := GenerateCA(""); !errors.Is(err, boom) {
		t.Fatalf("sign failure not surfaced: %v", err)
	}
	createCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
		return []byte("not-der"), nil
	}
	if _, _, _, err := GenerateCA(""); err == nil {
		t.Fatal("unparseable certificate should surface")
	}
	createCertificate = prevCreate

	marshalECKey = func(*ecdsa.PrivateKey) ([]byte, error) { return nil, boom }
	if _, _, _, err := GenerateCA(""); !errors.Is(err, boom) {
		t.Fatalf("key marshal failure not surfaced: %v", err)
	}
}

// A leaf mint fails when the key cannot be generated or when the CA's private
// key does not sign for its certificate.
func TestLeafFor_MintFailures(t *testing.T) {
	boom := errors.New("boom")
	ca, _, _, err := GenerateCA("")
	if err != nil {
		t.Fatal(err)
	}
	ca.keygen = func() (*ecdsa.PrivateKey, error) { return nil, boom }
	if _, err := ca.leafFor("a.example.com"); !errors.Is(err, boom) {
		t.Fatalf("leaf keygen failure not surfaced: %v", err)
	}

	other, _, _, err := GenerateCA("")
	if err != nil {
		t.Fatal(err)
	}
	mismatched := &CA{cert: ca.cert, key: other.key, certDER: ca.certDER, nowFn: time.Now, keygen: defaultKeygen, cache: map[string]*leaf{}}
	if _, err := mismatched.leafFor("b.example.com"); err == nil {
		t.Fatal("a CA key that does not match its certificate must fail to sign")
	}
}

func TestLeafFor_ChainVerifiesAndCaches(t *testing.T) {
	ca, _, _, err := GenerateCA("")
	if err != nil {
		t.Fatal(err)
	}
	tc, err := ca.leafFor("api.provider.example")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	// The leaf must chain to the CA and be valid for the host.
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := tc.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "api.provider.example",
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
	// A second mint for the same host returns the cached cert.
	tc2, _ := ca.leafFor("api.provider.example")
	if tc2.Leaf.SerialNumber.Cmp(tc.Leaf.SerialNumber) != 0 {
		t.Fatal("expected cached leaf on second call")
	}
	// Expiry forces a re-mint.
	ca.nowFn = func() time.Time { return time.Now().Add(leafTTL + time.Hour) }
	tc3, _ := ca.leafFor("api.provider.example")
	if tc3.Leaf.SerialNumber.Cmp(tc.Leaf.SerialNumber) == 0 {
		t.Fatal("expected fresh leaf after expiry")
	}
}

// A principal cycling many distinct SNIs (e.g. under a wildcard credential)
// must not grow the leaf cache without bound: minting more distinct hosts than
// the cap leaves the cache at or below the cap rather than climbing forever.
func TestLeafFor_CacheBounded(t *testing.T) {
	ca, _, _, err := GenerateCA("")
	if err != nil {
		t.Fatal(err)
	}
	ca.maxEntries = 4
	for i := range 40 {
		if _, err := ca.leafFor(fmt.Sprintf("h%d.example.com", i)); err != nil {
			t.Fatalf("leafFor: %v", err)
		}
	}
	if got := len(ca.cache); got > ca.maxEntries {
		t.Fatalf("cache grew unbounded: %d entries, cap %d", got, ca.maxEntries)
	}
}

// Expired entries are evicted, not merely overwritten on re-request: advancing
// the clock past every cached leaf's expiry and minting one new host leaves only
// live entries behind.
func TestLeafFor_EvictsExpired(t *testing.T) {
	ca, _, _, err := GenerateCA("")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	ca.nowFn = func() time.Time { return base }
	for i := range 3 {
		if _, err := ca.leafFor(fmt.Sprintf("h%d.example.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	// Jump past the cached leaves' TTL, then mint a fresh host: the three stale
	// entries are dropped, leaving only the new one.
	ca.nowFn = func() time.Time { return base.Add(leafTTL + time.Hour) }
	if _, err := ca.leafFor("fresh.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := len(ca.cache); got != 1 {
		t.Fatalf("expected only the fresh entry, got %d", got)
	}
}

// A concurrent mint that lands a still-valid entry while another mint for the
// same host is in flight is reused rather than churned.
func TestLeafFor_ConcurrentMintReusesFirst(t *testing.T) {
	ca, _, _, err := GenerateCA("")
	if err != nil {
		t.Fatal(err)
	}
	first, err := ca.leafFor("race.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Force the initial cache miss for the second call, then restore the entry
	// before the post-mint lock: the seam runs inside mintLeaf, between the two
	// locked sections.
	entry := ca.cache["race.example.com"]
	delete(ca.cache, "race.example.com")
	ca.keygen = func() (*ecdsa.PrivateKey, error) {
		ca.mu.Lock()
		ca.cache["race.example.com"] = entry
		ca.mu.Unlock()
		return defaultKeygen()
	}
	second, err := ca.leafFor("race.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) != 0 {
		t.Fatal("expected the concurrently minted entry to be reused")
	}
}

func TestLeafFor_IPHost(t *testing.T) {
	ca, _, _, _ := GenerateCA("")
	tc, err := ca.leafFor("127.0.0.1")
	if err != nil {
		t.Fatalf("leafFor ip: %v", err)
	}
	if len(tc.Leaf.IPAddresses) != 1 || tc.Leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("expected IP SAN, got %+v", tc.Leaf.IPAddresses)
	}
}
