// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// leafTTL bounds how long a minted leaf cert is valid. Leaves are minted per
// SNI on the fly and cached, so a short life keeps a cache poisoning / clock
// window small without hurting the hit rate for a live principal's traffic.
const leafTTL = 24 * time.Hour

// maxLeafCacheEntries bounds the per-SNI leaf cache. A wildcard credential makes
// every subdomain a distinct inspected host, so an unbounded cache would let one
// principal grow the gateway heap without limit by cycling random subdomains.
// When the cache is full, expired entries are dropped first, then the soonest-
// to-expire entry, before a fresh leaf is inserted.
const maxLeafCacheEntries = 1024

// DefaultCACommonName is the subject GenerateCA uses when none is given.
const DefaultCACommonName = "Egress CA"

// CA is the gateway's certificate authority. It signs a short-lived leaf
// certificate for each upstream SNI the gateway terminates TLS for; the
// workload trusts the CA (the control plane installs CertPEM into the
// workload's trust store), so the inner TLS handshake to the gateway
// validates. The CA private key never leaves the gateway process. Safe for
// concurrent use.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certDER []byte

	// nowFn is time.Now, overridable in tests.
	nowFn func() time.Time
	// maxEntries caps the leaf cache; 0 means maxLeafCacheEntries. Overridable
	// in tests to exercise eviction without minting thousands of leaves.
	maxEntries int

	mu    sync.Mutex
	cache map[string]*leaf
}

// cacheCap returns the effective leaf-cache capacity.
func (c *CA) cacheCap() int {
	if c.maxEntries > 0 {
		return c.maxEntries
	}
	return maxLeafCacheEntries
}

type leaf struct {
	cert    tlsCertificate
	expires time.Time
}

// tlsCertificate mirrors the tls.Certificate shape the proxy needs without
// importing crypto/tls here (the proxy layer builds the tls.Certificate).
// Keeping ca.go tls-free keeps it trivially unit-testable.
type tlsCertificate struct {
	Certificate [][]byte // leaf DER, then CA DER
	PrivateKey  *ecdsa.PrivateKey
	Leaf        *x509.Certificate
}

// Seams over the crypto primitives so their failure paths are testable.
var (
	generateKey       = ecdsa.GenerateKey
	createCertificate = x509.CreateCertificate
	marshalECKey      = x509.MarshalECPrivateKey
)

// GenerateCA mints a fresh self-signed egress CA whose subject common name is
// commonName ([DefaultCACommonName] when empty). Returns the CA plus its
// PEM-encoded cert and key so an operator (or a test) can persist them. In
// production the CA is generated once and loaded via LoadCA.
func GenerateCA(commonName string) (ca *CA, certPEM, keyPEM []byte, err error) {
	if commonName == "" {
		commonName = DefaultCACommonName
	}
	key, err := generateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := createCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := marshalECKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &CA{cert: cert, key: key, certDER: der, nowFn: time.Now, cache: map[string]*leaf{}}, certPEM, keyPEM, nil
}

// LoadCA reconstructs a CA from a PEM cert + PEM EC private key (the operator
// secret).
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cBlock, _ := pem.Decode(certPEM)
	if cBlock == nil || cBlock.Type != "CERTIFICATE" {
		return nil, errors.New("egress: CA cert PEM invalid")
	}
	cert, err := x509.ParseCertificate(cBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("egress: parse CA cert: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("egress: CA cert is not a CA")
	}
	kBlock, _ := pem.Decode(keyPEM)
	if kBlock == nil {
		return nil, errors.New("egress: CA key PEM invalid")
	}
	key, err := x509.ParseECPrivateKey(kBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("egress: parse CA key: %w", err)
	}
	return &CA{cert: cert, key: key, certDER: cBlock.Bytes, nowFn: time.Now, cache: map[string]*leaf{}}, nil
}

// CertPEM returns the CA certificate PEM to install in the workload trust store.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certDER})
}

// leafFor mints (or returns a cached) leaf certificate for host, signed by the
// CA, valid for leafTTL. The returned tlsCertificate chains leaf → CA so the
// workload validates against the installed CA. The mutex is held only for the
// cache read and write; the keygen+sign happens unlocked so a slow mint does not
// serialize every other principal's inspected handshake.
func (c *CA) leafFor(host string) (tlsCertificate, error) {
	now := c.nowFn()
	c.mu.Lock()
	if l, ok := c.cache[host]; ok && now.Before(l.expires) {
		cert := l.cert
		c.mu.Unlock()
		return cert, nil
	}
	c.mu.Unlock()

	tc, err := c.mintLeaf(host, now)
	if err != nil {
		return tlsCertificate{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// A concurrent mint for the same host may have landed a still-valid entry
	// while we were minting; reuse it and drop ours (both are equally valid) to
	// avoid churning the cache.
	if l, ok := c.cache[host]; ok && now.Before(l.expires) {
		return l.cert, nil
	}
	c.evictLocked(now)
	c.cache[host] = &leaf{cert: tc, expires: now.Add(leafTTL)}
	return tc, nil
}

// mintLeaf signs a fresh leaf for host valid for leafTTL. It touches no shared
// state, so callers invoke it without holding c.mu.
func (c *CA) mintLeaf(host string, now time.Time) (tlsCertificate, error) {
	key, err := generateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsCertificate{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return tlsCertificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// A CONNECT target may be a hostname or an IP literal; certificate SAN
	// matching requires IPs in IPAddresses and hostnames in DNSNames.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := createCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tlsCertificate{}, err
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return tlsCertificate{}, err
	}
	return tlsCertificate{
		Certificate: [][]byte{der, c.certDER},
		PrivateKey:  key,
		Leaf:        leafCert,
	}, nil
}

// evictLocked bounds the cache before an insert: it drops expired entries first,
// then, while still at capacity, evicts the soonest-to-expire (oldest) entry.
// Callers hold c.mu.
func (c *CA) evictLocked(now time.Time) {
	for h, l := range c.cache {
		if !now.Before(l.expires) {
			delete(c.cache, h)
		}
	}
	for len(c.cache) >= c.cacheCap() {
		var oldestHost string
		var oldest time.Time
		first := true
		for h, l := range c.cache {
			if first || l.expires.Before(oldest) {
				oldestHost, oldest, first = h, l.expires, false
			}
		}
		delete(c.cache, oldestHost)
	}
}

// randSerial draws a 128-bit certificate serial. It reads through randRead so
// an entropy failure is reachable in tests.
func randSerial() (*big.Int, error) {
	buf := make([]byte, 16)
	if _, err := randRead(buf); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(buf), nil
}
