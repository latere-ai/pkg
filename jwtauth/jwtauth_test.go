package jwtauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Test helpers ────────────────────────────────────────────────────────────

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rsaKid(pub *rsa.PublicKey) string {
	h := sha256.Sum256(pub.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(h[:])[:8]
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func signToken(t *testing.T, key *rsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	h := b64(header)
	p := b64(payload)
	input := h + "." + p
	digest := hashSHA256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwksJSON(t *testing.T, keys ...*rsa.PrivateKey) []byte {
	t.Helper()
	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	var out struct {
		Keys []jwk `json:"keys"`
	}
	for _, k := range keys {
		out.Keys = append(out.Keys, jwk{
			Kty: "RSA",
			Kid: rsaKid(&k.PublicKey),
			Alg: "RS256",
			Use: "sig",
			N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		})
	}
	b, _ := json.Marshal(out)
	return b
}

func serveJWKS(t *testing.T, keys ...*rsa.PrivateKey) *httptest.Server {
	t.Helper()
	data := jwksJSON(t, keys...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(data); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testValidator(t *testing.T, key *rsa.PrivateKey, opts ...func(*Config)) *Validator {
	t.Helper()
	srv := serveJWKS(t, key)
	cfg := Config{JWKSURL: srv.URL, CacheTTL: time.Hour}
	for _, o := range opts {
		o(&cfg)
	}
	return New(cfg)
}

func defaultHeader(key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": rsaKid(&key.PublicKey),
	}
}

func defaultPayload() map[string]any {
	return map[string]any{
		"sub":            "user-123",
		"iss":            "https://auth.latere.ai",
		"aud":            "my-client",
		"exp":            float64(time.Now().Add(time.Hour).Unix()),
		"iat":            float64(time.Now().Unix()),
		"principal_type": "user",
		"email":          "test@example.com",
		"org_id":         "org-456",
		"is_superadmin":  false,
		"scp":            []string{"read:projects", "write:projects"},
		"roles":          []string{"editor"},
	}
}

// ── Validate tests ──────────────────────────────────────────────────────────

func TestValidateUserToken(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	token := signToken(t, key, defaultHeader(key), defaultPayload())

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Sub != "user-123" {
		t.Errorf("Sub = %q, want user-123", claims.Sub)
	}
	if claims.PrincipalType != PrincipalUser {
		t.Errorf("PrincipalType = %q, want user", claims.PrincipalType)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("Email = %q, want test@example.com", claims.Email)
	}
	if claims.OrgID != "org-456" {
		t.Errorf("OrgID = %q, want org-456", claims.OrgID)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "read:projects" {
		t.Errorf("Scopes = %v, want [read:projects write:projects]", claims.Scopes)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "editor" {
		t.Errorf("Roles = %v, want [editor]", claims.Roles)
	}
	if claims.Iss != "https://auth.latere.ai" {
		t.Errorf("Iss = %q", claims.Iss)
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != "my-client" {
		t.Errorf("Aud = %v", claims.Aud)
	}
}

func TestValidateUsesConfiguredHTTPClient(t *testing.T) {
	key := genKey(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, key))
	}))
	t.Cleanup(srv.Close)
	v := New(Config{JWKSURL: srv.URL, HTTPClient: srv.Client()})
	token := signToken(t, key, defaultHeader(key), defaultPayload())
	if _, err := v.Validate(token); err != nil {
		t.Fatalf("Validate with configured TLS client: %v", err)
	}
}

func TestValidateServiceToken(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	payload := defaultPayload()
	payload["principal_type"] = "service"
	delete(payload, "email")
	token := signToken(t, key, defaultHeader(key), payload)

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.PrincipalType != PrincipalService {
		t.Errorf("PrincipalType = %q, want service", claims.PrincipalType)
	}
}
func TestValidateExpiredToken(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	payload := defaultPayload()
	payload["exp"] = float64(time.Now().Add(-time.Hour).Unix())
	token := signToken(t, key, defaultHeader(key), payload)

	_, err := v.Validate(token)
	if err != ErrTokenExpired {
		t.Errorf("err = %v, want ErrTokenExpired", err)
	}
}

func TestValidateNotYetValidToken(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	payload := defaultPayload()
	payload["nbf"] = float64(time.Now().Add(time.Hour).Unix())
	token := signToken(t, key, defaultHeader(key), payload)

	_, err := v.Validate(token)
	if err != ErrTokenNotValidYet {
		t.Errorf("err = %v, want ErrTokenNotValidYet", err)
	}
}

func TestValidatePastNbfAccepted(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	payload := defaultPayload()
	payload["nbf"] = float64(time.Now().Add(-time.Hour).Unix())
	token := signToken(t, key, defaultHeader(key), payload)

	if _, err := v.Validate(token); err != nil {
		t.Errorf("past-nbf token rejected: %v", err)
	}
}

func TestValidateInvalidSignature(t *testing.T) {
	key := genKey(t)
	wrongKey := genKey(t)
	v := testValidator(t, key)
	token := signToken(t, wrongKey, defaultHeader(wrongKey), defaultPayload())

	_, err := v.Validate(token)
	if err != ErrInvalidSignature {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestValidateMalformedToken(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)

	cases := []string{
		"",
		"one.two",
		"one.two.three.four",
		"!!!.!!!.!!!",
	}
	for _, tc := range cases {
		_, err := v.Validate(tc)
		if err != ErrMalformedToken {
			t.Errorf("Validate(%q) = %v, want ErrMalformedToken", tc, err)
		}
	}
}

func TestValidateBadBase64Payload(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)

	header := b64(defaultHeader(key))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake"))
	token := header + ".!!invalid!!." + sig

	_, err := v.Validate(token)
	// The signature check runs before payload decode, so this is either
	// ErrMalformedToken (bad base64 in sig input) or ErrInvalidSignature.
	if err != ErrMalformedToken && err != ErrInvalidSignature {
		t.Errorf("err = %v, want ErrMalformedToken or ErrInvalidSignature", err)
	}
}

func TestValidateUnsupportedAlgorithm(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	token := signToken(t, key, header, defaultPayload())

	_, err := v.Validate(token)
	if err != ErrUnsupportedAlg {
		t.Errorf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestValidateIssuerMismatch(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key, func(c *Config) {
		c.Issuer = "https://auth.latere.ai"
	})
	payload := defaultPayload()
	payload["iss"] = "https://evil.example.com"
	token := signToken(t, key, defaultHeader(key), payload)

	_, err := v.Validate(token)
	if err != ErrInvalidIssuer {
		t.Errorf("err = %v, want ErrInvalidIssuer", err)
	}
}

func TestValidateIssuerSkippedWhenEmpty(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key) // no Issuer set
	payload := defaultPayload()
	payload["iss"] = "anything"
	token := signToken(t, key, defaultHeader(key), payload)

	_, err := v.Validate(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAudienceMismatch(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key, func(c *Config) {
		c.Audiences = []string{"expected-client"}
	})
	payload := defaultPayload()
	payload["aud"] = "wrong-client"
	token := signToken(t, key, defaultHeader(key), payload)

	_, err := v.Validate(token)
	if err != ErrInvalidAudience {
		t.Errorf("err = %v, want ErrInvalidAudience", err)
	}
}

func TestValidateAudienceArray(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key, func(c *Config) {
		c.Audiences = []string{"client-b"}
	})
	payload := defaultPayload()
	payload["aud"] = []string{"client-a", "client-b"}
	token := signToken(t, key, defaultHeader(key), payload)

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(claims.Aud) != 2 {
		t.Errorf("Aud = %v, want 2 entries", claims.Aud)
	}
}

func TestValidateAudienceSkippedWhenEmpty(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key) // no Audiences set
	token := signToken(t, key, defaultHeader(key), defaultPayload())

	_, err := v.Validate(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMissingSub(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	payload := defaultPayload()
	delete(payload, "sub")
	token := signToken(t, key, defaultHeader(key), payload)

	_, err := v.Validate(token)
	if err != ErrMalformedToken {
		t.Errorf("err = %v, want ErrMalformedToken", err)
	}
}

func TestValidateWithoutKid(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	token := signToken(t, key, header, defaultPayload())

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Sub != "user-123" {
		t.Errorf("Sub = %q", claims.Sub)
	}
}

func TestValidateSuperadmin(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	payload := defaultPayload()
	payload["is_superadmin"] = true
	token := signToken(t, key, defaultHeader(key), payload)

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claims.IsSuperadmin {
		t.Error("IsSuperadmin should be true")
	}
}

// ── JWKS Cache tests ────────────────────────────────────────────────────────

func TestJWKSCacheRespectsTTL(t *testing.T) {
	key := genKey(t)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if _, err := w.Write(jwksJSON(t, key)); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	cache := &jwksCache{url: srv.URL, ttl: time.Hour}
	if _, err := cache.getKeys(); err != nil {
		t.Fatalf("getKeys: %v", err)
	}
	if _, err := cache.getKeys(); err != nil {
		t.Fatalf("getKeys: %v", err)
	}
	if _, err := cache.getKeys(); err != nil {
		t.Fatalf("getKeys: %v", err)
	}

	if calls != 1 {
		t.Errorf("expected 1 JWKS fetch, got %d", calls)
	}
}

func TestJWKSCacheRefetchesAfterTTL(t *testing.T) {
	key := genKey(t)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if _, err := w.Write(jwksJSON(t, key)); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	now := time.Now()
	orig := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = orig })

	cache := &jwksCache{url: srv.URL, ttl: time.Minute}
	if _, err := cache.getKeys(); err != nil {
		t.Fatalf("getKeys: %v", err)
	}

	// Advance past TTL.
	now = now.Add(2 * time.Minute)
	if _, err := cache.getKeys(); err != nil {
		t.Fatalf("getKeys: %v", err)
	}

	if calls != 2 {
		t.Errorf("expected 2 JWKS fetches, got %d", calls)
	}
}

func TestJWKSCacheStaleOnError(t *testing.T) {
	key := genKey(t)
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if first {
			first = false
			if _, err := w.Write(jwksJSON(t, key)); err != nil {
				t.Errorf("write JWKS response: %v", err)
			}
			return
		}
		http.Error(w, "fail", 500)
	}))
	t.Cleanup(srv.Close)

	now := time.Now()
	orig := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = orig })

	cache := &jwksCache{url: srv.URL, ttl: time.Second}
	keys, err := cache.getKeys()
	if err != nil || len(keys) == 0 {
		t.Fatal("first fetch should succeed")
	}

	// Advance past TTL so cache re-fetches, but server errors.
	now = now.Add(time.Minute)
	keys, err = cache.getKeys()
	if err != nil || len(keys) == 0 {
		t.Error("should return stale keys on error")
	}
}

func TestJWKSCacheEmptyKeysServesStale(t *testing.T) {
	// A 200 whose key set yields no usable RSA keys after a prior successful
	// fetch must keep serving the cached key and must not advance cachedAt
	// (so the next request retries rather than caching the empty result).
	key := genKey(t)
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if first {
			first = false
			if _, err := w.Write(jwksJSON(t, key)); err != nil {
				t.Errorf("write JWKS response: %v", err)
			}
			return
		}
		if _, err := w.Write([]byte(`{"keys":[]}`)); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	now := time.Now()
	orig := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = orig })

	cache := &jwksCache{url: srv.URL, ttl: time.Second}
	if keys, err := cache.getKeys(); err != nil || len(keys) == 0 {
		t.Fatal("first fetch should succeed")
	}
	cachedAt := cache.cachedAt

	now = now.Add(time.Minute) // expire TTL so the empty response is fetched
	keys, err := cache.getKeys()
	if err != nil || len(keys) == 0 {
		t.Errorf("should serve stale key on empty JWKS, got keys=%d err=%v", len(keys), err)
	}
	if cache.cachedAt != cachedAt {
		t.Errorf("cachedAt advanced on empty JWKS: %v -> %v", cachedAt, cache.cachedAt)
	}
}

func TestJWKSCacheCachedReadNotBlockedByInflightFetch(t *testing.T) {
	// A forced refetch (kid miss) must not stall concurrent validations whose
	// key is already cached: the blocking JWKS round-trip runs without c.mu
	// held, so a fresh-cache read returns immediately instead of queuing behind
	// the network call. With the old single-lock design this read deadlocked
	// behind the in-flight fetch and timed out.
	keyA := genKey(t)
	release := make(chan struct{})
	var once sync.Once
	started := make(chan struct{})
	var mu sync.Mutex
	reqs := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs++
		cur := reqs
		mu.Unlock()
		if cur >= 2 { // the forced refetch: signal, then block until released
			once.Do(func() { close(started) })
			<-release
		}
		if _, err := w.Write(jwksJSON(t, keyA)); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	cache := &jwksCache{url: srv.URL, ttl: time.Hour}
	if keys, err := cache.getKeys(); err != nil || len(keys) == 0 {
		t.Fatal("prime fetch should succeed")
	}

	fetchDone := make(chan struct{})
	go func() {
		// The kid is absent by construction, so the error is the expected
		// outcome. The call is here for the forced refetch it triggers, which
		// blocks in the handler until release.
		_, _ = cache.getKeysForKid("absent-kid")
		close(fetchDone)
	}()
	<-started // the forced fetch is now blocked mid-round-trip

	read := make(chan struct{})
	go func() {
		// Fresh cache: the assertion is that this returns without waiting on
		// the in-flight fetch, not what it returns.
		_, _ = cache.getKeys()
		close(read)
	}()
	select {
	case <-read:
	case <-time.After(2 * time.Second):
		t.Error("cached read blocked behind in-flight JWKS fetch")
	}

	close(release)
	<-fetchDone
}

func TestJWKSCacheErrorNoStale(t *testing.T) {
	orig := httpGet
	httpGet = func(url string) (*http.Response, error) {
		return nil, fmt.Errorf("network error")
	}
	t.Cleanup(func() { httpGet = orig })

	cache := &jwksCache{url: "http://unreachable", ttl: time.Minute}
	_, err := cache.getKeys()
	if err == nil {
		t.Error("expected error with no stale cache")
	}
}

func TestJWKSCacheNon2xxStatus(t *testing.T) {
	// A non-2xx response with a JSON-shaped body (e.g. {"keys":[]}) must not
	// be parsed as a successful empty key set; with no cache it errors.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte(`{"keys":[]}`)); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	cache := &jwksCache{url: srv.URL, ttl: time.Hour}
	if _, err := cache.getKeys(); err == nil {
		t.Error("expected error on non-2xx JWKS status with no cache")
	}
}

func TestJWKSCacheNon2xxStatusServesStale(t *testing.T) {
	key := genKey(t)
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if first {
			first = false
			if _, err := w.Write(jwksJSON(t, key)); err != nil {
				t.Errorf("write JWKS response: %v", err)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte(`{"keys":[]}`)); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	now := time.Now()
	orig := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = orig })

	cache := &jwksCache{url: srv.URL, ttl: time.Second}
	if keys, err := cache.getKeys(); err != nil || len(keys) == 0 {
		t.Fatal("first fetch should succeed")
	}
	now = now.Add(time.Minute) // expire TTL → refetch hits the 503
	if keys, err := cache.getKeys(); err != nil || len(keys) == 0 {
		t.Error("should return stale keys on non-2xx status")
	}
}

func TestValidateForcesRefreshOnKidMiss(t *testing.T) {
	key1 := genKey(t)
	key2 := genKey(t)
	var mu sync.Mutex
	current := key1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		k := current
		mu.Unlock()
		if _, err := w.Write(jwksJSON(t, k)); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	v := New(Config{JWKSURL: srv.URL, CacheTTL: time.Hour})
	// Warm the cache with key1.
	if _, err := v.Validate(signToken(t, key1, defaultHeader(key1), defaultPayload())); err != nil {
		t.Fatalf("key1 token: %v", err)
	}
	// Rotate to key2 (new kid) while the cache is still well within its TTL.
	mu.Lock()
	current = key2
	mu.Unlock()
	// The new kid is absent from the warm cache; validation must force a
	// refetch rather than failing for up to CacheTTL.
	if _, err := v.Validate(signToken(t, key2, defaultHeader(key2), defaultPayload())); err != nil {
		t.Fatalf("rotated key2 token should validate via forced refresh: %v", err)
	}
}

func TestValidateConcurrentKidMiss(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	hdr := defaultHeader(key)
	hdr["kid"] = "absent-kid" // never present in the served JWKS
	tok := signToken(t, key, hdr, defaultPayload())

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_, _ = v.Validate(tok)
		})
	}
	wg.Wait()
}

func TestJWKSCacheSkipsNonRSA(t *testing.T) {
	data := `{"keys":[{"kty":"EC","kid":"ec1","alg":"ES256","use":"sig","crv":"P-256","x":"abc","y":"def"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(data)); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	cache := &jwksCache{url: srv.URL, ttl: time.Hour}
	keys, _ := cache.getKeys()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestJWKSCacheMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("not json")); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	cache := &jwksCache{url: srv.URL, ttl: time.Hour}
	_, err := cache.getKeys()
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestJWKSCacheMultipleKeys(t *testing.T) {
	key1 := genKey(t)
	key2 := genKey(t)
	srv := serveJWKS(t, key1, key2)

	cache := &jwksCache{url: srv.URL, ttl: time.Hour}
	keys, err := cache.getKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

// ── Middleware tests ─────────────────────────────────────────────────────────

func TestMiddlewareSuccess(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	token := signToken(t, key, defaultHeader(key), defaultPayload())

	var got *Claims
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if got == nil || got.Sub != "user-123" {
		t.Errorf("claims = %v", got)
	}
}

func TestMiddlewareMissingToken(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)

	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestMiddlewareInvalidToken(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)

	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestClaimsFromContextNil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if c := ClaimsFromContext(req.Context()); c != nil {
		t.Error("expected nil claims")
	}
}

func TestJsonAudString(t *testing.T) {
	var a jsonAud
	if err := json.Unmarshal([]byte(`"single"`), &a); err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || a[0] != "single" {
		t.Errorf("got %v", a)
	}
}

func TestJsonAudArray(t *testing.T) {
	var a jsonAud
	if err := json.Unmarshal([]byte(`["a","b"]`), &a); err != nil {
		t.Fatal(err)
	}
	if len(a) != 2 || a[0] != "a" || a[1] != "b" {
		t.Errorf("got %v", a)
	}
}

func TestJsonAudInvalid(t *testing.T) {
	var a jsonAud
	if err := json.Unmarshal([]byte(`123`), &a); err == nil {
		t.Error("expected error for invalid aud type")
	}
}

// ── audMatch tests ──────────────────────────────────────────────────────────

func TestAudMatch(t *testing.T) {
	if !audMatch(jsonAud{"a", "b"}, []string{"b"}) {
		t.Error("should match")
	}
	if audMatch(jsonAud{"a"}, []string{"b"}) {
		t.Error("should not match")
	}
	if audMatch(jsonAud{}, []string{"b"}) {
		t.Error("empty aud should not match")
	}
}

// ── parseRSAPublicKey tests ─────────────────────────────────────────────────

func TestParseRSAPublicKeyInvalidN(t *testing.T) {
	_, err := parseRSAPublicKey("!!!", "AQAB")
	if err == nil {
		t.Error("expected error for invalid N")
	}
}

func TestParseRSAPublicKeyInvalidE(t *testing.T) {
	_, err := parseRSAPublicKey("AQAB", "!!!")
	if err == nil {
		t.Error("expected error for invalid E")
	}
}

// ── writeError test ─────────────────────────────────────────────────────────

func TestWriteUnauthorized(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteUnauthorized(rr, "test message")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("WriteUnauthorized must emit JSON: %v", err)
	}
	if body["message"] != "test message" {
		t.Errorf("body = %v", body)
	}
}

// ── Config defaults test ────────────────────────────────────────────────────

func TestNewDefaultCacheTTL(t *testing.T) {
	v := New(Config{JWKSURL: "http://example.com"})
	if v.cfg.CacheTTL != 5*time.Minute {
		t.Errorf("CacheTTL = %v, want 5m", v.cfg.CacheTTL)
	}
}

func TestNewCustomCacheTTL(t *testing.T) {
	v := New(Config{JWKSURL: "http://example.com", CacheTTL: time.Hour})
	if v.cfg.CacheTTL != time.Hour {
		t.Errorf("CacheTTL = %v, want 1h", v.cfg.CacheTTL)
	}
}

// ── Bad signature encoding ──────────────────────────────────────────────────

func TestValidateBadSignatureEncoding(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	header := b64(defaultHeader(key))
	payload := b64(defaultPayload())
	token := header + "." + payload + ".!!invalid-base64!!"

	_, err := v.Validate(token)
	if err != ErrMalformedToken {
		t.Errorf("err = %v, want ErrMalformedToken", err)
	}
}

// ── Bad header encoding ─────────────────────────────────────────────────────

func TestValidateBadHeaderEncoding(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	token := "!!invalid!!." + b64(defaultPayload()) + ".fakesig"

	_, err := v.Validate(token)
	if err != ErrMalformedToken {
		t.Errorf("err = %v, want ErrMalformedToken", err)
	}
}

func TestValidateBadHeaderJSON(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)
	badHeader := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	token := badHeader + "." + b64(defaultPayload()) + ".fakesig"

	_, err := v.Validate(token)
	if err != ErrMalformedToken {
		t.Errorf("err = %v, want ErrMalformedToken", err)
	}
}

// ── Additional coverage tests ───────────────────────────────────────────────

func TestValidateJWKSFetchError(t *testing.T) {
	orig := httpGet
	httpGet = func(url string) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	}
	t.Cleanup(func() { httpGet = orig })

	v := New(Config{JWKSURL: "http://unreachable"})
	key := genKey(t)
	token := signToken(t, key, defaultHeader(key), defaultPayload())

	_, err := v.Validate(token)
	if err == nil || !strings.Contains(err.Error(), "fetch JWKS") {
		t.Errorf("err = %v, want JWKS fetch error", err)
	}
}

func TestJWKSCacheStaleOnReadError(t *testing.T) {
	key := genKey(t)
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if first {
			first = false
			if _, err := w.Write(jwksJSON(t, key)); err != nil {
				t.Errorf("write JWKS response: %v", err)
			}
			return
		}
		// Write partial response then close to cause ReadAll error.
		w.Header().Set("Content-Length", "9999")
		if _, err := w.Write([]byte("{")); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
		// Closing the connection will cause io.ReadAll to get less than expected,
		// but it won't error. Use malformed JSON to trigger unmarshal error with stale.
		if _, err := w.Write([]byte("not json")); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	now := time.Now()
	orig := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = orig })

	cache := &jwksCache{url: srv.URL, ttl: time.Second}
	keys, err := cache.getKeys()
	if err != nil || len(keys) == 0 {
		t.Fatal("first fetch should succeed")
	}

	// Advance past TTL, server returns bad JSON.
	now = now.Add(time.Minute)
	keys, err = cache.getKeys()
	if err != nil || len(keys) == 0 {
		t.Error("should return stale keys on JSON error")
	}
}

func TestJWKSCacheBadKeyValues(t *testing.T) {
	// JWKS with RSA key that has bad base64 in N field.
	data := `{"keys":[{"kty":"RSA","kid":"bad","alg":"RS256","use":"sig","n":"!!!","e":"AQAB"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(data)); err != nil {
			t.Errorf("write JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	cache := &jwksCache{url: srv.URL, ttl: time.Hour}
	keys, _ := cache.getKeys()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for bad key data, got %d", len(keys))
	}
}

// ── Fuzz tests ──────────────────────────────────────────────────────────────

func FuzzValidate(f *testing.F) {
	f.Add("a.b.c")
	f.Add("")
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid")
	f.Fuzz(func(t *testing.T, token string) {
		key := genKey(t)
		v := testValidator(t, key)
		_, _ = v.Validate(token) // must not panic
	})
}

func FuzzParseJWKS(f *testing.F) {
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := w.Write(data); err != nil {
				t.Errorf("write JWKS response: %v", err)
			}
		}))
		defer srv.Close()
		cache := &jwksCache{url: srv.URL, ttl: time.Hour}
		_, _ = cache.getKeys() // must not panic
	})
}

func TestValidateActorClaims(t *testing.T) {
	key := genKey(t)
	v := testValidator(t, key)

	// A sandbox token carries a generic actor: kind + actor_id.
	p := defaultPayload()
	p["actor_id"] = "sb-abc123"
	p["kind"] = "sandbox"
	claims, err := v.Validate(signToken(t, key, defaultHeader(key), p))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.ActorID != "sb-abc123" {
		t.Errorf("ActorID = %q, want sb-abc123", claims.ActorID)
	}
	if claims.Kind != "sandbox" {
		t.Errorf("Kind = %q, want sandbox", claims.Kind)
	}

	// Ordinary token: both empty (back-compat).
	claims2, err := v.Validate(signToken(t, key, defaultHeader(key), defaultPayload()))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims2.ActorID != "" || claims2.Kind != "" {
		t.Errorf("non-actor token carried ActorID=%q Kind=%q, want empty", claims2.ActorID, claims2.Kind)
	}
}
