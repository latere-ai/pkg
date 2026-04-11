// Package jwtauth provides JWKS-based RS256 JWT validation for services
// that accept tokens issued by the Latere auth service.
//
// # Design
//
// The auth service issues RS256 JWTs with claims that vary by principal type.
// Downstream services (FS, API, etc.) validate these tokens locally using the
// public keys published at the auth service's JWKS endpoint, without any
// round-trip to the auth service.
//
// # Principal types and validation strategies
//
// Every token carries a "principal_type" claim that identifies the subject:
//
//   - "user"    — a human user authenticated via OIDC. Local JWT validation
//     is always sufficient.
//   - "service" — a service account using client_credentials. Local JWT
//     validation is always sufficient.
//   - "agent"   — an AI agent acting on behalf of a delegator (RFC 8693
//     token exchange). Agent tokens carry a "validation" claim:
//   - "local"  — read-only agent; local JWT validation is sufficient.
//   - "strict" — agent with write/delete/admin scopes; the downstream
//     service MUST call GET /tokeninfo on EVERY request to verify
//     that the delegation has not been revoked or expired.
//
// Use [Claims.NeedsTokenInfo] to determine whether a token requires online
// validation. The /tokeninfo call itself is the caller's responsibility.
//
// # JWKS caching
//
// Public keys are fetched from the JWKS endpoint and cached for the duration
// specified by [Config.CacheTTL] (default 5 minutes). On fetch errors the
// validator falls back to stale cached keys, so transient auth-service
// outages do not break validation for already-seen keys.
//
// # Token claims
//
// The [Claims] struct is a superset of all principal types. Fields that do
// not apply to a given principal type are zero-valued:
//
//	Field          User   Service  Agent
//	─────          ────   ───────  ─────
//	Sub            ✓      ✓        ✓
//	PrincipalType  ✓      ✓        ✓
//	OrgID          ✓      ✓        ✓
//	Scopes         ✓      ✓        ✓       (JWT claim key: "scp")
//	Roles          ✓      ✓        ✓
//	Email          ✓
//	IsSuperadmin   ✓      ✓        ✓
//	Validation                      ✓       ("local" or "strict")
//	DelegationID                    ✓
//	Act                             ✓       (delegator identity)
//
// # Usage
//
//	v := jwtauth.New(jwtauth.Config{
//	    JWKSURL:   "https://auth.latere.ai/.well-known/jwks.json",
//	    Issuer:    "https://auth.latere.ai",        // optional
//	    Audiences: []string{"my-service-client-id"}, // optional
//	})
//
//	// As HTTP middleware:
//	mux.Handle("GET /api/resource", v.Middleware(handler))
//
//	// In a handler:
//	claims := jwtauth.ClaimsFromContext(r.Context())
//	if claims.NeedsTokenInfo() {
//	    // call auth service's GET /tokeninfo before proceeding
//	}
package jwtauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── Principal & Validation Types ────────────────────────────────────────────

// PrincipalType is the type of the token subject.
type PrincipalType string

const (
	PrincipalUser    PrincipalType = "user"
	PrincipalService PrincipalType = "service"
	PrincipalAgent   PrincipalType = "agent"
)

// ValidationStrategy indicates how an agent token must be validated.
type ValidationStrategy string

const (
	ValidationLocal  ValidationStrategy = "local"
	ValidationStrict ValidationStrategy = "strict"
)

// ── Claims ──────────────────────────────────────────────────────────────────

// Claims holds verified JWT claims across all principal types.
type Claims struct {
	Sub           string
	Iss           string
	Aud           []string
	Exp           time.Time
	PrincipalType PrincipalType
	OrgID         string
	Email         string // populated for users
	IsSuperadmin  bool
	Scopes        []string
	Roles         []string

	// Agent-only.
	Validation   ValidationStrategy // "local" or "strict"; empty for non-agents
	DelegationID string
	Act          *ActClaims // delegator identity (RFC 8693)
}

// ActClaims carries the RFC 8693 "act" delegator identity.
type ActClaims struct {
	Sub string
}

// NeedsTokenInfo returns true when the token requires online validation
// via the auth service's /tokeninfo endpoint.
func (c *Claims) NeedsTokenInfo() bool {
	return c.PrincipalType == PrincipalAgent && c.Validation == ValidationStrict
}

// ── Errors ──────────────────────────────────────────────────────────────────

var (
	ErrNoToken          = errors.New("jwtauth: missing bearer token")
	ErrMalformedToken   = errors.New("jwtauth: malformed token")
	ErrInvalidSignature = errors.New("jwtauth: invalid signature")
	ErrTokenExpired     = errors.New("jwtauth: token expired")
	ErrInvalidIssuer    = errors.New("jwtauth: invalid issuer")
	ErrInvalidAudience  = errors.New("jwtauth: invalid audience")
	ErrUnsupportedAlg   = errors.New("jwtauth: unsupported algorithm")
)

// ── Config & Validator ──────────────────────────────────────────────────────

// Config holds the settings for JWT validation.
type Config struct {
	// JWKSURL is the JWKS endpoint, e.g. "https://auth.latere.ai/.well-known/jwks.json".
	JWKSURL string
	// Issuer is the expected "iss" claim. Skipped if empty.
	Issuer string
	// Audiences is the set of acceptable "aud" values. Skipped if empty.
	Audiences []string
	// CacheTTL controls how long JWKS keys are cached. Defaults to 5 minutes.
	CacheTTL time.Duration
}

// Validator validates RS256 JWTs using keys fetched from a JWKS endpoint.
type Validator struct {
	cfg   Config
	cache *jwksCache
}

// New creates a Validator.
func New(cfg Config) *Validator {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	return &Validator{
		cfg:   cfg,
		cache: &jwksCache{url: cfg.JWKSURL, ttl: cfg.CacheTTL},
	}
}

// ── Package-level vars for testability ──────────────────────────────────────

var httpGet = func(url string) (*http.Response, error) {
	return http.Get(url) //nolint:gosec
}

var timeNow = time.Now

// ── Validate ────────────────────────────────────────────────────────────────

// Validate parses and validates a raw JWT string.
func (v *Validator) Validate(rawToken string) (*Claims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	// Decode header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrMalformedToken
	}
	if header.Alg != "RS256" {
		return nil, ErrUnsupportedAlg
	}

	// Verify signature.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformedToken
	}

	keys, err := v.cache.getKeys()
	if err != nil {
		return nil, fmt.Errorf("jwtauth: fetch JWKS: %w", err)
	}

	sigInput := parts[0] + "." + parts[1]
	digest := hashSHA256([]byte(sigInput))

	if !verifySignature(keys, header.Kid, digest, sig) {
		return nil, ErrInvalidSignature
	}

	// Decode payload.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var raw rawPayload
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return nil, ErrMalformedToken
	}

	// Validate exp.
	exp := time.Unix(int64(raw.Exp), 0)
	if timeNow().After(exp) {
		return nil, ErrTokenExpired
	}

	// Validate iss.
	if v.cfg.Issuer != "" && raw.Iss != v.cfg.Issuer {
		return nil, ErrInvalidIssuer
	}

	// Validate aud.
	if len(v.cfg.Audiences) > 0 {
		if !audMatch(raw.Aud, v.cfg.Audiences) {
			return nil, ErrInvalidAudience
		}
	}

	if raw.Sub == "" {
		return nil, ErrMalformedToken
	}

	claims := &Claims{
		Sub:           raw.Sub,
		Iss:           raw.Iss,
		Aud:           []string(raw.Aud),
		Exp:           exp,
		PrincipalType: PrincipalType(raw.PrincipalType),
		OrgID:         raw.OrgID,
		Email:         raw.Email,
		IsSuperadmin:  raw.IsSuperadmin,
		Scopes:        raw.Scopes,
		Roles:         raw.Roles,
		Validation:    ValidationStrategy(raw.Validation),
		DelegationID:  raw.DelegationID,
	}
	if raw.Act != nil {
		claims.Act = &ActClaims{Sub: raw.Act.Sub}
	}
	return claims, nil
}

// ── Middleware ───────────────────────────────────────────────────────────────

type ctxKey int

const ctxKeyClaims ctxKey = iota

// Middleware returns HTTP middleware that validates the JWT from the
// Authorization: Bearer header and injects Claims into the request context.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, ErrNoToken.Error())
			return
		}
		token := auth[7:]

		claims, err := v.Validate(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyClaims, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClaimsFromContext extracts validated Claims from the context.
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxKeyClaims).(*Claims)
	return c
}

// ── JWKS Cache ──────────────────────────────────────────────────────────────

type jwkEntry struct {
	kid string
	pub *rsa.PublicKey
}

type jwksCache struct {
	url      string
	ttl      time.Duration
	mu       sync.Mutex
	cachedAt time.Time
	keys     []jwkEntry
}

func (c *jwksCache) getKeys() ([]jwkEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if timeNow().Sub(c.cachedAt) < c.ttl && len(c.keys) > 0 {
		return c.keys, nil
	}

	resp, err := httpGet(c.url)
	if err != nil {
		if len(c.keys) > 0 {
			return c.keys, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if len(c.keys) > 0 {
			return c.keys, nil
		}
		return nil, err
	}

	var jwks struct {
		Keys []jwkRaw `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		if len(c.keys) > 0 {
			return c.keys, nil
		}
		return nil, err
	}

	var keys []jwkEntry
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys = append(keys, jwkEntry{kid: k.Kid, pub: pub})
	}

	if len(keys) > 0 {
		c.keys = keys
		c.cachedAt = timeNow()
	}

	return keys, nil
}

type jwkRaw struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func hashSHA256(data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	return h.Sum(nil)
}

func verifySignature(keys []jwkEntry, kid string, digest, sig []byte) bool {
	if kid != "" {
		for _, k := range keys {
			if k.kid == kid {
				return rsa.VerifyPKCS1v15(k.pub, crypto.SHA256, digest, sig) == nil
			}
		}
	}
	// Fallback: try all keys.
	for _, k := range keys {
		if rsa.VerifyPKCS1v15(k.pub, crypto.SHA256, digest, sig) == nil {
			return true
		}
	}
	return false
}

// rawPayload is the JWT payload as emitted by the auth service.
type rawPayload struct {
	Sub           string     `json:"sub"`
	Iss           string     `json:"iss"`
	Aud           jsonAud    `json:"aud"`
	Exp           float64    `json:"exp"`
	PrincipalType string     `json:"principal_type"`
	Email         string     `json:"email"`
	OrgID         string     `json:"org_id"`
	IsSuperadmin  bool       `json:"is_superadmin"`
	Scopes        []string   `json:"scp"`
	Roles         []string   `json:"roles"`
	Validation    string     `json:"validation"`
	DelegationID  string     `json:"delegation_id"`
	Act           *rawActSub `json:"act"`
}

type rawActSub struct {
	Sub string `json:"sub"`
}

// jsonAud handles the RFC 7519 "aud" claim which can be a string or []string.
type jsonAud []string

func (a *jsonAud) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = jsonAud{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*a = jsonAud(multi)
	return nil
}

func audMatch(tokenAud jsonAud, expected []string) bool {
	set := make(map[string]struct{}, len(expected))
	for _, a := range expected {
		set[a] = struct{}{}
	}
	for _, a := range tokenAud {
		if _, ok := set[a]; ok {
			return true
		}
	}
	return false
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized", "message": msg})
}
