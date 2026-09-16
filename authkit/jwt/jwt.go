// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package jwt verifies the JWTs the Latere auth service issues, using the
// keys it publishes at its JWKS endpoint. Verification is offline: no
// request path calls the auth service.
//
// # Algorithms
//
// Two signatures verify, the two the family's issuers sign with: RS256
// over an RSA key (JWKS kty RSA) and ES256 over a P-256 key (kty EC, crv
// P-256). The header's alg selects the key family: an RS256 token is
// checked against RSA keys alone and an ES256 token against P-256 keys
// alone, so a signature is never tried against a key of the other kind. A
// token whose alg is neither is [ErrUnsupportedAlg], and a key of any
// other type or curve in the set is skipped.
//
// # What a token names
//
// A principal is a user or a service, and the "principal_type" claim says
// which. Both verify the same way, so the type is a fact a handler may read,
// not a branch in this package. A verified token becomes a [Claims], which
// embeds authkit.Identity: the subject and its membership, plus the token
// envelope.
//
//	Claim               Field                  Note
//	─────               ─────                  ────
//	sub                 Sub                    the principal id; the only claim required
//	principal_type      PrincipalType          "user" or "service"
//	org_id              OrgID                  the active organisation
//	roles               Roles                  platform_admin, then the role names in that organisation
//	email               Email
//	client_id           ClientID               "azp" is the fallback
//	kind, actor_id      Kind, ActorID          a non-principal actor a token is bound to
//	preferred_username  PreferredUsername      the person's handle; absent until they claim one
//	org_slug, org_name  OrgSlug, OrgName       the slug and display name of org_id; absent with it
//	iss, aud, exp       Iss, Aud, Exp          the envelope
//
// An issuer that stamps only "sub" still verifies; the Identity that results
// carries the subject and nothing more. The three label claims are display
// only: they name the person and the active organisation so that a service
// can label a resource without calling the issuer, and the membership a
// service decides from stays "org_id" and "roles". Two claims are read by
// nothing: "scp" is the client's ceiling at the issuer and no service decides
// from it, and a token that carries a retired flag in place of a role confers
// nothing, so an admin route opens only to a token whose "roles" names
// platform_admin. A
// product whose own tokens carry scopes decodes them into its own type with
// [DecodePayload] after [Validator.Validate] has verified the token. [Config.Issuer] and [Config.Audiences]
// are checked when set, and a service should set both: a token minted for
// another relying party carries the same signature, and the audience is what
// refuses it here.
//
// # Authentication is local
//
// Nothing in this package calls the issuer while a request is served: the
// signature, the envelope and the claims decide, and a token's own expiry
// is its revocation window. The membership a service may read, org_id and
// roles, arrives in the token; anything finer is the service's own state.
//
// # JWKS caching
//
// Public keys are fetched from the JWKS endpoint and cached for
// [Config.CacheTTL] (default 5 minutes). On a fetch error the validator falls
// back to stale cached keys, so a transient auth-service outage does not break
// verification for a key already seen.
//
// # Usage
//
//	v := jwt.New(jwt.Config{
//	    JWKSURL:   "https://auth.latere.ai/.well-known/jwks.json",
//	    Issuer:    "https://auth.latere.ai",
//	    Audiences: []string{"my-service-client-id"},
//	})
//
//	// As HTTP middleware:
//	mux.Handle("GET /api/resource", v.Middleware(handler))
//
//	// In a handler:
//	claims := jwt.ClaimsFromContext(r.Context())
//	_ = claims.Sub
//
//	// As an authkit.Authenticator, composable in an authkit.Chain:
//	auth := jwt.NewAuthenticator(v)
package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"latere.ai/x/pkg/otel"

	"latere.ai/x/pkg/authkit"
	"latere.ai/x/pkg/bearer"
)

// ── Principal & Validation Types ────────────────────────────────────────────

// PrincipalType is the type of the token subject. It is authkit's type;
// the aliases keep existing references compiling.
type PrincipalType = authkit.PrincipalType

const (
	PrincipalUser    = authkit.PrincipalUser
	PrincipalService = authkit.PrincipalService
)

// ── Claims ──────────────────────────────────────────────────────────────────

// Claims is a verified token: the principal it names, as an
// authkit.Identity, plus the token envelope. Principal fields are promoted,
// so claims.Sub and claims.Identity.Sub are the same field. ClientID is the
// originating OAuth client ("client_id", "azp" fallback); Kind and ActorID
// from "kind" and "actor_id"; PreferredUsername, OrgSlug and OrgName from
// "preferred_username", "org_slug" and "org_name".
//
// Identity.TokenID and Identity.AuthMethod are not claims and are left zero
// here; Authenticator sets them.
type Claims struct {
	authkit.Identity
	Iss string
	Aud []string
	Exp time.Time
}

// ── Errors ──────────────────────────────────────────────────────────────────

// Reason is why a token was refused: one row of the reason table, and the
// string a core writes as the reason of its 401. The identifiers name the
// row; the values are the wire words, so a service that renders
// ReasonOf(err) renders the same word as every other service in the family.
type Reason string

// The rows of the reason table.
const (
	ReasonMalformed    Reason = "malformed"
	ReasonBadSignature Reason = "signature"
	ReasonBadIssuer    Reason = "issuer"
	ReasonBadAudience  Reason = "audience"
	ReasonExpired      Reason = "expired"
	ReasonNotYetValid  Reason = "nbf"
	ReasonTooLarge     Reason = "size"
	ReasonTooOld       Reason = "iat"
)

// Error is a refusal: the sentinel a caller matches with errors.Is and the
// table row it belongs to. Every error below is one, so ReasonOf answers for
// any of them; the sentinels are compared by identity, so a caller's
// errors.Is and the text of Error are what they always were.
type Error struct {
	Reason Reason
	msg    string
}

func (e *Error) Error() string { return e.msg }

// refusal declares one sentinel of the table.
func refusal(reason Reason, msg string) error { return &Error{Reason: reason, msg: msg} }

var (
	// ErrNoToken carries no reason: no token arrived, so nothing was refused.
	ErrNoToken          = errors.New("authkit/jwt: missing bearer token")
	ErrMalformedToken   = refusal(ReasonMalformed, "authkit/jwt: malformed token")
	ErrInvalidSignature = refusal(ReasonBadSignature, "authkit/jwt: invalid signature")
	ErrTokenExpired     = refusal(ReasonExpired, "authkit/jwt: token expired")
	ErrTokenNotValidYet = refusal(ReasonNotYetValid, "authkit/jwt: token not valid yet")
	ErrInvalidIssuer    = refusal(ReasonBadIssuer, "authkit/jwt: invalid issuer")
	ErrInvalidAudience  = refusal(ReasonBadAudience, "authkit/jwt: invalid audience")
	// ErrUnsupportedAlg is a signature refusal: the header names an algorithm
	// no key of the set can answer, which the caller learns as a signature
	// that did not check out. It is a row of its own only in Go.
	ErrUnsupportedAlg = refusal(ReasonBadSignature, "authkit/jwt: unsupported algorithm")
	ErrTokenTooLarge  = refusal(ReasonTooLarge, "authkit/jwt: token too large")
	ErrTokenTooOld    = refusal(ReasonTooOld, "authkit/jwt: token too old")
)

// ReasonOf reports the table row err belongs to, reading through any number
// of wraps. An error that is not a refusal, and a nil error, have no reason.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

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
	// HTTPClient fetches JWKS documents. Defaults to a client with a 10-second
	// timeout. Supply it for custom trust roots, proxies, or mTLS.
	HTTPClient *http.Client
	// MaxTokenBytes is the size above which a token is [ErrTokenTooLarge],
	// refused before it is parsed. Zero is [DefaultMaxTokenBytes]; a
	// negative value is no bound, for a caller whose tokens are larger.
	MaxTokenBytes int
	// MaxTokenAge is how old "iat" may be before the token is
	// [ErrTokenTooOld], whatever "exp" it carries. Zero is
	// [DefaultMaxTokenAge]; a negative value is no bound, and "exp" alone
	// decides. A token that carries no "iat" has no age and is unaffected
	// unless RequireIssuedAt is set.
	MaxTokenAge time.Duration
	// RequireIssuedAt refuses a token that carries no "iat" as
	// [ErrTokenTooOld]. Set it where every trusted issuer stamps one, so
	// that a token with no age cannot slip past MaxTokenAge. Off by
	// default: an issuer that stamps only "sub" still verifies.
	RequireIssuedAt bool
}

// DefaultMaxTokenBytes is the size bound a caller that configures none
// gets. A bearer token is a credential, not a document: 8 KiB is past
// every token the family's issuers mint and short of a payload worth
// parsing to reject.
const DefaultMaxTokenBytes = 8 << 10

// DefaultMaxTokenAge is the age bound a caller that configures none gets.
// It is a second ceiling under "exp": an issuer that mints a long-lived
// token does not thereby mint a credential that outlives the day it was
// issued in.
const DefaultMaxTokenAge = 24 * time.Hour

// Validator validates RS256 and ES256 JWTs using keys fetched from a JWKS
// endpoint.
type Validator struct {
	cfg   Config
	cache *jwksCache
}

// New creates a Validator.
func New(cfg Config) *Validator {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.MaxTokenBytes == 0 {
		cfg.MaxTokenBytes = DefaultMaxTokenBytes
	}
	if cfg.MaxTokenAge == 0 {
		cfg.MaxTokenAge = DefaultMaxTokenAge
	}
	cache := &jwksCache{url: cfg.JWKSURL, ttl: cfg.CacheTTL}
	if cfg.HTTPClient != nil {
		cache.get = cfg.HTTPClient.Get
	}
	return &Validator{
		cfg:   cfg,
		cache: cache,
	}
}

// ── Package-level vars for testability ──────────────────────────────────────

var httpGet = func(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 10 * time.Second, Transport: otel.Transport(nil)}
	return client.Get(url) //nolint:gosec
}

var timeNow = time.Now

// ── Validate ────────────────────────────────────────────────────────────────

// Validate parses and validates a raw JWT string.
func (v *Validator) Validate(rawToken string) (*Claims, error) {
	if v.cfg.MaxTokenBytes > 0 && len(rawToken) > v.cfg.MaxTokenBytes {
		return nil, ErrTokenTooLarge
	}

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
	if header.Alg != algRS256 && header.Alg != algES256 {
		return nil, ErrUnsupportedAlg
	}

	// Verify signature.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformedToken
	}

	keys, err := v.cache.getKeysForKid(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("authkit/jwt: fetch JWKS: %w", err)
	}

	sigInput := parts[0] + "." + parts[1]
	digest := hashSHA256([]byte(sigInput))

	if !verifySignature(keys, header.Kid, header.Alg, digest, sig) {
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

	// Validate nbf (RFC 7519 §4.1.5): reject a token used before its
	// not-before instant. Tokens that omit nbf are unaffected.
	if raw.Nbf != 0 && timeNow().Before(time.Unix(int64(raw.Nbf), 0)) {
		return nil, ErrTokenNotValidYet
	}

	// Validate the age (iat). A token is a credential for as long as the
	// bound, whatever exp it carries; one that stamps no iat has no age.
	if err := v.validateAge(raw.Iat); err != nil {
		return nil, err
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

	return claimsFromRawPayload(raw), nil
}

// validateAge checks the age the "iat" claim gives the token: none when the
// claim is absent, unless the caller declared that its issuers stamp one.
func (v *Validator) validateAge(iat float64) error {
	if iat == 0 {
		if v.cfg.RequireIssuedAt {
			return ErrTokenTooOld
		}
		return nil
	}
	if v.cfg.MaxTokenAge > 0 && timeNow().Sub(time.Unix(int64(iat), 0)) > v.cfg.MaxTokenAge {
		return ErrTokenTooOld
	}
	return nil
}

// claimsFromRawPayload maps a decoded JWT payload onto Claims. It is
// the single mapping site shared by Validate (after full verification)
// and ParseUnverified (transport-trusted, no verification) so the two
// paths can never disagree on which JSON claim feeds which field.
func claimsFromRawPayload(raw rawPayload) *Claims {
	clientID := raw.ClientID
	if clientID == "" {
		clientID = raw.AuthorizedParty
	}
	return &Claims{
		Sub:           raw.Sub,
		PrincipalType: PrincipalType(raw.PrincipalType),
		OrgID:         raw.OrgID,
		Email:         raw.Email,
		ClientID:      clientID,
		Roles:         raw.Roles,
		Kind:          raw.Kind,
		ActorID:       raw.ActorID,

		PreferredUsername: raw.PreferredUsername,
		OrgSlug:           raw.OrgSlug,
		OrgName:           raw.OrgName,

		Iss: raw.Iss,
		Aud: []string(raw.Aud),
		Exp: time.Unix(int64(raw.Exp), 0),
	}
}

// ParseUnverified decodes a JWT's payload into Claims WITHOUT
// signature, issuer, audience, or expiration validation. It is
// intended only for tokens already trusted by transport — e.g. an
// access token loaded from an encrypted session cookie minted via the
// OIDC PKCE flow, where the bytes never left a trusted boundary
// unverified. For every other input (Authorization headers, query
// params, log fields, anything off the wire), use Validate.
//
// It performs no network I/O (no JWKS fetch) and the only structural
// checks are: three dot-separated segments, a base64url-decodable
// JSON payload, and a non-empty sub. Exp is populated on the returned
// Claims so callers can apply their own lifecycle policy, but it is
// not enforced here.
func ParseUnverified(rawToken string) (*Claims, error) {
	var raw rawPayload
	if err := DecodePayload(rawToken, &raw); err != nil {
		return nil, err
	}
	if raw.Sub == "" {
		return nil, ErrMalformedToken
	}
	return claimsFromRawPayload(raw), nil
}

// DecodePayload unmarshals the payload segment of a compact JWT into v
// without verifying the signature. It is the one place a token is split and
// base64-decoded for its claims; every caller that has already verified the
// token, or holds one that never left a trusted boundary, reads through it.
// Anything else uses [Validator.Validate]. A token that is not three
// segments, or whose payload is not base64url JSON, is [ErrMalformedToken].
func DecodePayload(rawToken string, v any) error {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return ErrMalformedToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrMalformedToken
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return ErrMalformedToken
	}
	return nil
}

// Scopes decodes the "scp" claim of a compact JWT: a product-local token's
// own capability list. The family identity carries no scope (rule R9); a
// service that mints a token for its own seams (rule R4) reads that token's
// scopes through this one helper rather than re-declaring the claim at each
// call site. Like [DecodePayload] it verifies no signature, so use it only on
// a token already verified or one that never left a trusted boundary; a
// malformed token yields nil.
func Scopes(rawToken string) []string {
	var p struct {
		Scopes []string `json:"scp"`
	}
	if err := DecodePayload(rawToken, &p); err != nil {
		return nil
	}
	return p.Scopes
}

// ── Middleware ───────────────────────────────────────────────────────────────

type ctxKey int

const ctxKeyClaims ctxKey = iota

// Middleware returns HTTP middleware that validates the JWT from the
// Authorization: Bearer header and injects Claims into the request context.
// The principal is also stored as an authkit.Identity, so a handler written
// against authkit.IdentityFromContext works behind this middleware and
// behind authkit.Middleware alike.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer.FromRequest(r)
		if !ok {
			authkit.WriteUnauthorized(w, ErrNoToken.Error())
			return
		}

		claims, err := v.Validate(token)
		if err != nil {
			authkit.WriteUnauthorized(w, err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyClaims, claims)
		ctx = authkit.WithIdentity(ctx, claims.authenticated())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClaimsFromContext extracts validated Claims from the context.
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxKeyClaims).(*Claims)
	return c
}

// ── JWKS Cache ──────────────────────────────────────────────────────────────

// The two algorithms a token may name.
const (
	algRS256 = "RS256"
	algES256 = "ES256"
)

// jwkEntry is one usable key of the set: an RSA key, which answers RS256,
// or a P-256 key, which answers ES256. Exactly one of the two is set.
type jwkEntry struct {
	kid string
	rsa *rsa.PublicKey
	ec  *ecdsa.PublicKey
}

// verifies reports whether the key checks sig over digest under alg. An
// RSA key answers RS256 alone and a P-256 key ES256 alone, so a token
// whose header names one algorithm is never checked against a key of the
// other family. An ES256 signature is the JWS form, r and s as two 32-byte
// integers.
func (k jwkEntry) verifies(alg string, digest, sig []byte) bool {
	switch {
	case alg == algRS256 && k.rsa != nil:
		return rsa.VerifyPKCS1v15(k.rsa, crypto.SHA256, digest, sig) == nil
	case alg == algES256 && k.ec != nil:
		if len(sig) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k.ec, digest, r, s)
	}
	return false
}

// minForcedRefreshInterval bounds how often a kid miss may force a JWKS
// refetch, so a flood of tokens carrying unknown kids cannot hammer the
// endpoint.
const minForcedRefreshInterval = 15 * time.Second

type jwksCache struct {
	url        string
	ttl        time.Duration
	get        func(string) (*http.Response, error)
	mu         sync.Mutex // guards cachedAt, lastForced, keys; never held across I/O
	fetchMu    sync.Mutex // serializes JWKS fetches so only one goroutine hits the network
	cachedAt   time.Time
	lastForced time.Time
	keys       []jwkEntry
}

// getKeys returns the cached JWKS, refetching only when the TTL has elapsed.
func (c *jwksCache) getKeys() ([]jwkEntry, error) {
	return c.load(false)
}

// getKeysForKid returns the cached JWKS but, when no cached key matches kid,
// forces a single TTL-bypassing refetch (rate-limited by
// minForcedRefreshInterval) so a freshly rotated signing key is picked up
// without waiting out the whole CacheTTL.
func (c *jwksCache) getKeysForKid(kid string) ([]jwkEntry, error) {
	keys, err := c.load(false)
	if err != nil {
		return keys, err
	}
	if kid == "" || slices.ContainsFunc(keys, func(k jwkEntry) bool { return k.kid == kid }) {
		return keys, nil
	}

	// Claim the forced-refresh window atomically: a flood of unknown-kid tokens
	// triggers at most one refetch per minForcedRefreshInterval.
	c.mu.Lock()
	if timeNow().Sub(c.lastForced) < minForcedRefreshInterval {
		c.mu.Unlock()
		return keys, nil
	}
	c.lastForced = timeNow()
	c.mu.Unlock()

	return c.load(true)
}

// load returns the cached JWKS, fetching from the network only when the cache
// is stale (or force is set). The blocking HTTP fetch runs WITHOUT c.mu held —
// fetchMu serializes fetchers instead — so a concurrent validation whose kid is
// already cached is served from the fast path rather than blocking behind the
// round-trip. The stale-on-error fallback is preserved: any fetch/parse failure
// (or an empty key set) returns the previously cached keys when present.
func (c *jwksCache) load(force bool) ([]jwkEntry, error) {
	if keys, ok := c.freshKeys(force); ok {
		return keys, nil
	}

	// Only one goroutine fetches at a time; the rest wait here, not on c.mu.
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()

	// A fetch we queued behind may have refreshed the cache while we waited.
	if keys, ok := c.freshKeys(force); ok {
		return keys, nil
	}

	get := c.get
	if get == nil {
		get = httpGet
	}
	resp, err := get(c.url)
	if err != nil {
		return c.cachedOr(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.cachedOr(fmt.Errorf("authkit/jwt: JWKS status %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.cachedOr(err)
	}

	var jwks struct {
		Keys []jwkRaw `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return c.cachedOr(err)
	}

	var keys []jwkEntry
	for _, k := range jwks.Keys {
		e := jwkEntry{kid: k.Kid}
		switch k.Kty {
		case "RSA":
			pub, err := parseRSAPublicKey(k.N, k.E)
			if err != nil {
				continue
			}
			e.rsa = pub
		case "EC":
			pub, err := parseECPublicKey(k.Crv, k.X, k.Y)
			if err != nil {
				continue
			}
			e.ec = pub
		default:
			continue
		}
		keys = append(keys, e)
	}

	if len(keys) == 0 {
		// A well-formed 200 that yields no usable keys must not discard a
		// still-valid cache: keep serving the cache and leave cachedAt untouched
		// so the next request retries (mirrors the error-path fallback).
		if cached, _ := c.cachedOr(nil); len(cached) > 0 {
			return cached, nil
		}
		return keys, nil
	}

	c.mu.Lock()
	c.keys = keys
	c.cachedAt = timeNow()
	c.mu.Unlock()
	return keys, nil
}

// freshKeys returns the cached keys when they are still within TTL and force is
// not set; ok is false when a fetch is required. Held briefly under c.mu.
func (c *jwksCache) freshKeys(force bool) ([]jwkEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && timeNow().Sub(c.cachedAt) < c.ttl && len(c.keys) > 0 {
		return c.keys, true
	}
	return nil, false
}

// cachedOr returns the cached keys when present (the stale-on-error fallback),
// otherwise the supplied error. Held briefly under c.mu.
func (c *jwksCache) cachedOr(err error) ([]jwkEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.keys) > 0 {
		return c.keys, nil
	}
	return nil, err
}

type jwkRaw struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// N and E are an RSA key's modulus and exponent.
	N string `json:"n"`
	E string `json:"e"`
	// Crv, X and Y are an EC key's curve and point.
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
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

// parseECPublicKey reads a JWK EC key. Only P-256 is a key this package
// verifies with, and the point must lie on the curve; the coordinates are
// the base64url of two 32-byte big-endian integers (RFC 7518 §6.2.1).
func parseECPublicKey(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	if crv != "P-256" {
		return nil, fmt.Errorf("authkit/jwt: unsupported curve %q", crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, err
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, errors.New("authkit/jwt: EC coordinates are not 32 bytes")
	}
	point := make([]byte, 0, 65)
	point = append(point, 0x04)
	point = append(point, x...)
	point = append(point, y...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

func hashSHA256(data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	return h.Sum(nil)
}

func verifySignature(keys []jwkEntry, kid, alg string, digest, sig []byte) bool {
	if kid != "" {
		for _, k := range keys {
			if k.kid == kid {
				return k.verifies(alg, digest, sig)
			}
		}
	}
	// Fallback: try all keys.
	for _, k := range keys {
		if k.verifies(alg, digest, sig) {
			return true
		}
	}
	return false
}

// rawPayload is the JWT payload as emitted by the auth service.
type rawPayload struct {
	Sub             string   `json:"sub"`
	Iss             string   `json:"iss"`
	Aud             jsonAud  `json:"aud"`
	Exp             float64  `json:"exp"`
	Nbf             float64  `json:"nbf"`
	Iat             float64  `json:"iat"`
	PrincipalType   string   `json:"principal_type"`
	Email           string   `json:"email"`
	OrgID           string   `json:"org_id"`
	Roles           []string `json:"roles"`
	ClientID        string   `json:"client_id"`
	Kind            string   `json:"kind"`
	ActorID         string   `json:"actor_id"`
	AuthorizedParty string   `json:"azp"`

	// The issuer's display labels. Each is a plain string like the claims
	// above it, so a non-string value fails the payload unmarshal and the
	// token is ErrMalformedToken, exactly as it is for org_id.
	PreferredUsername string `json:"preferred_username"`
	OrgSlug           string `json:"org_slug"`
	OrgName           string `json:"org_name"`
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
	return slices.ContainsFunc(tokenAud, func(a string) bool {
		return slices.Contains(expected, a)
	})
}
