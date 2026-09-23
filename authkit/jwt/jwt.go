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
//	org_id              OrgID                  the active organization
//	roles               Roles                  platform_admin, then the role names in that organization
//	email               Email
//	client_id           ClientID               "azp" is the fallback
//	kind, actor_id      Kind, ActorID          a non-principal actor a token is bound to
//	preferred_username  PreferredUsername      the person's handle; absent until they claim one
//	org_slug, org_name  OrgSlug, OrgName       the slug and display name of org_id; absent with it
//	token_use           TokenUse               the credential class that minted it; "pat" is a personal access token
//	authorization_details  Grants              what that credential may do; read on a "pat" token alone
//	iss, aud, exp       Iss, Aud, Exp          the envelope
//
// An issuer that stamps only "sub" still verifies; the Identity that results
// carries the subject and nothing more. The three label claims are display
// only: they name the person and the active organization so that a service
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
// # What is refused, and why
//
// Every refusal is an [Error]: the sentinel a caller matches with errors.Is
// and the [Reason] it belongs to, the word a service writes as the reason of
// its 401. [ReasonOf] reads that word through any number of wraps, so a
// service renders the family's word for a refusal rather than inventing one.
//
//	Error                 Reason                   Word
//	─────                 ──────                   ────
//	ErrMalformedToken     ReasonMalformed          malformed
//	ErrInvalidSignature   ReasonBadSignature       signature
//	ErrUnsupportedAlg     ReasonBadSignature       signature
//	ErrInvalidIssuer      ReasonBadIssuer          issuer
//	ErrInvalidAudience    ReasonBadAudience        audience
//	ErrTokenExpired       ReasonExpired            expired
//	ErrTokenNotValidYet   ReasonNotYetValid        nbf
//	ErrTokenTooLarge      ReasonTooLarge           size
//	ErrTokenTooOld        ReasonTooOld             iat
//	ErrUnknownKey         ReasonUnknownKey         unknown_key
//	ErrBadDiscovery       ReasonBadIssuer          issuer
//	ErrIssuerUnavailable  ReasonIssuerUnavailable  issuer_unavailable
//	ErrGrantsUnread       ReasonGrantsUnread       grants_unread
//
// The word is not the Go identifier and two errors may share one, as the
// two signature refusals do: an algorithm no key of the set can answer is
// what a caller learns as a signature that did not check out. [ErrNoToken]
// carries no reason, because nothing arrived to refuse.
//
// # Grants
//
// A personal access token is the person who holds it, narrowed by what
// that person said the key may do: the grants, carried as RFC 9396's
// "authorization_details" claim (identity id-13). A verified token hands
// them back on [Claims] as an [authkit.Grants], beside the "token_use"
// that says which credential minted it, and the [authkit.Identity] an
// [Authenticator] yields carries both.
//
// Reading them is a promise, and [Config.ReadsGrants] is where a service
// makes it. Off, which is the default, a token that carries grants is
// [ErrGrantsUnread]: the claim is a restriction, so a service that reads
// the token and applies nothing grants more than the person asked for,
// and the closed failure is to refuse. What a grant means at a decision
// is latere.ai/x/pkg/authz's, not this package's; nothing here decides.
//
// # Bounds
//
// A bearer token is a credential, not a document. [Config.MaxTokenBytes]
// refuses one above [DefaultMaxTokenBytes] before it is parsed, and
// [Config.MaxTokenAge] refuses one whose "iat" is older than
// [DefaultMaxTokenAge] whatever "exp" it carries, so an issuer that mints a
// long-lived token does not thereby mint a credential that outlives the day
// it was issued in. A negative value turns either bound off, and
// [Config.RequireIssuedAt] refuses a token that stamps no "iat" at all.
// Both bounds are [Validator.Validate]'s alone: [ParseUnverified] and
// [DecodePayload] take no Config and read a token already trusted by
// transport.
//
// [Config.ClockSkew] is the other direction: the tolerance on "exp" and
// "nbf" for the difference between the issuer's clock and this node's. It
// widens those two claims and nothing else, so it reaches neither the age
// bound, measured against this clock alone, nor a local token, stamped on
// this clock already.
//
// # The clock
//
// [Config.Now] is this node's clock, and nil is time.Now. It is the one
// clock the validator reads: the "exp", "nbf" and "iat" windows, the key
// set's cache TTL, and the back-off on a refresh a kid miss forces. A
// caller that hands one in therefore holds every instant the validator
// reads, which is how a test mints a token, verifies it, and then ages it
// past its "exp" without waiting for the wall clock.
//
// # Which key verifies a token
//
// One rule, on every path. The "kid" names the key that must verify the
// token: the key declaring it, or a key declaring no kid at all, since a
// key published without a name can be reached no other way. A token
// carrying no kid leaves the choice to the set, which only a set holding
// exactly one key can make. Anything else, a kid the set does not hold or a
// choice between keys, is [ErrUnknownKey], and no second key is ever tried:
// admitting a token under a key it did not name is a claim about the set
// that whoever published it never made. On the JWKS path a kid miss forces
// one refresh of the set first, so a key just rotated in at the issuer is
// still picked up. Once the key is chosen only its own verdict counts, so a
// signature that does not check out against it is [ErrInvalidSignature] and
// not the other refusal.
//
// [ParseHeader] hands that same header back, so a caller holding its own
// key sets can make the choice itself. It verifies nothing.
//
// # More than one issuer
//
// [Config.Issuers] is a list of issuer URLs to trust beside
// [Config.Issuer]. A token's "iss" must name one of them; each issuer's key
// set is discovered from the issuer itself, so no JWKS URL is configured
// per issuer, and each answers for its own tokens alone. An "iss" naming
// none of them is [ErrInvalidIssuer] before any key is read, because the
// issuer is what selects the key set. With the list empty, Config.Issuer
// decides alone against the one [Config.JWKSURL].
//
// Discovery follows OpenID Connect Discovery 4.3: the "issuer" the
// document names must be the issuer it was fetched from, trailing slashes
// aside, and a document naming another issuer or naming none is
// [ErrBadDiscovery] before its "jwks_uri" is read. The check runs on the
// one discovery per issuer, since the "jwks_uri" it yields is kept.
//
// # A local issuer
//
// [Config.LocalIssuer] is an issuer verified against a key the caller
// configures, with no JWKS fetch: the tokens a process mints for itself, and
// a stub issuer a test stands up with no server. A token naming it is
// checked against [Config.LocalKey] under the kid [Config.LocalKeyID] names,
// and is not checked against [Config.Issuer]; every other token takes the
// JWKS path unchanged.
//
// [Config.LocalKeys] holds more than one such key, which is what a rotation
// needs: the newer key signs while the older still verifies, until the
// tokens it signed expire. Which key answers is the one rule above.
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
// [Validator.Warm] reads every configured issuer's key set once, for a
// process that wants the fetch paid at start-up rather than by the first
// request. It is optional and idempotent, and a validator that was never
// warmed behaves exactly as it always did.
//
// When no cached set answers either, the refusal is
// [ErrIssuerUnavailable], reason "issuer_unavailable": the discovery
// document or the JWKS endpoint did not answer, so nothing is known about
// the token. It is the issuer that is out of reach and not the token that
// is wrong, which is why it is a row of its own rather than a signature
// that failed.
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
	"bytes"
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
	"maps"
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
	ReasonUnknownKey   Reason = "unknown_key"
	// ReasonIssuerUnavailable is the issuer being out of reach rather than
	// the token being wrong: nothing is known about the token because the
	// keys that would decide it could not be read.
	ReasonIssuerUnavailable Reason = "issuer_unavailable"
	// ReasonGrantsUnread is a token that carries grants and a validator
	// that does not read them. The token is well formed and the refusal
	// is about this node: it would admit a credential narrower than it
	// can enforce.
	ReasonGrantsUnread Reason = "grants_unread"
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
	// ErrUnknownKey is a token whose "kid" names no key of the issuer's
	// set, after one refresh of that set. It is not a bad signature: the
	// token named a key nobody published, and no other key was tried.
	ErrUnknownKey = refusal(ReasonUnknownKey, "authkit/jwt: unknown key")
	// ErrBadDiscovery is a discovery document that names an issuer other
	// than the one it was fetched from, or names none at all (OpenID
	// Connect Discovery 4.3). Such a document is not the issuer's own
	// statement about itself, so the key set it points at is not the
	// issuer's set, and no key of it is read. Its reason is the issuer:
	// what failed is the issuer this node was told to trust.
	ErrBadDiscovery = refusal(ReasonBadIssuer, "authkit/jwt: discovery document names another issuer")
	// ErrIssuerUnavailable is an issuer whose key set could not be read:
	// its discovery document or its JWKS endpoint did not answer, and no
	// cached set was held to answer in their place. It says nothing about
	// the token, which is why it is a row of its own: a node that cannot
	// reach an issuer refuses that issuer's tokens until one fetch
	// succeeds, and a cached set, however stale, is still an answer and is
	// still served.
	ErrIssuerUnavailable = refusal(ReasonIssuerUnavailable, "authkit/jwt: issuer unavailable")
	// ErrGrantsUnread is a token whose "token_use" is a personal access
	// token and which carries an "authorization_details" claim, presented
	// to a validator whose [Config.ReadsGrants] is false. The claim is a
	// restriction, so a reader that ignores it grants more than the person
	// asked for, silently, at the one place nobody is looking: a refusal
	// is visible in a 401 with a named reason, and an ignored restriction
	// is visible nowhere.
	ErrGrantsUnread = refusal(ReasonGrantsUnread, "authkit/jwt: the token carries grants this validator does not read")
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
	// Issuer is the expected "iss" claim. Skipped if empty. Trailing
	// slashes are not part of an issuer's name, so "https://x" and
	// "https://x/" are one issuer; the claim is handed back on [Claims]
	// exactly as the token carried it.
	Issuer string
	// Issuers are further issuer URLs to trust, beside Issuer: a token's
	// "iss" must name one of them, and each one's key set is discovered
	// from the issuer itself, at
	// "<issuer>/.well-known/openid-configuration", so no JWKS URL is
	// configured per issuer. Issuer keeps its own JWKSURL and is trusted
	// beside these. When this list is empty nothing changes: Issuer alone
	// decides, against the one JWKSURL.
	//
	// With the list set, an "iss" naming none of the trusted issuers is
	// [ErrInvalidIssuer] before any key is read, since the issuer is what
	// selects the key set. Each issuer answers for its own tokens alone:
	// trusting two issuers does not pool their keys.
	//
	// Each discovery document must name the issuer it was fetched from
	// (OpenID Connect Discovery 4.3); one that names another issuer, or
	// names none, is [ErrBadDiscovery] and its "jwks_uri" is not read.
	Issuers []string
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
	// ReadsGrants is this validator's promise that whoever holds the
	// Identity it yields applies the grants a token carries: the
	// "authorization_details" claim of RFC 9396, which narrows a personal
	// access token to the actions and resources its holder chose
	// (identity id-13).
	//
	// It is off by default and a token that carries grants is then
	// [ErrGrantsUnread], reason "grants_unread". That is the closed
	// failure: the claim is a restriction, so a service that reads the
	// token and ignores it grants more than the person asked for, and an
	// ignored restriction is visible nowhere. A refusal is visible in a
	// 401 with a named reason.
	//
	// A service sets it once its own authz/conformance run passes the
	// grant rows, which is what turns the flag from a promise into
	// evidence. It reaches [Validator.Validate] alone: [ParseUnverified]
	// and [DecodePayload] take no Config and read a token already trusted
	// by transport.
	ReadsGrants bool
	// LocalIssuer is an issuer verified against LocalKey with no JWKS
	// fetch: the "iss" of the tokens the process mints for itself, and of
	// a stub issuer a test stands up with no server. A token naming it is
	// checked against LocalKey alone and is not checked against Issuer;
	// every other token takes the JWKS path unchanged. It is matched like
	// Issuer, trailing slashes aside. Empty turns the mode off.
	LocalIssuer string
	// LocalKey is the public half of the key LocalIssuer signs with, an
	// *rsa.PublicKey or an *ecdsa.PublicKey on P-256. [New] panics when
	// LocalIssuer is set with neither this nor LocalKeys: a local issuer
	// with no key would
	// refuse every one of its tokens as a bad signature, which is a wiring
	// mistake and not a verdict.
	LocalKey crypto.PublicKey
	// LocalKeyID is the "kid" a token of LocalIssuer must name. Empty
	// accepts any kid, since the set holds one key either way.
	LocalKeyID string
	// LocalKeys are further keys of LocalIssuer, beside LocalKey: the form
	// a rotation needs, where the newer key signs and the older still
	// verifies until the tokens it signed expire. A token's "kid" selects
	// the key that must verify it, so a kid naming none of them is
	// [ErrUnknownKey] rather than tried against every key. A key that
	// declares no KeyID answers whatever kid a token names, as the one-key
	// form does.
	LocalKeys []LocalKey
	// ClockSkew is the tolerance on "exp" and "nbf" for the difference
	// between the issuer's clock and this node's: a token is read until
	// ClockSkew past its "exp", and from ClockSkew before its "nbf". Zero
	// by default, so neither claim is widened unless a caller asks.
	//
	// It is a tolerance between two clocks, so it reaches neither
	// [Config.MaxTokenAge], which is measured against this node's clock
	// alone, nor a token of [Config.LocalIssuer], which was stamped on
	// this clock and has no second clock to reconcile.
	ClockSkew time.Duration
	// Now is this node's clock: what the validator reads every time it
	// needs the current instant. Nil is time.Now, which is what a service
	// wants; a caller supplies one to run the whole validator on a clock
	// it moves, which is how a test mints a token and then ages it without
	// waiting.
	//
	// It is the one clock: the "exp", "nbf" and "iat" windows read it, and
	// so do the key-set cache's TTL and the back-off on a forced refresh.
	// A validator handed a clock therefore reaches no real time at all, so
	// a test that advances the clock past [Config.CacheTTL] sees the next
	// fetch it would see in production.
	Now func() time.Time
}

// LocalKey is one key of [Config.LocalIssuer]: the "kid" a token names it
// by, and the public half it is verified with, an *rsa.PublicKey or an
// *ecdsa.PublicKey on P-256.
type LocalKey struct {
	KeyID string
	Key   crypto.PublicKey
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
// endpoint, and the tokens of [Config.LocalIssuer] against the key it was
// configured with.
type Validator struct {
	cfg   Config
	cache *jwksCache
	// issuers is the key set of each trusted issuer, by its trimmed URL,
	// when Config.Issuers is configured. Empty otherwise, and Config.Issuer
	// then decides alone against cache.
	issuers map[string]*jwksCache
	// local is the key set of Config.LocalIssuer: one key, or none when
	// no local issuer is configured.
	local []jwkEntry
	// now is the clock every window is read against: Config.Now, or the
	// package clock when the caller supplied none.
	now func() time.Time
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
	cache := &jwksCache{url: cfg.JWKSURL, ttl: cfg.CacheTTL, clock: cfg.Now}
	if cfg.HTTPClient != nil {
		cache.get = cfg.HTTPClient.Get
	}
	return &Validator{
		cfg:     cfg,
		cache:   cache,
		issuers: issuerKeySets(cfg, cache),
		local:   localKeySet(cfg),
		now:     clockOf(cfg.Now),
	}
}

// Warm reads every configured issuer's key set once, so a process that
// probes its own readiness at start-up and the first request that follows
// do not each pay for the fetch. It is what a start-up hook calls, and
// calling it is optional: a validator that was never warmed fetches on
// the first token it is handed, exactly as before.
//
// It is idempotent. Warming again inside [Config.CacheTTL] reads the
// cache and reaches no network, so a probe on a schedule costs one fetch
// per TTL and not one per probe.
//
// Which sets are read is which issuers are configured: each of
// [Config.Issuers], and [Config.Issuer] beside them when it names its own
// [Config.JWKSURL]. [Config.LocalIssuer] is verified against a key the
// caller already holds, so there is nothing of it to warm, and a
// validator that reaches no network at all warms nothing and reports
// nothing.
//
// The return is a report and not a verdict: an issuer that did not answer
// is named, every other issuer is still warm, and the validator verifies
// either way, retrying the fetch when a token of that issuer arrives.
// More than one failure is joined, so a probe names every issuer it could
// not reach rather than the first. ctx bounds the walk, and a cancelled
// one stops it before the next fetch.
func (v *Validator) Warm(ctx context.Context) error {
	sets := v.keySets()
	var errs []error
	for _, iss := range slices.Sorted(maps.Keys(sets)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := sets[iss].getKeys(); err != nil {
			errs = append(errs, fmt.Errorf("authkit/jwt: warm %s: %w", iss, err))
		}
	}
	return errors.Join(errs...)
}

// keySets is every key set a token could send this validator to, by the
// name it is warmed and reported under: the issuer list when one is
// configured, and the one configured JWKS endpoint otherwise. A validator
// with neither has no set to fetch.
//
// Config.Issuer is in the list only when it names its own JWKSURL, which
// is the same rule issuerKeySets folds it in under, and it is the same
// rule keysFor reads: with an issuer list configured, a token is answered
// from that list alone and v.cache is not reached, so a cache the list
// does not hold is a cache no token can spend.
func (v *Validator) keySets() map[string]*jwksCache {
	if len(v.issuers) > 0 {
		return v.issuers
	}
	if v.cfg.JWKSURL == "" {
		return nil
	}
	name := v.cfg.Issuer
	if name == "" {
		name = v.cfg.JWKSURL
	}
	return map[string]*jwksCache{trimIssuer(name): v.cache}
}

// clockOf is the clock a validator reads: the caller's when Config.Now is
// set, and the package clock otherwise. The fallback is a closure rather
// than time.Now itself so that the package clock stays one variable, which
// is what this package's own tests move.
func clockOf(now func() time.Time) func() time.Time {
	if now != nil {
		return now
	}
	return func() time.Time { return timeNow() }
}

// issuerKeySets is one key set per trusted issuer, keyed by its trimmed
// URL, or nil when Config.Issuers names none. An issuer on the list
// discovers its own key set; Config.Issuer keeps the explicitly configured
// JWKSURL, which wins for it even when the list names it too.
func issuerKeySets(cfg Config, cache *jwksCache) map[string]*jwksCache {
	if len(cfg.Issuers) == 0 {
		return nil
	}
	var get func(string) (*http.Response, error)
	if cfg.HTTPClient != nil {
		get = cfg.HTTPClient.Get
	}
	sets := make(map[string]*jwksCache, len(cfg.Issuers)+1)
	for _, iss := range cfg.Issuers {
		key := trimIssuer(iss)
		if key == "" || sets[key] != nil {
			continue
		}
		sets[key] = &jwksCache{issuer: key, ttl: cfg.CacheTTL, get: get, clock: cfg.Now}
	}
	if cfg.Issuer != "" && cfg.JWKSURL != "" {
		sets[trimIssuer(cfg.Issuer)] = cache
	}
	return sets
}

// localKeySet is the key set of Config.LocalIssuer, the one-key form and
// the list together, and nil when no local issuer is configured. It panics
// on a local issuer with no key, or a key of a kind no algorithm here
// verifies with.
func localKeySet(cfg Config) []jwkEntry {
	if cfg.LocalIssuer == "" {
		return nil
	}
	var set []jwkEntry
	if cfg.LocalKey != nil {
		set = append(set, localEntry(cfg.LocalKeyID, cfg.LocalKey))
	}
	for _, k := range cfg.LocalKeys {
		set = append(set, localEntry(k.KeyID, k.Key))
	}
	if len(set) == 0 {
		panic("authkit/jwt: Config.LocalIssuer needs a LocalKey or LocalKeys")
	}
	return set
}

// localEntry is one local key as a set entry.
func localEntry(kid string, key crypto.PublicKey) jwkEntry {
	e := jwkEntry{kid: kid}
	switch k := key.(type) {
	case *rsa.PublicKey:
		e.rsa = k
	case *ecdsa.PublicKey:
		e.ec = k
	default:
		panic("authkit/jwt: a local key must be an *rsa.PublicKey or an *ecdsa.PublicKey")
	}
	return e
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
	header, err := parseHeaderSegment(parts[0])
	if err != nil {
		return nil, err
	}
	if header.Alg != algRS256 && header.Alg != algES256 {
		return nil, ErrUnsupportedAlg
	}

	// Verify signature.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformedToken
	}

	// Decode the payload: the issuer it names selects the keys, the local
	// set or the issuer's.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var raw rawPayload
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return nil, ErrMalformedToken
	}

	local := v.cfg.LocalIssuer != "" && sameIssuer(raw.Iss, v.cfg.LocalIssuer)
	keys, err := v.keysFor(local, raw.Iss, header.KID)
	if err != nil {
		return nil, err
	}

	sigInput := parts[0] + "." + parts[1]
	digest := hashSHA256([]byte(sigInput))

	if err := verifyAgainst(keys, header.KID, header.Alg, digest, sig); err != nil {
		return nil, err
	}

	// Validate exp and nbf, each widened by the skew between the issuer's
	// clock and this one. A local token was stamped on this clock, so it
	// gets none.
	skew := v.cfg.ClockSkew
	if local {
		skew = 0
	}
	exp := time.Unix(int64(raw.Exp), 0)
	if v.now().After(exp.Add(skew)) {
		return nil, ErrTokenExpired
	}

	// Validate nbf (RFC 7519 §4.1.5): reject a token used before its
	// not-before instant. Tokens that omit nbf are unaffected.
	if raw.Nbf != 0 && v.now().Before(time.Unix(int64(raw.Nbf), 0).Add(-skew)) {
		return nil, ErrTokenNotValidYet
	}

	// Validate the age (iat). A token is a credential for as long as the
	// bound, whatever exp it carries; one that stamps no iat has no age.
	if err := v.validateAge(raw.Iat); err != nil {
		return nil, err
	}

	// Validate iss. A local token named its issuer to be routed there, so
	// the Issuer of an issuer's tokens is not a second value it must carry.
	if !local && len(v.issuers) == 0 && v.cfg.Issuer != "" && !sameIssuer(raw.Iss, v.cfg.Issuer) {
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

	// The grants are read last, after the signature and the envelope, so
	// that a tampered token is refused as a signature and never as an
	// unread grant: the reason a service writes names what was actually
	// wrong with the token.
	if raw.carriesGrants() && !v.cfg.ReadsGrants {
		return nil, ErrGrantsUnread
	}

	return claimsFromRawPayload(raw)
}

// sameIssuer reports whether two issuer URLs name one issuer. Trailing
// slashes are not part of the name: an issuer that publishes "https://x"
// and stamps "https://x/" is one issuer, and no caller can reconcile that
// from outside. Nothing else is normalized, so a path is still a path.
func sameIssuer(a, b string) bool { return trimIssuer(a) == trimIssuer(b) }

// trimIssuer is an issuer URL by the name it is matched under.
func trimIssuer(s string) string { return strings.TrimRight(s, "/") }

// keysFor is the set the token's signature is checked against: the local
// key alone for a token of Config.LocalIssuer, which reaches no network,
// and the issuer's set otherwise. A local token whose kid does not name the
// local key is answered with an empty set, so it fails as a signature.
func (v *Validator) keysFor(local bool, iss, kid string) ([]jwkEntry, error) {
	if local {
		return v.local, nil
	}
	set := v.cache
	if len(v.issuers) > 0 {
		// The issuer selects the key set, so an issuer that is trusted by
		// nothing is refused here rather than against another's keys.
		set = v.issuers[trimIssuer(iss)]
		if set == nil {
			return nil, ErrInvalidIssuer
		}
	}
	keys, err := set.getKeysForKid(kid)
	if err != nil {
		return nil, unreachable(err)
	}
	return keys, nil
}

// unreachable classifies a failure to read an issuer's key set. A failure
// the fetch already named keeps its own row, as a discovery document that
// names another issuer does; anything else is the issuer being out of
// reach, which is [ErrIssuerUnavailable]. A cached set never reaches here:
// it is an answer, and load serves it in place of the error.
func unreachable(err error) error {
	if ReasonOf(err) != "" {
		return fmt.Errorf("authkit/jwt: fetch JWKS: %w", err)
	}
	return fmt.Errorf("%w: fetch JWKS: %w", ErrIssuerUnavailable, err)
}

// validateAge checks the age the "iat" claim gives the token: none when the
// claim is absent, unless the caller declared that its issuers stamp one.
// The claim is a pointer so that an absent "iat" and an "iat" of 0 are two
// different tokens: the second names the epoch and is ancient.
func (v *Validator) validateAge(iat *float64) error {
	if iat == nil {
		if v.cfg.RequireIssuedAt {
			return ErrTokenTooOld
		}
		return nil
	}
	if v.cfg.MaxTokenAge > 0 && v.now().Sub(time.Unix(int64(*iat), 0)) > v.cfg.MaxTokenAge {
		return ErrTokenTooOld
	}
	return nil
}

// claimsFromRawPayload maps a decoded JWT payload onto Claims. It is
// the single mapping site shared by Validate (after full verification)
// and ParseUnverified (transport-trusted, no verification) so the two
// paths can never disagree on which JSON claim feeds which field.
//
// One claim can fail to map: a grants claim that cannot be read as a set
// of grants is [ErrMalformedToken], the row a non-string "org_id" already
// lands in. It is refused on both paths, so a token trusted by transport
// cannot carry what a verified token could not.
func claimsFromRawPayload(raw rawPayload) (*Claims, error) {
	grants, err := raw.grants()
	if err != nil {
		return nil, err
	}
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

		TokenUse: raw.TokenUse,
		Grants:   grants,

		Iss: raw.Iss,
		Aud: []string(raw.Aud),
		Exp: time.Unix(int64(raw.Exp), 0),
	}, nil
}

// grants reads the "authorization_details" claim off the payload. Only a
// personal access token carries one, so a token of any other credential
// class carries no grant whatever the claim says, which is also why a
// malformed claim on such a token refuses nothing: nothing would read it.
func (raw rawPayload) grants() (authkit.Grants, error) {
	if !raw.carriesGrants() {
		return nil, nil
	}
	g, err := authkit.ParseGrants(raw.AuthorizationDetails)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedToken, err)
	}
	return g, nil
}

// carriesGrants reports whether this payload was minted from a key whose
// class grants narrow, with a grants claim to read. A claim written as JSON
// null carries nothing, the same as an absent one.
func (raw rawPayload) carriesGrants() bool {
	if !authkit.NarrowedByGrants(raw.TokenUse) {
		return false
	}
	trimmed := bytes.TrimSpace(raw.AuthorizationDetails)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
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
	return claimsFromRawPayload(raw)
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

// Header is the JOSE header of a compact JWT: what a caller needs to pick
// the key that must verify the token.
type Header struct {
	// Alg is the "alg" the token is signed under: "RS256" or "ES256" for a
	// token this package verifies.
	Alg string
	// KID is the "kid" the header names, and empty when it names none. It
	// is the name the key is published under at the issuer.
	KID string
	// Typ is the "typ" the header declares, and empty when it declares
	// none. Nothing here reads it.
	Typ string
}

// ParseHeader decodes the JOSE header of a compact JWT. It verifies
// nothing and reaches no network: it is for a caller that holds its own
// key sets and needs the "kid" to choose the key, which is the choice
// [Validator.Validate] makes for itself and has no other way to hand back.
// A token that is not three segments, or whose header is not base64url
// JSON, is [ErrMalformedToken].
func ParseHeader(rawToken string) (Header, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return Header{}, ErrMalformedToken
	}
	return parseHeaderSegment(parts[0])
}

// parseHeaderSegment decodes one JOSE header segment. It is the one place
// a header is read, shared by ParseHeader and Validate, so the two can
// never disagree on what a header says.
func parseHeaderSegment(seg string) (Header, error) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return Header{}, ErrMalformedToken
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return Header{}, ErrMalformedToken
	}
	return Header{Alg: h.Alg, KID: h.Kid, Typ: h.Typ}, nil
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
	// url is the JWKS endpoint. Empty when the set was given an issuer to
	// discover it from; the first fetch then resolves it and keeps it.
	url string
	// issuer is the trimmed issuer URL a discovered set belongs to.
	issuer string
	ttl    time.Duration
	// clock is Config.Now, and nil when the caller supplied none: the set
	// then reads the package clock, like everything else here.
	clock      func() time.Time
	get        func(string) (*http.Response, error)
	mu         sync.Mutex // guards cachedAt, lastForced, keys; never held across I/O
	fetchMu    sync.Mutex // serializes JWKS fetches so only one goroutine hits the network
	cachedAt   time.Time
	lastForced time.Time
	keys       []jwkEntry
}

// now is the clock this set measures its TTL and its refresh back-off on.
func (c *jwksCache) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return timeNow()
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
	if c.now().Sub(c.lastForced) < minForcedRefreshInterval {
		c.mu.Unlock()
		return keys, nil
	}
	c.lastForced = c.now()
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
	url, err := c.resolve(get)
	if err != nil {
		return c.cachedOr(err)
	}
	resp, err := get(url)
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
	c.cachedAt = c.now()
	c.mu.Unlock()
	return keys, nil
}

// resolve is the JWKS endpoint of this set: the configured one, or the
// "jwks_uri" of the issuer's discovery document, read once and kept. It
// runs under fetchMu, so one goroutine discovers and the rest read what it
// found.
func (c *jwksCache) resolve(get func(string) (*http.Response, error)) (string, error) {
	c.mu.Lock()
	url := c.url
	c.mu.Unlock()
	if url != "" {
		return url, nil
	}
	if c.issuer == "" {
		return "", errors.New("authkit/jwt: no JWKS URL and no issuer to discover one from")
	}

	resp, err := get(c.issuer + "/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authkit/jwt: discovery status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", err
	}
	// OpenID Connect Discovery 4.3, weighed before the document is read
	// for anything else: the issuer a document names must be the issuer it
	// was fetched from. A document naming another issuer, or naming none,
	// is somebody else's statement served under this URL, and following
	// its jwks_uri would let its keys verify this issuer's tokens.
	if !sameIssuer(doc.Issuer, c.issuer) {
		return "", fmt.Errorf("%w: %s names issuer %q", ErrBadDiscovery, c.issuer, doc.Issuer)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("authkit/jwt: %s names no jwks_uri", c.issuer)
	}

	c.mu.Lock()
	c.url = doc.JWKSURI
	c.mu.Unlock()
	return doc.JWKSURI, nil
}

// freshKeys returns the cached keys when they are still within TTL and force is
// not set; ok is false when a fetch is required. Held briefly under c.mu.
func (c *jwksCache) freshKeys(force bool) ([]jwkEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.now().Sub(c.cachedAt) < c.ttl && len(c.keys) > 0 {
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

// verifyAgainst checks sig against the one key of the set that may answer
// the token, by the same rule on every path.
//
// The "kid" names that key: a key declaring it, or a key declaring no kid
// at all, since a key the issuer published without a name can be reached no
// other way. A token naming no kid leaves the choice to the set, which only
// a set of exactly one key can make. Anything else, a kid the set does not
// hold or a choice between keys, is [ErrUnknownKey], and no second key is
// ever tried: admitting a token under a key it did not name is a claim
// about the set that whoever published it never made. Once the key is
// chosen, only its own verdict counts, so a signature that does not check
// out against it is [ErrInvalidSignature].
func verifyAgainst(keys []jwkEntry, kid, alg string, digest, sig []byte) error {
	named := keys
	if kid != "" {
		named = nil
		for _, k := range keys {
			if k.kid == kid || k.kid == "" {
				named = append(named, k)
			}
		}
	}
	if len(named) != 1 {
		return ErrUnknownKey
	}
	if !named[0].verifies(alg, digest, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// rawPayload is the JWT payload as emitted by the auth service.
type rawPayload struct {
	Sub             string   `json:"sub"`
	Iss             string   `json:"iss"`
	Aud             jsonAud  `json:"aud"`
	Exp             float64  `json:"exp"`
	Nbf             float64  `json:"nbf"`
	Iat             *float64 `json:"iat"`
	PrincipalType   string   `json:"principal_type"`
	Email           string   `json:"email"`
	OrgID           string   `json:"org_id"`
	Roles           []string `json:"roles"`
	ClientID        string   `json:"client_id"`
	Kind            string   `json:"kind"`
	ActorID         string   `json:"actor_id"`
	AuthorizedParty string   `json:"azp"`

	// The credential class that minted the token, and what the person who
	// created it said it may do. Both are read only together: the grants
	// claim belongs to a personal access token and to no other token the
	// family mints, so token_use is what selects it.
	TokenUse             string          `json:"token_use"`
	AuthorizationDetails json.RawMessage `json:"authorization_details"`

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
