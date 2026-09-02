package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"latere.ai/x/pkg/otel"

	"golang.org/x/oauth2"

	"latere.ai/x/pkg/jwtauth"
)

// Identity is the lowest-common-denominator result of a successful login. Roles
// is populated only for IDPs that expose roles/groups (empty for identity-only
// providers like Google); consumers needing authorization for those providers
// derive it from their own store. Raw carries the verified ID-token claims for
// providers that need a claim this struct does not name.
type Identity struct {
	Subject string
	Email   string
	Name    string
	Roles   []string
	Raw     map[string]any
}

// ClaimsMapper turns verified token claims into an Identity. idClaims is the
// verified ID-token payload (never nil). accessClaims is the verified
// access-token payload when the access token is a verifiable JWT from the same
// issuer, or nil when it is absent or opaque (e.g. Google) — a mapper must treat
// nil as "no roles available", never as an error.
type ClaimsMapper interface {
	Map(idClaims, accessClaims map[string]any) (Identity, error)
}

// ProviderConfig configures a [Provider] built by [NewProvider].
type ProviderConfig struct {
	Issuer       string // OIDC issuer, e.g. https://auth.latere.ai or a Keycloak realm URL
	ClientID     string
	ClientSecret string // optional; empty means a public client (PKCE only)
	RedirectURL  string
	Scopes       []string // defaults to ["openid","email","profile"]

	// Kind selects the built-in ClaimsMapper: "latere" (default),
	// "keycloak", "google", or "cognito". Ignored when Mapper is set.
	Kind string
	// Mapper overrides Provider with a custom claim mapper.
	Mapper ClaimsMapper

	// HTTPClient is used for discovery and JWKS fetches. Defaults to
	// http.DefaultClient.
	HTTPClient *http.Client
}

// Provider is one issuer: its endpoints, its keys, and the mapper that turns
// its claims into an [Identity]. [NewProvider] discovers the endpoints from
// the issuer; the Latere [Client] builds one from the auth service's fixed
// layout. Safe for concurrent use.
type Provider struct {
	oauth      *oauth2.Config
	idVerifier *jwtauth.Validator // verifies the ID token: sig + aud(==ClientID) + exp
	atVerifier *jwtauth.Validator // verifies the access token: sig + exp (aud skipped)
	issuer     string             // authoritative issuer from discovery
	mapper     ClaimsMapper
}

// discoveryDoc is the subset of the OIDC discovery document we consume.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// NewProvider discovers the issuer's OIDC endpoints and builds a Provider. It
// performs a network fetch of the discovery document, so call it at startup
// with a bounded context.
func NewProvider(ctx context.Context, cfg ProviderConfig) (*Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("oidc: issuer, client id, and redirect url are required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = otel.HTTPClient()
	}
	doc, err := fetchDiscovery(ctx, hc, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	// Public clients (no secret) send client_id in the request body; a
	// confidential client uses client_secret_basic. Never AuthStyleAutoDetect.
	authStyle := oauth2.AuthStyleInHeader
	if cfg.ClientSecret == "" {
		authStyle = oauth2.AuthStyleInParams
	}

	mapper := cfg.Mapper
	if mapper == nil {
		mapper, err = mapperForKind(cfg.Kind)
		if err != nil {
			return nil, err
		}
	}

	return newProvider(&oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   doc.AuthorizationEndpoint,
			TokenURL:  doc.TokenEndpoint,
			AuthStyle: authStyle,
		},
	}, doc.Issuer, doc.JWKSURI, hc, mapper), nil
}

// newProvider assembles a Provider from resolved endpoints. It is the one
// constructor behind NewProvider and the Latere Client.
func newProvider(oauth *oauth2.Config, issuer, jwksURL string, hc *http.Client, mapper ClaimsMapper) *Provider {
	return &Provider{
		oauth: oauth,
		// idVerifier checks aud == ClientID. Issuer is validated separately
		// (issuerOK) so Google's scheme-optional iss is accepted.
		idVerifier: jwtauth.New(jwtauth.Config{
			JWKSURL: jwksURL, Audiences: []string{oauth.ClientID}, HTTPClient: hc,
		}),
		// atVerifier skips aud (an access token's audience is the resource
		// server, not this client); signature and exp are still enforced.
		atVerifier: jwtauth.New(jwtauth.Config{JWKSURL: jwksURL, HTTPClient: hc}),
		issuer:     issuer,
		mapper:     mapper,
	}
}

// AuthCodeURL builds the authorize URL, binding the CSRF state, the PKCE
// S256 challenge derived from verifier (from [GenerateVerifier]), and the
// replay nonce when one is given. extra carries further parameters the
// issuer understands.
func (a *Provider) AuthCodeURL(state, nonce, verifier string, extra ...oauth2.AuthCodeOption) string {
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	return a.oauth.AuthCodeURL(state, append(opts, extra...)...)
}

// Refresh trades a refresh token for a new token set.
func (a *Provider) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return a.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

// DeviceAuth starts an RFC 8628 device authorization. extra carries issuer
// extension parameters.
func (a *Provider) DeviceAuth(ctx context.Context, extra ...oauth2.AuthCodeOption) (*oauth2.DeviceAuthResponse, error) {
	return a.oauth.DeviceAuth(ctx, extra...)
}

// DeviceAccessToken polls the token endpoint with the device-code grant
// until the user approves, denies, or the code expires.
func (a *Provider) DeviceAccessToken(ctx context.Context, da *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	return a.oauth.DeviceAccessToken(ctx, da)
}

// Exchange swaps the authorization code for tokens, proving possession of the
// PKCE verifier. No client secret is sent for a public client.
func (a *Provider) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	tok, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange: %w", err)
	}
	return tok, nil
}

// VerifyIDToken verifies the ID token from an exchanged token and maps its
// claims to an Identity. It fails closed if id_token is missing, fails
// verification (signature/aud/exp/alg via jwtauth — RS256 pinned, so alg=none /
// HS256-confusion is rejected), its issuer does not match, or its nonce does not
// match the nonce bound at AuthCodeURL time.
func (a *Provider) VerifyIDToken(_ context.Context, tok *oauth2.Token, nonce string) (Identity, error) {
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, fmt.Errorf("oidc: token response missing id_token")
	}
	if _, err := a.idVerifier.Validate(raw); err != nil {
		return Identity{}, fmt.Errorf("oidc: verify id_token: %w", err)
	}
	idClaims, err := decodeJWTPayload(raw)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: decode id_token: %w", err)
	}
	if !issuerOK(stringClaim(idClaims["iss"]), a.issuer) {
		return Identity{}, fmt.Errorf("oidc: id_token issuer mismatch")
	}
	if stringClaim(idClaims["nonce"]) != nonce {
		return Identity{}, fmt.Errorf("oidc: id_token nonce mismatch")
	}

	// Best-effort: read roles from the access token only if it is a JWT we can
	// verify from the same issuer. Opaque tokens (Google) yield nil — never an
	// error. Reading roles from an unverified token would be a privilege-escalation
	// hole, so this path is verify-before-trust.
	var accessClaims map[string]any
	if at := tok.AccessToken; at != "" {
		if _, err := a.atVerifier.Validate(at); err == nil {
			if m, err := decodeJWTPayload(at); err == nil && issuerOK(stringClaim(m["iss"]), a.issuer) {
				accessClaims = m
			}
		}
	}

	id, err := a.mapper.Map(idClaims, accessClaims)
	if err != nil {
		return Identity{}, err
	}
	id.Raw = idClaims
	return id, nil
}

// fetchDiscovery loads the OIDC discovery document from issuer.
func fetchDiscovery(ctx context.Context, hc *http.Client, issuer string) (*discoveryDoc, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover %q: %w", issuer, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: discover %q: status %d", issuer, resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("oidc: decode discovery: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, fmt.Errorf("oidc: discovery for %q is missing endpoints", issuer)
	}
	if doc.Issuer == "" {
		doc.Issuer = issuer
	}
	return &doc, nil
}

// decodeJWTPayload decodes the (already-verified) middle segment of a JWT into a
// generic claim map. Callers must verify the token before relying on these
// claims for anything security-sensitive.
func decodeJWTPayload(raw string) (map[string]any, error) {
	var m map[string]any
	if err := jwtauth.DecodePayload(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// issuerOK reports whether a token's iss matches the expected issuer. Google
// emits iss as "https://accounts.google.com" or "accounts.google.com"; treat the
// scheme as optional so both forms verify. For every other IDP this collapses to
// exact match.
func issuerOK(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	if got == want {
		return true
	}
	return strings.TrimPrefix(got, "https://") == strings.TrimPrefix(want, "https://")
}

// stringClaim returns a string claim, or "" when absent or not a string.
func stringClaim(v any) string {
	s, _ := v.(string)
	return s
}

// stringsClaim returns a []string from a claim that may be a []any of strings
// or a single string. Used by mappers for roles/groups claims.
func stringsClaim(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}

// mapperForKind returns the built-in ClaimsMapper for an issuer kind. An
// empty kind defaults to "latere". Unknown kinds are an error.
func mapperForKind(kind string) (ClaimsMapper, error) {
	switch kind {
	case "", "latere":
		return LatereMapper{}, nil
	case "keycloak":
		return KeycloakMapper{}, nil
	case "google":
		return GoogleMapper{}, nil
	case "cognito":
		return CognitoMapper{}, nil
	default:
		return nil, fmt.Errorf("oidc: unknown issuer kind %q", kind)
	}
}

// LatereMapper maps latere auth ID-token claims. latere stamps identity on the
// ID token and roles on the access token (and/or a "roles" claim); read both.
type LatereMapper struct{}

func (LatereMapper) Map(idClaims, accessClaims map[string]any) (Identity, error) {
	roles := stringsClaim(idClaims["roles"])
	if accessClaims != nil {
		roles = unionStrings(roles, stringsClaim(accessClaims["roles"]))
	}
	return Identity{
		Subject: stringClaim(idClaims["sub"]),
		Email:   stringClaim(idClaims["email"]),
		Name:    stringClaim(idClaims["name"]),
		Roles:   roles,
	}, nil
}

// unionStrings returns the de-duplicated union of two string slices, preserving
// first-seen order.
func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
