// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"latere.ai/x/pkg/authkit/jwt"
	pkgotel "latere.ai/x/pkg/otel"
)

// jwksFetchTimeout bounds a single JWKS document fetch. It matches the default
// the JWT validator applies when no client is supplied, so instrumenting the
// client does not change the gateway's failure timing.
const jwksFetchTimeout = 10 * time.Second

// DefaultSubjectClaim is the claim TokenAuth reads the principal from when
// TokenAuthOptions.SubjectClaim is empty.
const DefaultSubjectClaim = "sub"

// TokenAuthOptions configures a [TokenAuth].
type TokenAuthOptions struct {
	// JWKSURL is the issuer's key set endpoint. Required.
	JWKSURL string
	// Issuer, when non-empty, is enforced as the expected "iss".
	Issuer string
	// Audience is the value every gateway token must carry in "aud". Required:
	// a token the same issuer minted for any other purpose must not reach the
	// gateway, so there is no unscoped mode.
	Audience string
	// Scope, when non-empty, is a scope the token must carry.
	Scope string
	// Kind, when non-empty, is the value the token's "kind" claim must equal.
	Kind string
	// SubjectClaim names the claim whose string value identifies the principal
	// and keys its substitution map. Empty means [DefaultSubjectClaim]. A token
	// without a non-empty string under this claim is rejected.
	SubjectClaim string
	// HTTPClient fetches the JWKS. nil uses a traced client with a 10-second
	// timeout.
	HTTPClient *http.Client
}

// claimsValidator is the seam over jwt.Validator so the authenticator's
// logic is unit-testable without a JWKS server.
type claimsValidator interface {
	Validate(rawToken string) (*jwt.Claims, error)
}

// TokenAuth authenticates a CONNECT via the per-workload JWT presented in
// Proxy-Authorization. It verifies the signature against the issuer's JWKS,
// requires the configured audience, scope and kind, and returns the value of
// the configured subject claim as the principal.
type TokenAuth struct {
	v       claimsValidator
	scope   string
	aud     string
	kind    string
	subject string
}

// NewTokenAuth builds an authenticator that fetches keys from opts.JWKSURL.
// It fails when JWKSURL or Audience is empty.
//
// The JWKS fetch is the gateway's only outbound call of its own, and it is the
// one safe to trace: a first-party GET to a fixed keys endpoint with no query
// and no credential. The token being validated never travels on it;
// validation is local against the fetched keys. The traffic the gateway
// forwards on a workload's behalf is deliberately left uninstrumented, since
// a client span would export the request URL, which for many providers
// carries the API key in a query parameter.
func NewTokenAuth(opts TokenAuthOptions) (*TokenAuth, error) {
	if opts.JWKSURL == "" {
		return nil, errors.New("egress: TokenAuthOptions.JWKSURL is required")
	}
	if opts.Audience == "" {
		return nil, errors.New("egress: TokenAuthOptions.Audience is required")
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Transport: pkgotel.Transport(nil),
			Timeout:   jwksFetchTimeout,
		}
	}
	subject := opts.SubjectClaim
	if subject == "" {
		subject = DefaultSubjectClaim
	}
	return &TokenAuth{
		v: jwt.New(jwt.Config{
			JWKSURL:    opts.JWKSURL,
			Issuer:     opts.Issuer,
			HTTPClient: client,
		}),
		scope:   opts.Scope,
		aud:     opts.Audience,
		kind:    opts.Kind,
		subject: subject,
	}, nil
}

// Authenticate implements Authenticator.
func (a *TokenAuth) Authenticate(header string) (string, bool) {
	raw := bearerToken(header)
	if raw == "" {
		return "", false
	}
	claims, err := a.v.Validate(raw)
	if err != nil || claims == nil {
		return "", false
	}
	if a.kind != "" && claims.Kind != a.kind {
		return "", false
	}
	if a.scope != "" && !slices.Contains(claims.Scopes, a.scope) {
		return "", false
	}
	if !slices.Contains(claims.Aud, a.aud) {
		return "", false
	}
	return subjectClaim(raw, a.subject)
}

// subjectClaim reads the string claim named by key from an already verified
// token's payload. The signature was checked by Validate, so decoding the
// payload again is safe; it is the only way to reach a claim the verified
// [jwt.Claims] shape does not carry.
func subjectClaim(raw, key string) (string, bool) {
	var payload map[string]any
	if err := jwt.DecodePayload(raw, &payload); err != nil {
		return "", false
	}
	s, ok := payload[key].(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// bearerToken extracts the JWT from a Proxy-Authorization header. It accepts
// two shapes so both explicit clients and stock HTTPS_PROXY setups work:
//   - "Bearer <jwt>": a client that sets the header directly.
//   - "Basic base64(user:<jwt>)": the token carried as the password in the
//     proxy URL userinfo (HTTPS_PROXY=https://x:<jwt>@egress:port), which is how
//     most HTTP clients pass proxy credentials. The username is ignored.
//
// Returns "" for an empty header or an unrecognised scheme.
func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	scheme, rest, ok := strings.Cut(header, " ")
	if !ok {
		return ""
	}
	rest = strings.TrimSpace(rest)
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return rest
	case strings.EqualFold(scheme, "Basic"):
		raw, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return ""
		}
		_, pass, ok := strings.Cut(string(raw), ":")
		if !ok {
			return ""
		}
		return pass
	default:
		return ""
	}
}
