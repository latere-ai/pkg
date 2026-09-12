// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"net/http"

	"latere.ai/x/pkg/authkit"
	"latere.ai/x/pkg/bearer"
)

// validator is the subset of *Validator used by Authenticator, extracted as
// an interface so tests can inject a fake without running a real JWKS server.
type validator interface {
	Validate(rawToken string) (*Claims, error)
}

// Authenticator adapts a Validator to the authkit.Authenticator interface.
// The validator caches JWKS internally; its Middleware is kept out of the
// path so callers can apply their own request-id logging before auth.
//
// Authentication is local: the signature and claims of the presented token
// decide the Identity. No claim makes this authenticator reach for
// /tokeninfo, so a token's own expiry is its revocation window.
//
// TokenInfo is a field Authenticate never reads. It is here so a consumer
// that wants online revalidation can carry the lookup beside the
// authenticator and call it where the decision is visible, rather than
// having one hidden behind a claim.
type Authenticator struct {
	V         validator
	TokenInfo TokenInfoLookup
}

// NewAuthenticator wires a JWT authenticator around the JWKS-backed
// validator v. ti is stored on the returned Authenticator and never consulted
// by Authenticate; pass nil unless you read a.TokenInfo yourself.
func NewAuthenticator(v *Validator, ti TokenInfoLookup) *Authenticator {
	return &Authenticator{V: v, TokenInfo: ti}
}

func (a *Authenticator) Authenticate(r *http.Request) (authkit.Identity, error) {
	raw, ok := bearer.FromRequest(r)
	if !ok {
		return authkit.Identity{}, authkit.ErrUnauthenticated
	}
	claims, err := a.V.Validate(raw)
	if err != nil {
		return authkit.Identity{}, err
	}
	return claims.authenticated(), nil
}

// authenticated is the Identity a bearer JWT resolves to: the verified
// principal stamped with the resolution fields that are not claims.
func (c *Claims) authenticated() authkit.Identity {
	id := c.Identity
	id.TokenID = c.Sub
	id.AuthMethod = authkit.MethodBearer
	return id
}
