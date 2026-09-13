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
// decide the Identity. Nothing here calls the issuer, so a token's own
// expiry is its revocation window. A service that wants online
// revalidation holds a [TokenInfoLookup] itself and calls it where the
// decision it changes is visible.
type Authenticator struct {
	V validator
}

// NewAuthenticator wires a JWT authenticator around the JWKS-backed
// validator v.
func NewAuthenticator(v *Validator) *Authenticator {
	return &Authenticator{V: v}
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
