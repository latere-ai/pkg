// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"net/http"

	"latere.ai/x/pkg/bearer"
)

// BearerToken is a single shared-secret authenticator for local dev and CI.
// It synthesises an Identity whose Sub is a configurable dev-user id so
// ownership plumbing works end-to-end without a real auth service.
type BearerToken struct {
	token string
	id    Identity
}

// NewBearerToken wires a single shared-secret authenticator. devSub is
// stamped as the owner Sub on every created resource so ownership scoping
// works uniformly in dev. Leaving devSub empty defaults to "dev-local".
func NewBearerToken(token, devSub string) *BearerToken {
	if devSub == "" {
		devSub = "dev-local"
	}
	return &BearerToken{
		token: token,
		id: Identity{
			Sub:           devSub,
			PrincipalType: PrincipalDev,
			IsSuperadmin:  true, // dev token bypasses ownership scoping
			TokenID:       "dev",
			AuthMethod:    MethodBearer,
		},
	}
}

func (b *BearerToken) Authenticate(r *http.Request) (Identity, error) {
	// Fail closed on an empty configured secret: bearer.Equal("", "") is true,
	// so without this guard a zero-value or empty-token BearerToken would
	// accept any request bearing an empty credential and return a superadmin
	// identity.
	if b.token == "" {
		return Identity{}, ErrUnauthenticated
	}
	token, ok := bearer.FromRequest(r)
	if !ok || !bearer.Equal(token, b.token) {
		return Identity{}, ErrUnauthenticated
	}
	return b.id, nil
}
