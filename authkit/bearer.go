package authkit

import (
	"net/http"
	"strings"
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
			PrincipalType: "dev",
			IsSuperadmin:  true, // dev token bypasses ownership scoping
			TokenID:       "dev",
			AuthMethod:    MethodBearer,
		},
	}
}

func (b *BearerToken) Authenticate(r *http.Request) (Identity, error) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return Identity{}, ErrUnauthenticated
	}
	if !constantEq(h[len(p):], b.token) {
		return Identity{}, ErrUnauthenticated
	}
	return b.id, nil
}
