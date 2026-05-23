// Package authkit provides product-agnostic authentication glue for
// Latere AI services. It defines the shared Identity type and
// Authenticator interface so sandbox, Topos, and future services can
// share one implementation instead of drifting copies.
//
// Typical usage:
//
//	v := jwtauth.New(jwtauth.Config{JWKSURL: ..., Issuer: ...})
//	ti := authkit.NewTokenInfoClient(authURL + "/tokeninfo")
//	auth := authkit.NewJWT(v, ti)
//
//	mux.Handle("GET /api/resource", authkit.Middleware(handler, auth))
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    id := authkit.IdentityFromContext(r.Context())
//	    // id.Sub, id.OrgID, id.Scopes ...
//	}
package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// Identity is what handlers see after authentication. Sub is the canonical
// owner key; OrgID is the tenant key. Resources created by a principal are
// labeled with both so lists and deletes can scope to them.
type Identity struct {
	Sub           string
	OrgID         string
	Email         string
	PrincipalType string // "user" | "service" | "agent" | "dev"
	IsSuperadmin  bool
	Scopes        []string
	// ClientID is the OAuth client_id of the caller's token. Used to
	// resolve per-client config. Empty for dev bearer tokens and for
	// older JWTs minted before the client_id claim was added.
	ClientID string
	// TokenID is a stable, low-cardinality audit identifier. For JWT it is
	// the principal Sub; for BearerToken it is "dev".
	TokenID string
}

// Authenticator validates an inbound HTTP request and returns the caller's
// Identity.
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, error)
}

// ErrUnauthenticated is returned when the request carries no recognisable
// credential.
var ErrUnauthenticated = errors.New("unauthenticated")

// ── Context helpers ──────────────────────────────────────────────────────────

type ctxKey int

const ctxKeyIdentity ctxKey = iota

// WithIdentity returns a copy of ctx with the given Identity attached.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKeyIdentity, id)
}

// IdentityFromContext extracts the Identity stored by WithIdentity. Returns
// a zero-value Identity when no identity is present.
func IdentityFromContext(ctx context.Context) Identity {
	id, _ := ctx.Value(ctxKeyIdentity).(Identity)
	return id
}

// ── Middleware ───────────────────────────────────────────────────────────────

// Middleware wraps next with authentication: it calls a.Authenticate,
// injects the Identity into the request context, and responds with 401 JSON
// on failure.
func Middleware(next http.Handler, a Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := a.Authenticate(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "unauthorized",
				"message": err.Error(),
			})
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

// ── Chain ────────────────────────────────────────────────────────────────────

// Chain tries each Authenticator in order and returns the first successful
// Identity. Useful when multiple credential formats circulate concurrently
// (e.g. during a token-type migration). An empty chain returns
// ErrUnauthenticated.
type Chain []Authenticator

func (c Chain) Authenticate(r *http.Request) (Identity, error) {
	var lastErr error = ErrUnauthenticated
	for _, a := range c {
		id, err := a.Authenticate(r)
		if err == nil {
			return id, nil
		}
		lastErr = err
	}
	return Identity{}, lastErr
}
