package authkit

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"latere.ai/x/pkg/jwtauth"
)

// validator is the subset of *jwtauth.Validator used by JWT, extracted as an
// interface so tests can inject a fake without running a real JWKS server.
type validator interface {
	Validate(rawToken string) (*jwtauth.Claims, error)
}

// JWT adapts latere.ai/x/pkg/jwtauth to the Authenticator interface. The
// underlying validator caches JWKS internally; we keep its Middleware out of
// the path so callers can apply their own request-id logging before auth.
//
// For tokens whose claims return NeedsTokenInfo() == true (strict agent
// tokens), JWT calls the auth service's GET /tokeninfo on every request and
// uses the returned payload as the authoritative source of Sub, OrgID, and
// Scopes — because a delegation can be revoked between token issuance and
// expiry. A nil TokenInfoClient in this case fails closed: such tokens are
// rejected outright.
type JWT struct {
	V         validator
	TokenInfo *TokenInfoClient
}

// NewJWT wires a JWT authenticator. v is the JWKS-backed validator from
// latere.ai/x/pkg/jwtauth; ti is optional but required for strict agent
// tokens (NeedsTokenInfo).
func NewJWT(v *jwtauth.Validator, ti *TokenInfoClient) *JWT {
	return &JWT{V: v, TokenInfo: ti}
}

func (j *JWT) Authenticate(r *http.Request) (Identity, error) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return Identity{}, ErrUnauthenticated
	}
	raw := h[len(p):]
	claims, err := j.V.Validate(raw)
	if err != nil {
		return Identity{}, err
	}
	// pkg/jwtauth.Claims doesn't currently surface the "client_id"
	// claim. Pull it locally from the already-validated token so
	// per-OAuth-client resolution works without a pkg release.
	// Safe: V.Validate verified the signature above.
	clientID := clientIDFromJWT(raw)
	if claims.NeedsTokenInfo() {
		if j.TokenInfo == nil {
			return Identity{}, errors.New("strict agent token but tokeninfo client not configured")
		}
		ti, err := j.TokenInfo.Lookup(r.Context(), raw)
		if err != nil {
			return Identity{}, fmt.Errorf("tokeninfo: %w", err)
		}
		return Identity{
			Sub:           ti.Sub,
			OrgID:         ti.OrgID,
			Email:         ti.Email,
			PrincipalType: ti.PrincipalType,
			IsSuperadmin:  false, // superadmin is not re-asserted via tokeninfo
			Scopes:        ti.Scopes,
			ClientID:      firstNonEmpty(ti.ClientID, clientID),
			TokenID:       ti.Sub,
		}, nil
	}
	return Identity{
		Sub:           claims.Sub,
		OrgID:         claims.OrgID,
		Email:         claims.Email,
		PrincipalType: string(claims.PrincipalType),
		IsSuperadmin:  claims.IsSuperadmin,
		Scopes:        claims.Scopes,
		ClientID:      clientID,
		TokenID:       claims.Sub,
	}, nil
}

// clientIDFromJWT base64-decodes the JWT payload segment and returns the
// "client_id" claim. Caller must have already verified the signature —
// we skip validation here because jwtauth.Validator did it. Returns
// "" if the claim is absent or the token is malformed (in which case the
// token would already have been rejected upstream).
func clientIDFromJWT(raw string) string {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var m struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		return ""
	}
	return m.ClientID
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func constantEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
