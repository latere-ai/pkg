package authkit

import (
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
	// jwtauth.Claims surfaces the originating OAuth client (client_id, azp
	// fallback) from the signature-verified token — no second decode needed.
	clientID := claims.ClientID
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
			// Preserve the actor binding from the signature-verified JWT:
			// tokeninfo re-authorizes the revocable fields (Sub/OrgID/Scopes)
			// but carries no Kind/ActorID, so taking them from the verified
			// claims keeps the strict path consistent with the non-strict one.
			Kind:       claims.Kind,
			ActorID:    claims.ActorID,
			GrantorID:  claims.GrantorID,
			AgentID:    claims.AgentID,
			AuthMethod: MethodBearer,
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
		Kind:          claims.Kind,
		ActorID:       claims.ActorID,
		GrantorID:     claims.GrantorID,
		AgentID:       claims.AgentID,
		AuthMethod:    MethodBearer,
	}, nil
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
