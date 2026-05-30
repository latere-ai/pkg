package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// jwtClaims holds the JWT access-token claims we surface in the session. These
// are identity hints for rendering — the access token itself remains the bearer
// of authority for downstream API calls, so the signature is not verified here
// (the token was just issued by our own auth service via a trusted exchange).
type jwtClaims struct {
	Sub             string   `json:"sub"`
	Email           string   `json:"email"`
	Name            string   `json:"name"`
	DisplayName     string   `json:"display_name"`
	Picture         string   `json:"picture"`
	AvatarURL       string   `json:"avatar_url"`
	OrgID           string   `json:"org_id"`
	ClientID        string   `json:"client_id"`
	AuthorizedParty string   `json:"azp"`
	Scope           string   `json:"scope"`
	Scopes          []string `json:"scopes"`
	Roles           []string `json:"roles"`
	IsSuperadmin    bool     `json:"is_superadmin"`
}

// decodeJWTClaims extracts claims from a JWT access token without
// verifying the signature. The token was just issued by our own auth
// service via a trusted exchange, so verification is unnecessary.
func decodeJWTClaims(accessToken string) (*jwtClaims, error) {
	parts := strings.SplitN(accessToken, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c jwtClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// SessionFromToken builds a Session from a freshly issued token, decoding the
// access token's JWT for identity hints (sub, email, name, org, roles, scopes,
// client, superadmin). Identity hints in the cookie are UI-only; downstream API
// calls always re-validate the access token. SessionExpiry is stamped at now+ttl
// when ttl > 0 (the dashboard session lifetime), and left zero otherwise.
func SessionFromToken(token *oauth2.Token, ttl time.Duration) *Session {
	now := time.Now().UTC()
	exp := token.Expiry
	if exp.IsZero() {
		exp = now.Add(15 * time.Minute)
	}
	claims, _ := decodeJWTClaims(token.AccessToken)
	if claims == nil {
		claims = &jwtClaims{}
	}
	sess := &Session{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       exp.UTC(),
		IssuedAt:     now,
		User: User{
			Sub:          claims.Sub,
			Email:        claims.Email,
			Name:         claims.Name,
			Picture:      claims.Picture,
			AvatarURL:    firstNonEmpty(claims.AvatarURL, claims.Picture),
			OrgID:        claims.OrgID,
			DisplayName:  firstNonEmpty(claims.DisplayName, claims.Name),
			OrgRoles:     claims.Roles,
			ClientID:     firstNonEmpty(claims.ClientID, claims.AuthorizedParty),
			Scopes:       scopesFromJWT(claims),
			IsSuperadmin: claims.IsSuperadmin,
		},
	}
	if ttl > 0 {
		sess.SessionExpiry = now.Add(ttl)
	}
	return sess
}

// scopesFromJWT reads granted scopes from either the space-delimited "scope"
// claim or the "scopes" array, normalizing to a deduped slice.
func scopesFromJWT(c *jwtClaims) []string {
	if c == nil {
		return nil
	}
	if strings.TrimSpace(c.Scope) != "" {
		return splitScopes(c.Scope)
	}
	if len(c.Scopes) > 0 {
		return splitScopes(strings.Join(c.Scopes, " "))
	}
	return nil
}

// splitScopes splits a space/comma-delimited scope string into a deduped,
// order-preserving slice.
func splitScopes(s string) []string {
	parts := strings.Fields(strings.ReplaceAll(s, ",", " "))
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// firstNonEmpty returns the first non-empty string, or "".
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// isSafeRedirect returns true when target is a relative path that won't
// redirect to an external host. Rejects "//host" (protocol-relative) and
// "/\host" (Chrome and other browsers normalize backslashes to forward
// slashes, so "/\evil.com" is followed as "//evil.com").
func isSafeRedirect(target string) bool {
	if target == "" || target[0] != '/' {
		return false
	}
	if len(target) == 1 {
		return true
	}
	return target[1] != '/' && target[1] != '\\'
}

// HandleLogin initiates the OAuth2 Authorization Code + PKCE flow.
// It generates a PKCE verifier and state, stores them in an encrypted
// flow cookie, and redirects the user to the auth service's authorize
// endpoint. The optional "return_to" query parameter is preserved so
// the callback can redirect the user back to their original page.
func (c *Client) HandleLogin(w http.ResponseWriter, r *http.Request) {
	verifier := GenerateVerifier()

	state, err := GenerateState()
	if err != nil {
		slog.Error("oidc: generate state", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if !isSafeRedirect(returnTo) {
		returnTo = "/"
	}

	if err := c.SetFlowState(w, &FlowState{
		CodeVerifier: verifier,
		State:        state,
		ReturnTo:     returnTo,
	}); err != nil {
		slog.Error("oidc: set flow state", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Forward selected query params to the authorize endpoint as
	// extension parameters. Currently allowlisted: org_id, which the
	// auth service uses to scope the resulting token. New hints go
	// through this same list so unknown query strings don't leak into
	// the authorize URL accidentally.
	extra := forwardedAuthorizeParams(r.URL.Query())
	http.Redirect(w, r, c.AuthCodeURLWithOpts(state, verifier, extra), http.StatusFound)
}

// forwardedAuthorizeParams is the allowlist of query parameters on
// /login that get forwarded to the authorize endpoint. Kept narrow
// to avoid turning /login into an open pass-through.
//
// Presence-sensitive for org_id: a present-but-empty "org_id=" must
// survive the forward, because the auth service reads it as the
// clear-to-personal signal. An absent org_id leaves the session's
// active_org unchanged. Silently stripping the empty value is what
// caused "switch to Personal" to be a no-op end-to-end.
func forwardedAuthorizeParams(q url.Values) url.Values {
	out := url.Values{}
	for _, k := range []string{"org_id"} {
		if vs, ok := q[k]; ok {
			// Forward even when the value is empty, so the auth
			// service sees `?org_id=` and not the param missing.
			if len(vs) > 0 {
				out.Set(k, vs[0])
			} else {
				out.Set(k, "")
			}
		}
	}
	return out
}

// HandleCallback handles the OAuth2 redirect from the auth service.
// It validates the state, exchanges the authorization code for tokens,
// decodes the JWT claims, stores the session in an encrypted cookie,
// and redirects to the original return_to path.
func (c *Client) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Check for error from auth service.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		slog.Warn("oidc: callback error", "error", errParam, "description", desc)
		http.Redirect(w, r, "/?auth_error="+url.QueryEscape(errParam), http.StatusFound)
		return
	}

	flow, err := c.GetFlowState(r)
	if err != nil {
		slog.Warn("oidc: get flow state", "error", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	ClearFlowState(w)

	// Verify state.
	if r.URL.Query().Get("state") != flow.State {
		slog.Warn("oidc: state mismatch")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Exchange code for tokens.
	code := r.URL.Query().Get("code")
	token, err := c.Exchange(r, code, flow.CodeVerifier)
	if err != nil {
		slog.Error("oidc: token exchange", "error", err)
		http.Redirect(w, r, "/?auth_error=token_exchange_failed", http.StatusFound)
		return
	}

	// Validate the access token is a well-formed JWT before building a
	// session from it. The full claim set (sub/email/org/roles/scopes/...)
	// is decoded by SessionFromToken; name and picture not present in the
	// token are filled by a follow-up /userinfo round-trip in UserFromRequest.
	if _, err := decodeJWTClaims(token.AccessToken); err != nil {
		slog.Error("oidc: decode JWT claims", "error", err)
		http.Redirect(w, r, "/?auth_error=invalid_token", http.StatusFound)
		return
	}

	sess := SessionFromToken(token, c.cfg.SessionTTL)
	if err := c.SetSession(w, sess); err != nil {
		slog.Error("oidc: set session", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	returnTo := flow.ReturnTo
	if !isSafeRedirect(returnTo) {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// HandleLogout clears the local session cookie and redirects to the
// auth service's logout endpoint. The optional "return_to" query
// parameter is forwarded as the post_logout_redirect_uri so the auth
// service can redirect the user back after sign-out.
func (c *Client) HandleLogout(w http.ResponseWriter, r *http.Request) {
	c.ClearSession(w)

	returnTo := r.URL.Query().Get("return_to")
	if !isSafeRedirect(returnTo) {
		returnTo = "/"
	}
	// Build an absolute URL so the auth service can redirect back.
	scheme := "https"
	if r.TLS == nil && strings.HasPrefix(r.Host, "localhost") {
		scheme = "http"
	}
	postLogout := scheme + "://" + r.Host + returnTo
	http.Redirect(w, r, c.AuthURL()+"/logout?post_logout_redirect_uri="+url.QueryEscape(postLogout), http.StatusFound)
}

// UserFromRequest extracts the authenticated user from the session
// cookie. Returns nil if not authenticated or session is invalid.
// When an expired access token is successfully refreshed, the updated
// session is written back to the cookie via w so subsequent requests
// reuse the new token.
func (c *Client) UserFromRequest(w http.ResponseWriter, r *http.Request) *User {
	sess, err := c.GetSession(r)
	if err != nil {
		return nil
	}

	// If the access token is expired, try refreshing.
	if sess.Expiry.Before(time.Now()) && sess.RefreshToken != "" {
		token, err := c.RefreshToken(r, sess.RefreshToken)
		if err != nil {
			slog.Debug("oidc: token refresh failed", "error", err)
			return nil
		}
		sess.AccessToken = token.AccessToken
		sess.Expiry = token.Expiry
		if token.RefreshToken != "" {
			sess.RefreshToken = token.RefreshToken
		}
		// Persist the refreshed session so the next request doesn't
		// need to refresh again.
		if err := c.SetSession(w, sess); err != nil {
			slog.Warn("oidc: failed to persist refreshed session", "error", err)
		}
	}

	// Decode sub + email from the JWT — available without a round-trip
	// and covers the common "tell me who this is" query. Name and
	// picture aren't in the access token; fetch them from /userinfo
	// so downstream RPs can render display_name / avatar_url without
	// knowing about a second endpoint. Userinfo failure falls back to
	// the JWT-only shape: better to return a partial User than nil.
	claims, err := decodeJWTClaims(sess.AccessToken)
	if err != nil {
		return nil
	}

	u := &User{
		Sub:   claims.Sub,
		Email: claims.Email,
		OrgID: claims.OrgID,
	}
	if info, err := c.FetchUserInfo(r, sess.AccessToken); err == nil && info != nil {
		// /userinfo is authoritative for profile fields; overwrite in
		// case the JWT copy is stale or missing.
		if info.Email != "" {
			u.Email = info.Email
		}
		u.Name = info.Name
		u.Picture = info.Picture
		u.AvatarURL = info.AvatarURL
		// auth's /userinfo refreshes org_id from the active SSO
		// session, so prefer it over the JWT copy when present.
		if info.OrgID != "" {
			u.OrgID = info.OrgID
		}
	} else if err != nil {
		// Don't fail the request (a partial User still renders), but make the
		// degradation visible: a 401 here means the access token lacks the
		// issuer audience, so name/avatar silently go missing. See the
		// audience-tagging contract in the auth service bootstrap.
		slog.Warn("oidc: /userinfo failed; display name + avatar will be missing",
			"error", err, "sub", u.Sub)
	}
	return u
}
