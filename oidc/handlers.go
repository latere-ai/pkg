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
)

// jwtClaims holds the subset of JWT access token claims we extract.
type jwtClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
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

// isSafeRedirect returns true when target is a relative path that won't
// redirect to an external host.
func isSafeRedirect(target string) bool {
	return target != "" && target[0] == '/' && (len(target) == 1 || target[1] != '/')
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

	// Decode claims from the JWT access token.
	claims, err := decodeJWTClaims(token.AccessToken)
	if err != nil {
		slog.Error("oidc: decode JWT claims", "error", err)
		http.Redirect(w, r, "/?auth_error=invalid_token", http.StatusFound)
		return
	}

	// Store session with token + claims.
	sess := &Session{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		User: User{
			Sub:   claims.Sub,
			Email: claims.Email,
		},
	}
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
	ClearSession(w)

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
	}
	if info, err := c.FetchUserInfo(r, sess.AccessToken); err == nil && info != nil {
		// /userinfo is authoritative for profile fields; overwrite in
		// case the JWT copy is stale or missing.
		if info.Email != "" {
			u.Email = info.Email
		}
		u.Name = info.Name
		u.Picture = info.Picture
	}
	return u
}
