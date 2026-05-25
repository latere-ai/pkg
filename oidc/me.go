package oidc

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Me is the canonical principal + org context every Latere relying party
// returns from its /api/me endpoint. It is the single source of truth for
// "who is signed in, and what orgs can they switch to" so that login
// validation, profile resolution, and the org list are built identically
// across services. Apps map this into their own JSON shape and add only their
// app-specific extras (CSRF token, is_superadmin, quota, …).
type Me struct {
	Sub       string     `json:"sub"`
	Email     string     `json:"email"`
	Name      string     `json:"name"`
	AvatarURL string     `json:"avatar_url"`
	Initials  string     `json:"initials"`
	OrgID     string     `json:"org_id"`
	OrgName   string     `json:"org_name"` // resolved from Orgs by OrgID; "" == personal
	Orgs      []OrgEntry `json:"orgs"`
}

// BuildMe resolves the full principal for a cookie-session request: it
// validates the session cookie, refreshes the access token ONCE if expired
// (persisting it so a request crossing the expiry boundary doesn't refresh
// twice or use a stale token on one of the two downstream calls), then defers
// to BuildMeFromToken for the assembly. Use this from apps that store the
// session in the pkg/oidc cookie (e.g. lectio, latere-ai).
//
// Returns (nil, nil) when not authenticated; (me, nil) on success; (me, err)
// when authenticated but a downstream call degraded (see BuildMeFromToken).
func (c *Client) BuildMe(w http.ResponseWriter, r *http.Request) (*Me, error) {
	if c == nil {
		return nil, nil
	}
	sess, err := c.GetSession(r)
	if err != nil || sess == nil {
		return nil, nil // not authenticated
	}

	// Refresh once, up front, and reuse the single fresh token below.
	if sess.Expiry.Before(time.Now()) {
		if sess.RefreshToken == "" {
			// Dead session: the access token expired and there's no refresh
			// token to renew it. Clear the stale cookie and treat the request
			// as logged out so the SPA re-authenticates, rather than returning
			// a stale identity whose /userinfo + /me/orgs calls will 401.
			ClearSession(w)
			return nil, nil
		}
		token, rerr := c.RefreshToken(r, sess.RefreshToken)
		if rerr != nil {
			slog.Debug("oidc: token refresh failed for /me", "error", rerr)
			return nil, nil // can't recover the session → treat as logged out
		}
		sess.AccessToken = token.AccessToken
		sess.Expiry = token.Expiry
		if token.RefreshToken != "" {
			sess.RefreshToken = token.RefreshToken
		}
		if serr := c.SetSession(w, sess); serr != nil {
			slog.Warn("oidc: failed to persist refreshed /me session", "error", serr)
		}
	}

	return c.BuildMeFromToken(r.Context(), sess.AccessToken)
}

// BuildMeFromToken is the single shared /me assembly, independent of how the
// caller stores its session — apps with a server-side session store (cella),
// authkit middleware (lux), or a cookie (lectio/latere-ai) all funnel their
// access token through here so identity, profile, orgs, initials and the
// active org name are resolved IDENTICALLY:
//
//   - decode sub/email/org_id from the JWT (no round-trip);
//   - fetch name + avatar from /userinfo and the org list from /me/orgs with
//     the SAME token;
//   - derive initials and the active org name.
//
// Returns (nil, nil) if the token can't be decoded (treat as unauthenticated);
// (me, nil) on success; (me, err) when a downstream call (/userinfo or
// /me/orgs) degraded — `me` is still populated with whatever resolved and
// `err` is the (already-logged) first failure. The usual cause of a degraded
// result is a token whose `aud` lacks the issuer.
func (c *Client) BuildMeFromToken(ctx context.Context, accessToken string) (*Me, error) {
	if c == nil {
		return nil, nil
	}
	claims, cerr := decodeJWTClaims(accessToken)
	if cerr != nil {
		return nil, nil
	}
	me := &Me{Sub: claims.Sub, Email: claims.Email, OrgID: claims.OrgID}

	var degraded error

	// Name + avatar from /userinfo (best-effort).
	if info, uerr := c.FetchUserInfoContext(ctx, accessToken); uerr == nil && info != nil {
		if info.Email != "" {
			me.Email = info.Email
		}
		me.Name = info.Name
		if info.AvatarURL != "" {
			me.AvatarURL = info.AvatarURL
		} else {
			me.AvatarURL = info.Picture
		}
		if info.OrgID != "" {
			me.OrgID = info.OrgID
		}
	} else if uerr != nil {
		// A 401 here means the access token lacks the issuer audience: name +
		// avatar silently go missing without this log.
		slog.Warn("oidc: /userinfo failed; display name + avatar will be missing",
			"error", uerr, "sub", me.Sub)
		degraded = uerr
	}

	// Org memberships from /me/orgs (best-effort), using the SAME token.
	if orgs, oerr := c.FetchOrgs(ctx, accessToken); oerr == nil {
		me.Orgs = orgs
		for _, o := range orgs {
			if o.ID == me.OrgID {
				me.OrgName = o.Name
				break
			}
		}
	} else {
		slog.Warn("oidc: /me/orgs failed; org switcher will be empty",
			"error", oerr, "sub", me.Sub)
		if degraded == nil {
			degraded = oerr
		}
	}

	me.Initials = Initials(me.Name, me.Email)
	return me, degraded
}

// SwitchOrgRedirect implements the shared org-switch flow: clear the current
// session and return the login URL the SPA should navigate to. The chosen
// org_id is forwarded to /authorize, which mints a token scoped to that org
// (empty org_id == personal). Centralised so every service switches orgs
// identically. `returnTo` is where login should land after the switch.
func SwitchOrgRedirect(w http.ResponseWriter, orgID, returnTo string) string {
	ClearSession(w)
	url := "/login?return_to=" + returnTo
	if orgID != "" {
		url += "&org_id=" + orgID
	}
	return url
}

// Initials derives a two-letter avatar monogram from a display name, falling
// back to the email local-part, then "?". One shared rule so every service's
// avatar fallback is identical: first + last initial of a multi-word name, the
// first two letters of a single-word name, and the email local-part (split on
// dots, e.g. "first.last" -> "FL") when there's no name. The SPA renders this
// only when no avatar_url is available.
func Initials(name, email string) string {
	pick := func(s string) string {
		fields := strings.Fields(strings.TrimSpace(s))
		if len(fields) == 0 {
			return ""
		}
		if len(fields) == 1 {
			r := []rune(fields[0])
			if len(r) >= 2 {
				return strings.ToUpper(string(r[:2]))
			}
			return strings.ToUpper(string(r))
		}
		return strings.ToUpper(string([]rune(fields[0])[:1]) + string([]rune(fields[len(fields)-1])[:1]))
	}
	if v := pick(name); v != "" {
		return v
	}
	local := email
	if i := strings.IndexByte(email, '@'); i > 0 {
		local = email[:i]
	}
	if v := pick(strings.ReplaceAll(local, ".", " ")); v != "" {
		return v
	}
	return "?"
}
