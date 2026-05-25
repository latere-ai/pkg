package oidc

import (
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

// BuildMe resolves the full principal for the current request. It is the one
// shared implementation of /me assembly:
//
//   - validate the session cookie; refresh the access token ONCE if expired
//     and persist it (so a request that crosses the expiry boundary doesn't
//     refresh twice or use a stale token on one of the two downstream calls);
//   - decode sub/email/org_id from the JWT (no round-trip);
//   - fetch name + avatar from /userinfo and the org list from /me/orgs using
//     that single fresh token (the lux refresh-once pattern);
//   - derive initials and the active org name.
//
// Returns (nil, nil) when the request is not authenticated. Returns
// (me, nil) on full success. Returns (me, err) when authenticated but a
// downstream call (/userinfo or /me/orgs) degraded — `me` is still populated
// with whatever resolved, and `err` is the (already-logged) first failure so
// the caller can decide whether to surface it. The most common cause of a
// degraded result is an access token whose `aud` lacks the issuer.
func (c *Client) BuildMe(w http.ResponseWriter, r *http.Request) (*Me, error) {
	if c == nil {
		return nil, nil
	}
	sess, err := c.GetSession(r)
	if err != nil || sess == nil {
		return nil, nil // not authenticated
	}

	// Refresh once, up front, and reuse the single fresh token for both
	// downstream calls below.
	if sess.Expiry.Before(time.Now()) && sess.RefreshToken != "" {
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

	claims, cerr := decodeJWTClaims(sess.AccessToken)
	if cerr != nil {
		return nil, nil
	}
	me := &Me{Sub: claims.Sub, Email: claims.Email, OrgID: claims.OrgID}

	var degraded error

	// Name + avatar from /userinfo (best-effort).
	if info, uerr := c.FetchUserInfo(r, sess.AccessToken); uerr == nil && info != nil {
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
	if orgs, oerr := c.FetchOrgs(r.Context(), sess.AccessToken); oerr == nil {
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

// Initials derives a 1–2 character avatar label from a display name, falling
// back to the email local-part, then "?". One shared rule so every service's
// avatar fallback looks the same: two letters from a multi-word name (first +
// last), otherwise the first letter of the single token.
func Initials(name, email string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		if i := strings.IndexByte(email, '@'); i > 0 {
			name = strings.TrimSpace(email[:i])
		}
	}
	if name == "" {
		return "?"
	}
	fields := strings.Fields(name)
	if len(fields) >= 2 {
		return strings.ToUpper(firstRune(fields[0]) + firstRune(fields[len(fields)-1]))
	}
	return strings.ToUpper(firstRune(fields[0]))
}

func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return ""
}
