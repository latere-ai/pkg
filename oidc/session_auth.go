// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"time"

	"latere.ai/x/pkg/authkit"
)

// SessionAuthenticator adapts the encrypted session cookie to the
// authkit.Authenticator interface. It reads the cookie via Client.GetSession,
// trusts the (already-encrypted-and-MAC'd) embedded user fields, and stamps
// AuthMethod = authkit.MethodCookie.
//
// Construction with a nil Client yields an authenticator that always returns
// authkit.ErrUnauthenticated, so callers composing a Chain do not need a nil
// guard when cookie auth is optional.
type SessionAuthenticator struct {
	Client *Client
}

// NewSessionAuthenticator wires a cookie-session authenticator backed by c.
// c may be nil; see SessionAuthenticator for nil-handling semantics.
func NewSessionAuthenticator(c *Client) *SessionAuthenticator {
	return &SessionAuthenticator{Client: c}
}

func (s *SessionAuthenticator) Authenticate(r *http.Request) (authkit.Identity, error) {
	if s == nil || s.Client == nil {
		return authkit.Identity{}, authkit.ErrUnauthenticated
	}
	sess, err := s.Client.GetSession(r)
	if err != nil || sess == nil {
		return authkit.Identity{}, authkit.ErrUnauthenticated
	}
	now := time.Now()
	if sess.User.Sub == "" || sess.Expiry.IsZero() || !sess.Expiry.After(now) ||
		(!sess.SessionExpiry.IsZero() && !sess.SessionExpiry.After(now)) {
		return authkit.Identity{}, authkit.ErrUnauthenticated
	}
	return authkit.Identity{
		Sub:           sess.User.Sub,
		OrgID:         sess.User.OrgID,
		Email:         sess.User.Email,
		PrincipalType: authkit.PrincipalUser,
		IsSuperadmin:  sess.User.IsSuperadmin,
		Scopes:        sess.User.Scopes,
		Roles:         sess.User.OrgRoles,
		ClientID:      sess.User.ClientID,
		TokenID:       sess.User.Sub,
		AuthMethod:    authkit.MethodCookie,
	}, nil
}
