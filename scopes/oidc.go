package scopes

// OpenID Connect / OAuth 2.0 standard scopes.
//
// openid is required for any OIDC flow; email and profile request the
// matching userinfo claims; offline_access asks for a refresh token.
var (
	OpenID        = Scope{Name: "openid", Description: "OIDC sign-in (required for any OIDC flow).", Category: "OIDC"}
	Email         = Scope{Name: "email", Description: "User's email and email_verified claim.", Category: "OIDC"}
	Profile       = Scope{Name: "profile", Description: "User's name, picture, and locale claims.", Category: "OIDC"}
	OfflineAccess = Scope{Name: "offline_access", Description: "Issue a refresh token alongside the access token.", Category: "OIDC"}
)

func oidc() []Scope { return []Scope{OpenID, Email, Profile, OfflineAccess} }
