// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"cmp"

	"latere.ai/x/pkg/authkit"
)

// Built-in ClaimsMapper adapters for the IDPs latere services deploy against.
// Each maps an IDP's identity and (where available) role/group claims onto the
// portable User. Authentication is portable; these adapters localise the
// non-portable authorization shape per IDP.

// KeycloakMapper maps Keycloak claims. Keycloak puts realm roles under
// realm_access.roles, on the access token by default and on the ID token only
// when the client has a realm-roles mapper with "add to ID token" enabled.
// Union both so a role holder is recognised regardless of the client's mapper
// config (accessClaims is nil when the access token is not a verifiable JWT).
type KeycloakMapper struct{}

func (KeycloakMapper) Map(idClaims, accessClaims map[string]any) (User, error) {
	roles := realmRoles(idClaims)
	if accessClaims != nil {
		roles = unionStrings(roles, realmRoles(accessClaims))
	}
	return User{
		Sub:   stringClaim(idClaims["sub"]),
		Email: stringClaim(idClaims["email"]),
		Roles: roles,
		Name:  cmp.Or(stringClaim(idClaims["name"]), stringClaim(idClaims["preferred_username"])),
	}, nil
}

// realmRoles extracts realm_access.roles from a Keycloak claim map.
func realmRoles(claims map[string]any) []string {
	ra, ok := claims["realm_access"].(map[string]any)
	if !ok {
		return nil
	}
	return stringsClaim(ra["roles"])
}

// GoogleMapper maps Google ID-token claims. Google is identity-only: it issues
// no roles, and its access tokens are opaque (so accessClaims is always nil).
// Roles is therefore empty — a service that needs authorization derives it from
// its own store. The hosted-domain claim (hd) is left in User.Raw for
// domain gating.
type GoogleMapper struct{}

func (GoogleMapper) Map(idClaims, _ map[string]any) (User, error) {
	return User{
		Identity: authkit.Identity{
			Sub:   stringClaim(idClaims["sub"]),
			Email: stringClaim(idClaims["email"]),
			// Roles intentionally nil: Google provides identity only.
		},
		Name: stringClaim(idClaims["name"]),
	}, nil
}

// CognitoMapper maps AWS Cognito claims. Cognito puts group membership in
// cognito:groups (on both ID and access tokens) and the username in
// cognito:username.
type CognitoMapper struct{}

func (CognitoMapper) Map(idClaims, accessClaims map[string]any) (User, error) {
	roles := stringsClaim(idClaims["cognito:groups"])
	if accessClaims != nil {
		roles = unionStrings(roles, stringsClaim(accessClaims["cognito:groups"]))
	}
	return User{
		Sub:   stringClaim(idClaims["sub"]),
		Email: stringClaim(idClaims["email"]),
		Roles: roles,
		Name:  cmp.Or(stringClaim(idClaims["name"]), stringClaim(idClaims["cognito:username"])),
	}, nil
}
