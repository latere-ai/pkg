package authkit

import (
	"os"
	"strings"

	"latere.ai/x/pkg/oidc"
)

// LoadConfigWithPrefix reads an oidc.Config from environment variables
// consulting "<PREFIX>_AUTH_*" first and falling back to plain "AUTH_*".
// An empty prefix is equivalent to oidc.LoadConfig().
//
// Intended for cutover periods when a relying party still has its legacy
// per-product env-var prefix configured in production but wants to migrate
// to the unified AUTH_* names. Once the legacy vars are removed from the
// deploy config, callers switch back to oidc.LoadConfig().
//
// The fallback is per-variable: if "<PREFIX>_AUTH_URL" is set but
// "<PREFIX>_AUTH_CLIENT_ID" is not, the prefixed URL wins and the
// unprefixed CLIENT_ID is used.
func LoadConfigWithPrefix(prefix string) oidc.Config {
	base := oidc.LoadConfig()
	if prefix == "" {
		return base
	}
	p := prefix + "_"
	if v := os.Getenv(p + "AUTH_URL"); v != "" {
		base.AuthURL = v
	}
	if v := os.Getenv(p + "AUTH_CLIENT_ID"); v != "" {
		base.ClientID = v
	}
	if v := os.Getenv(p + "AUTH_CLIENT_SECRET"); v != "" {
		base.ClientSecret = v
	}
	if v := os.Getenv(p + "AUTH_REDIRECT_URL"); v != "" {
		base.RedirectURL = v
	}
	if v := os.Getenv(p + "AUTH_COOKIE_KEY"); v != "" {
		base.CookieKey = v
	}
	if v := os.Getenv(p + "AUTH_AUDIENCE"); v != "" {
		base.Audience = v
	}
	if v := os.Getenv(p + "AUTH_SCOPES"); v != "" {
		base.Scopes = splitConfigScopes(v)
	}
	return base
}

// splitConfigScopes splits the AUTH_SCOPES env-var format the same way
// pkg/oidc.LoadConfig does (comma or whitespace separated, deduped).
// Duplicated here because the helper inside pkg/oidc is unexported.
func splitConfigScopes(s string) []string {
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
	return out
}
