package authkit

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// randRead is the source of randomness for CSRF tokens. Tests can replace it
// to exercise error paths without adding external dependencies.
var randRead = func(b []byte) (int, error) {
	return rand.Read(b)
}

const csrfHeader = "X-CSRF-Token"
const csrfField = "csrf_token"

// CSRFIssue mints a fresh CSRF token, sets it as a cookie with the given
// cookieName, and returns the value to embed in the form or SPA state.
// Re-issuing on every render is fine — only the value at submit time has to
// match.
//
// cookieName should be product-specific (e.g. "__cella_csrf", "__topos_csrf")
// so products sharing a domain do not stomp each other's cookies.
// secure should be true in production (HTTPS) and false in local dev.
func CSRFIssue(w http.ResponseWriter, cookieName string, secure bool) (string, error) {
	tok, err := randomURLToken(16)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: false, // form template reads it
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})
	return tok, nil
}

// CSRFValidate compares the cookie against either the X-CSRF-Token
// header (the SPA's path) or the csrf_token form field (legacy form
// submits). Returns false on miss; does NOT write a response — the
// caller decides how to surface the failure.
func CSRFValidate(r *http.Request, cookieName string) bool {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return false
	}
	if h := r.Header.Get(csrfHeader); h != "" {
		return h == c.Value
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	return r.PostFormValue(csrfField) == c.Value
}

// CSRFHeaderName returns the expected request header name ("X-CSRF-Token").
func CSRFHeaderName() string { return csrfHeader }

// CSRFFieldName returns the form field name ("csrf_token").
func CSRFFieldName() string { return csrfField }

// randomURLToken returns a URL-safe random token built from n random bytes
// encoded with base64.RawURLEncoding. Inlined from sandbox's cryptoutil to
// avoid importing a sandbox-internal package.
func randomURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
