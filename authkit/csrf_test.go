package authkit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testCookieName = "__test_csrf"

func TestCSRFIssueSetsCookie(t *testing.T) {
	w := httptest.NewRecorder()
	tok, err := CSRFIssue(w, testCookieName, false)
	if err != nil {
		t.Fatalf("CSRFIssue: %v", err)
	}
	if tok == "" {
		t.Fatal("token is empty")
	}
	resp := w.Result()
	cookies := resp.Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == testCookieName {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatalf("cookie %q not set", testCookieName)
	}
	if found.Value != tok {
		t.Fatalf("cookie value %q != token %q", found.Value, tok)
	}
}

// TestCSRFIssueIsSessionCookie pins the cookie to browser-session scope. A
// finite Max-Age expires under a dashboard tab left open past it, dropping the
// X-CSRF-Token header and failing every state-changing request with a csrf
// error while the login session is still valid.
func TestCSRFIssueIsSessionCookie(t *testing.T) {
	w := httptest.NewRecorder()
	if _, err := CSRFIssue(w, testCookieName, false); err != nil {
		t.Fatalf("CSRFIssue: %v", err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name != testCookieName {
			continue
		}
		if c.MaxAge != 0 {
			t.Fatalf("Max-Age = %d, want 0 (session cookie)", c.MaxAge)
		}
		if !c.Expires.IsZero() {
			t.Fatalf("Expires = %v, want unset (session cookie)", c.Expires)
		}
		return
	}
	t.Fatalf("cookie %q not set", testCookieName)
}

func TestCSRFIssueSecureFlag(t *testing.T) {
	w := httptest.NewRecorder()
	_, err := CSRFIssue(w, testCookieName, true)
	if err != nil {
		t.Fatal(err)
	}
	resp := w.Result()
	for _, c := range resp.Cookies() {
		if c.Name == testCookieName {
			if !c.Secure {
				t.Fatal("Secure flag not set")
			}
			return
		}
	}
	t.Fatal("cookie not found")
}

func TestCSRFValidateHeader(t *testing.T) {
	const tok = "abc123"
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: testCookieName, Value: tok})
	r.Header.Set("X-CSRF-Token", tok)
	if !CSRFValidate(r, testCookieName) {
		t.Fatal("expected true for matching header")
	}
}

func TestCSRFValidateHeaderMismatch(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: testCookieName, Value: "tok1"})
	r.Header.Set("X-CSRF-Token", "tok2")
	if CSRFValidate(r, testCookieName) {
		t.Fatal("expected false for mismatched header")
	}
}

func TestCSRFValidateFormField(t *testing.T) {
	const tok = "formtok"
	body := strings.NewReader("csrf_token=" + tok)
	r := httptest.NewRequest(http.MethodPost, "/", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: testCookieName, Value: tok})
	if !CSRFValidate(r, testCookieName) {
		t.Fatal("expected true for matching form field")
	}
}

func TestCSRFValidateFormFieldMismatch(t *testing.T) {
	body := strings.NewReader("csrf_token=wrong")
	r := httptest.NewRequest(http.MethodPost, "/", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: testCookieName, Value: "correct"})
	if CSRFValidate(r, testCookieName) {
		t.Fatal("expected false for mismatched form field")
	}
}

func TestCSRFValidateNoCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("X-CSRF-Token", "tok")
	if CSRFValidate(r, testCookieName) {
		t.Fatal("expected false when cookie missing")
	}
}

func TestCSRFValidateEmptyCookieValue(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: testCookieName, Value: ""})
	r.Header.Set("X-CSRF-Token", "")
	if CSRFValidate(r, testCookieName) {
		t.Fatal("expected false for empty cookie value")
	}
}

func TestCSRFValidateMalformedFormBody(t *testing.T) {
	// %ZZ is not valid URL encoding → ParseForm returns an error.
	body := strings.NewReader("%ZZ=invalid")
	r := httptest.NewRequest(http.MethodPost, "/", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: testCookieName, Value: "tok"})
	// No X-CSRF-Token header, so it falls through to form parsing.
	// ParseForm fails → CSRFValidate returns false.
	if CSRFValidate(r, testCookieName) {
		t.Fatal("expected false for malformed form body")
	}
}

func TestCSRFValidateDifferentCookieName(t *testing.T) {
	const tok = "mytok"
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "__cella_csrf", Value: tok})
	r.Header.Set("X-CSRF-Token", tok)
	// Validate with a different cookie name → should not find cookie.
	if CSRFValidate(r, "__topos_csrf") {
		t.Fatal("expected false when cookie name differs")
	}
}

func TestCSRFHelperFunctions(t *testing.T) {
	if CSRFHeaderName() != "X-CSRF-Token" {
		t.Fatalf("CSRFHeaderName = %q", CSRFHeaderName())
	}
	if CSRFFieldName() != "csrf_token" {
		t.Fatalf("CSRFFieldName = %q", CSRFFieldName())
	}
}

func TestCSRFIssueRandError(t *testing.T) {
	orig := randRead
	randRead = func(b []byte) (int, error) {
		return 0, errors.New("rand failed")
	}
	t.Cleanup(func() { randRead = orig })

	w := httptest.NewRecorder()
	_, err := CSRFIssue(w, testCookieName, false)
	if err == nil {
		t.Fatal("expected error when rand fails")
	}
}

// ── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzCSRFValidate(f *testing.F) {
	// Seed: (cookieValue, headerValue)
	f.Add("abc", "abc")
	f.Add("abc", "xyz")
	f.Add("", "")
	f.Add("", "abc")
	f.Add("abc", "")
	f.Add("longtoken-xyz-123", "longtoken-xyz-123")

	f.Fuzz(func(t *testing.T, cookieVal, headerVal string) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if cookieVal != "" {
			r.AddCookie(&http.Cookie{Name: testCookieName, Value: cookieVal})
		}
		if headerVal != "" {
			r.Header.Set("X-CSRF-Token", headerVal)
		}

		result := CSRFValidate(r, testCookieName)

		// Invariant: empty cookie must always return false.
		if cookieVal == "" && result {
			t.Fatalf("empty cookie returned true")
		}
	})
}
