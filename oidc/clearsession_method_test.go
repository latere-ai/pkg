// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http/httptest"
	"testing"
)

// TestClientClearSessionHonorsConfig verifies the method clears the client's
// configured cookie name and drops Secure when InsecureCookies is set.
func TestClientClearSessionHonorsConfig(t *testing.T) {
	c := newConfiguredClient(t, 0)
	w := httptest.NewRecorder()
	c.ClearSession(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	ck := cookies[0]
	if ck.Name != "__custom_session" {
		t.Errorf("name = %q, want __custom_session", ck.Name)
	}
	if ck.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", ck.MaxAge)
	}
	if ck.Secure {
		t.Error("expected Secure dropped for InsecureCookies")
	}
}

// TestPackageClearSessionUnchanged is the regression guard for the three
// consumers that call the package-level func directly: it must still clear the
// default __Host- cookie with Secure set.
func TestPackageClearSessionUnchanged(t *testing.T) {
	w := httptest.NewRecorder()
	ClearSession(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	ck := cookies[0]
	if ck.Name != SessionCookieName {
		t.Errorf("name = %q, want %q", ck.Name, SessionCookieName)
	}
	if ck.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", ck.MaxAge)
	}
	if !ck.Secure {
		t.Error("package ClearSession must keep Secure set")
	}
}

// TestClientClearSessionDefaultConfig confirms a default-config client clears
// the default cookie with Secure (matching the package func).
func TestClientClearSessionDefaultConfig(t *testing.T) {
	c := testClient(t)
	w := httptest.NewRecorder()
	c.ClearSession(w)

	ck := w.Result().Cookies()[0]
	if ck.Name != SessionCookieName || !ck.Secure || ck.MaxAge != -1 {
		t.Errorf("default-config clear = %+v", ck)
	}
}
