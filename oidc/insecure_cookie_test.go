// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestInsecureCookies_DropHostPrefix is the regression guard for the
// localhost-HTTP browser flow. Under InsecureCookies the flow and session
// cookies must shed the "__Host-" prefix, because browsers silently discard a
// __Host-* cookie that lacks the Secure attribute. Both must still round-trip
// set -> get, and the clear must target the same stripped name.
func TestInsecureCookies_DropHostPrefix(t *testing.T) {
	c := New(Config{
		AuthURL:         "https://auth.example.com",
		ClientID:        "wallfacer",
		ClientSecret:    "sec", // derives a cookie key
		RedirectURL:     "http://localhost:8080/callback",
		InsecureCookies: true,
	})
	if c == nil {
		t.Fatal("New returned nil")
	}

	// Flow cookie: name stripped, not Secure, round-trips.
	wf := httptest.NewRecorder()
	if err := c.SetFlowState(wf, &FlowState{State: "s", CodeVerifier: "v"}); err != nil {
		t.Fatalf("SetFlowState: %v", err)
	}
	flow := wf.Result().Cookies()
	if len(flow) != 1 {
		t.Fatalf("flow cookies = %d, want 1", len(flow))
	}
	if flow[0].Name != "latere-flow" {
		t.Errorf("flow cookie name = %q, want latere-flow", flow[0].Name)
	}
	if flow[0].Secure {
		t.Error("flow cookie must not be Secure under InsecureCookies")
	}
	rf := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rf.AddCookie(flow[0])
	gotFlow, err := c.GetFlowState(rf)
	if err != nil {
		t.Fatalf("GetFlowState: %v", err)
	}
	if gotFlow.State != "s" {
		t.Errorf("flow state = %q, want s", gotFlow.State)
	}

	// Session cookie: name stripped, not Secure, round-trips.
	ws := httptest.NewRecorder()
	if err := c.SetSession(ws, &Session{AccessToken: "tok"}); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	sess := ws.Result().Cookies()[0]
	if sess.Name != "latere-session-v2" {
		t.Errorf("session cookie name = %q, want latere-session-v2", sess.Name)
	}
	if sess.Secure {
		t.Error("session cookie must not be Secure under InsecureCookies")
	}
	rs := httptest.NewRequest(http.MethodGet, "/", nil)
	rs.AddCookie(sess)
	gotSess, err := c.GetSession(rs)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if gotSess.AccessToken != "tok" {
		t.Errorf("session token = %q, want tok", gotSess.AccessToken)
	}

	// Clear targets the stripped name and drops Secure.
	wc := httptest.NewRecorder()
	c.ClearSession(wc)
	clr := wc.Result().Cookies()[0]
	if clr.Name != "latere-session-v2" || clr.Secure || clr.MaxAge != -1 {
		t.Errorf("clear cookie = %+v, want name=latere-session-v2 secure=false maxAge=-1", clr)
	}
}
