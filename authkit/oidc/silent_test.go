// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestHandleLoginForwardsPrompt: prompt is forwarded with a value OpenID
// Connect defines and dropped otherwise, and prompt=none marks the flow
// silent.
func TestHandleLoginForwardsPrompt(t *testing.T) {
	c := testClient(t)
	for _, tc := range []struct {
		query, prompt string
		silent        bool
	}{
		{"prompt=none", "none", true},
		{"prompt=login", "login", false},
		{"prompt=bogus", "", false},
		{"", "", false},
	} {
		w := httptest.NewRecorder()
		c.HandleLogin(w, httptest.NewRequest(http.MethodGet, "/login?return_to=/s/1%3Fq%3Dhi&"+tc.query, nil))
		loc, err := url.Parse(w.Result().Header.Get("Location"))
		if err != nil {
			t.Fatalf("%q: %v", tc.query, err)
		}
		if got := loc.Query().Get("prompt"); got != tc.prompt {
			t.Errorf("%q: prompt = %q, want %q", tc.query, got, tc.prompt)
		}
		flow, err := c.GetFlowState(requestWith(w.Result().Cookies()))
		if err != nil {
			t.Fatalf("%q: GetFlowState: %v", tc.query, err)
		}
		if flow.Silent != tc.silent || flow.ReturnTo != "/s/1?q=hi" {
			t.Errorf("%q: flow = %+v, want silent %v and the address kept", tc.query, flow, tc.silent)
		}
	}
}

// TestASilentSignInTheIssuerRefusesGoesBackQuietly: login_required on a
// silent flow returns to where the person was, with no error in the address,
// and clears the flow. The same error on a flow that is not silent, or with
// a state the flow does not hold, is the error it always was.
func TestASilentSignInTheIssuerRefusesGoesBackQuietly(t *testing.T) {
	c := testClient(t)
	flowFor := func(silent bool) []*http.Cookie {
		w := httptest.NewRecorder()
		if err := c.SetFlowState(w, &FlowState{CodeVerifier: "v", State: "st", ReturnTo: "/s/1?q=hi", Silent: silent}); err != nil {
			t.Fatalf("SetFlowState: %v", err)
		}
		return w.Result().Cookies()
	}
	for _, tc := range []struct {
		name   string
		silent bool
		state  string
		want   string
	}{
		{"silent", true, "st", "/s/1?q=hi"},
		{"not silent", false, "st", "/?auth_error=login_required"},
		{"another state", true, "other", "/?auth_error=login_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/callback?error=login_required&state="+tc.state, nil)
			for _, ck := range flowFor(tc.silent) {
				r.AddCookie(ck)
			}
			w := httptest.NewRecorder()
			c.HandleCallback(w, r)
			if got := w.Result().Header.Get("Location"); got != tc.want {
				t.Errorf("Location = %q, want %q", got, tc.want)
			}
			clears := false
			for _, ck := range w.Result().Cookies() {
				clears = clears || (strings.Contains(ck.Name, "flow") && ck.MaxAge < 0)
			}
			if quiet := tc.want == "/s/1?q=hi"; clears != quiet {
				t.Errorf("flow cleared = %v, want %v", clears, quiet)
			}
		})
	}

	// A silent flow whose return address is unsafe goes to the root.
	w := httptest.NewRecorder()
	if err := c.SetFlowState(w, &FlowState{State: "st", ReturnTo: "//evil.example", Silent: true}); err != nil {
		t.Fatalf("SetFlowState: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/callback?error=login_required&state=st", nil)
	for _, ck := range w.Result().Cookies() {
		r.AddCookie(ck)
	}
	out := httptest.NewRecorder()
	c.HandleCallback(out, r)
	if got := out.Result().Header.Get("Location"); got != "/" {
		t.Errorf("Location = %q, want /", got)
	}
}

// FuzzForwardedPrompt: whatever /login is given, the authorize request
// carries a prompt only with a value OpenID Connect defines, and nothing
// /login was given beyond org_id and prompt.
func FuzzForwardedPrompt(f *testing.F) {
	for _, raw := range []string{"prompt=none", "prompt=login&x=1", "prompt=none%20login", "prompt=", "org_id=&prompt=consent"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		q, err := url.ParseQuery(raw)
		if err != nil {
			t.Skip()
		}
		out := forwardedAuthorizeParams(q)
		if p, ok := out["prompt"]; ok && (len(p) != 1 || !prompts[p[0]]) {
			t.Errorf("forwarded prompt %q from %q", p, raw)
		}
		for k := range out {
			if k != "prompt" && k != "org_id" {
				t.Errorf("forwarded %q from %q", k, raw)
			}
		}
	})
}
