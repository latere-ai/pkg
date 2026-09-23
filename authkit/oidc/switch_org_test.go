// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// claimsJWT is an unsigned JWT whose payload is claims; SwitchOrg reads the
// organization and roles off the token the issuer just answered.
func claimsJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

// switchOrgIssuer answers the refresh-token grant with a token in the org the
// request named, and records the form it received.
func switchOrgIssuer(t *testing.T, got *map[string][]string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		form := map[string][]string(r.PostForm)
		if user, pass, ok := r.BasicAuth(); ok {
			form["basic"] = []string{user, pass}
		}
		*got = form
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		roles := []string{}
		if r.PostForm.Get("org_id") != "" {
			roles = []string{"member"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": claimsJWT(t, map[string]any{
				"sub": "u1", "org_id": r.PostForm.Get("org_id"), "roles": roles,
			}),
			"refresh_token": "rt-rotated",
			"expires_in":    900,
			"token_type":    "bearer",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSwitchOrgMovesTheSessionIntoTheOrg(t *testing.T) {
	var form map[string][]string
	srv := switchOrgIssuer(t, &form, http.StatusOK)
	c := New(Config{AuthURL: srv.URL, ClientID: "platform-web"})
	sess := &Session{AccessToken: "old", RefreshToken: "rt-1", User: User{Name: "Ada"}}

	next, err := c.SwitchOrg(context.Background(), sess, "org-1")
	if err != nil {
		t.Fatalf("SwitchOrg: %v", err)
	}
	if form["grant_type"][0] != "refresh_token" || form["refresh_token"][0] != "rt-1" ||
		form["org_id"][0] != "org-1" || form["client_id"][0] != "platform-web" {
		t.Fatalf("the issuer received %v", form)
	}
	if next.User.OrgID != "org-1" || !slices.Equal(next.User.Roles, []string{"member"}) {
		t.Fatalf("the switched session names %q %v", next.User.OrgID, next.User.Roles)
	}
	if next.RefreshToken != "rt-rotated" || next.AccessToken == "old" {
		t.Fatalf("the switched session keeps the old tokens: %+v", next)
	}
	if next.User.Name != "Ada" {
		t.Fatal("the switch dropped the profile fields the session carried")
	}
	if d := time.Until(next.Expiry); d < 14*time.Minute || d > 16*time.Minute {
		t.Fatalf("expiry in %v, want the issuer's 900s", d)
	}
	if sess.AccessToken != "old" || sess.RefreshToken != "rt-1" {
		t.Fatal("SwitchOrg changed the session it was given")
	}
}

func TestSwitchOrgToPersonalSendsAnEmptyOrg(t *testing.T) {
	var form map[string][]string
	srv := switchOrgIssuer(t, &form, http.StatusOK)
	c := New(Config{AuthURL: srv.URL, ClientID: "cid", ClientSecret: "sec"})
	next, err := c.SwitchOrg(context.Background(), &Session{RefreshToken: "rt"}, "")
	if err != nil {
		t.Fatalf("SwitchOrg: %v", err)
	}
	values, present := form["org_id"]
	if !present || len(values) != 1 || values[0] != "" {
		t.Fatalf("org_id = %v present=%v, want present and empty", values, present)
	}
	if _, inForm := form["client_id"]; inForm {
		t.Fatal("a confidential client sent its id in the form instead of Basic")
	}
	if b := form["basic"]; len(b) != 2 || b[0] != "cid" || b[1] != "sec" {
		t.Fatalf("basic = %v", b)
	}
	if next.User.OrgID != "" || len(next.User.Roles) != 0 {
		t.Fatalf("personal context = %q %v", next.User.OrgID, next.User.Roles)
	}
}

func TestSwitchOrgRefusalLeavesTheSession(t *testing.T) {
	var form map[string][]string
	srv := switchOrgIssuer(t, &form, http.StatusBadRequest)
	c := New(Config{AuthURL: srv.URL, ClientID: "cid"})
	if _, err := c.SwitchOrg(context.Background(), &Session{RefreshToken: "rt"}, "not-mine"); !errors.Is(err, ErrSwitchOrgRefused) {
		t.Fatalf("err = %v, want ErrSwitchOrgRefused", err)
	}
	if _, err := c.SwitchOrg(context.Background(), &Session{}, "org"); err == nil {
		t.Fatal("a session with no refresh token was switched")
	}
}
