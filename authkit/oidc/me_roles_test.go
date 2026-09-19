// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit"
)

// Exercise the cookie -> refresh -> profile round trip with roles revoked
// since login. The stale cookie and userinfo must not restore the old role.
func TestBuildMeCurrentRoles(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "refreshed"}[refresh], func(t *testing.T) {
			fresh := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1","org_id":"org-1","roles":["member"]}`)) + ".signature"
			var mints, profiles, orgs atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/token":
					if mints.Add(1) != 1 || r.FormValue("refresh_token") != "rt" {
						t.Error("refresh repeated or wrong token")
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fresh, "token_type": "Bearer", "refresh_token": "rotated", "expires_in": 3600})
				case "/userinfo", "/me/orgs":
					if r.Header.Get("Authorization") != "Bearer "+fresh {
						t.Error("profile used stale token")
					}
					if r.URL.Path == "/userinfo" {
						profiles.Add(1)
						_, _ = w.Write([]byte(`{"sub":"u1","name":"Ada","roles":["platform_admin"]}`))
					} else {
						orgs.Add(1)
						_, _ = w.Write([]byte(`[]`))
					}
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(ts.Close)
			c := newPublicClient(t, ts.URL)
			sess := &Session{AccessToken: fresh, Expiry: time.Now().Add(time.Hour), User: User{Identity: authkit.Identity{Roles: []string{"platform_admin"}}}}
			if refresh {
				sess.AccessToken = makeJWT(map[string]string{"sub": "u1"})
				sess.Expiry = time.Now().Add(-time.Hour)
				sess.RefreshToken = "rt"
			}
			r, w := sessionRequest(t, c, sess)
			me, err := c.BuildMe(w, r)
			if err != nil || me == nil {
				t.Fatalf("BuildMe = %+v, %v", me, err)
			}
			data, _ := json.Marshal(me)
			var wire struct {
				Roles []string `json:"roles"`
			}
			if err := json.Unmarshal(data, &wire); err != nil || !slices.Equal(wire.Roles, []string{"member"}) {
				t.Fatalf("current roles missing: %s (%v)", data, err)
			}
			if profiles.Load() != 1 || orgs.Load() != 1 || mints.Load() != map[bool]int32{false: 0, true: 1}[refresh] {
				t.Fatalf("calls refresh/profile/orgs = %d/%d/%d", mints.Load(), profiles.Load(), orgs.Load())
			}
		})
	}
}
