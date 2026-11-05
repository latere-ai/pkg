// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/authz"
)

func TestVocabularyCheck(t *testing.T) {
	v, err := authz.NewVocabulary("demo",
		authz.Action{Name: "repo.read", Kind: "Repository"},
		authz.Action{Name: "org.read", Kind: "Org"})
	if err != nil {
		t.Fatal(err)
	}
	req := func(action, kind string) authz.Request {
		return authz.Request{Action: action, Resource: authz.NewResource(kind, "x", nil)}
	}
	if err := (authz.Vocabulary{}).Check(req("anything", "")); err != nil {
		t.Fatalf("zero vocabulary: %v", err)
	}
	if err := v.Check(req("repo.read", "Repository")); err != nil {
		t.Fatalf("matching kind: %v", err)
	}
	var unknown *authz.UnknownAction
	if err := v.Check(req("repo.raed", "Repository")); !errors.As(err, &unknown) || unknown.Core != "demo" {
		t.Fatalf("unknown action: %v", err)
	}
	for _, kind := range []string{"Org", ""} {
		err := v.Check(req("repo.read", kind))
		var km *authz.KindMismatch
		if !errors.As(err, &km) {
			t.Fatalf("kind %q: %v; want *KindMismatch", kind, err)
		}
		if km.Core != "demo" || km.Action != "repo.read" || km.Want != "Repository" || km.Got != kind {
			t.Fatalf("KindMismatch = %+v", km)
		}
		for _, s := range []string{"repo.read", "Repository", kind} {
			if !strings.Contains(err.Error(), s) {
				t.Fatalf("message %q lacks %q", err.Error(), s)
			}
		}
		var un *authz.Unavailable
		if errors.As(err, &un) || authz.Retryable(err) {
			t.Fatal("a kind mismatch must be neither unavailable nor retryable")
		}
	}
}

func TestAKindMismatchNeverReachesTheWire(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"allow": true}`)
	}))
	t.Cleanup(srv.Close)
	v, err := authz.NewVocabulary("demo", authz.Action{Name: "repo.read", Kind: "Repository"})
	if err != nil {
		t.Fatal(err)
	}
	var observed int
	c, err := authz.NewClient(authz.Options{URL: srv.URL, HTTP: srv.Client(), Vocabulary: v,
		Observe: func(string, float64) { observed++ }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Authorize(t.Context(), authz.Request{Action: "repo.read", Resource: authz.NewResource("Org", "o1", nil)})
	var km *authz.KindMismatch
	if !errors.As(err, &km) {
		t.Fatalf("Authorize = %v; want *KindMismatch", err)
	}
	if calls != 0 || observed != 0 || c.CacheLen() != 0 {
		t.Fatalf("calls=%d observed=%d cache=%d; the request never leaves", calls, observed, c.CacheLen())
	}
}

func TestNilClaimsMarshalAsAnObject(t *testing.T) {
	nilClaims := authz.Request{Subject: "s", Action: "a", Resource: authz.NewResource("K", "1", map[string]any{"owner": "o"})}
	empty := nilClaims
	empty.Claims = map[string]any{}
	a, err := json.Marshal(nilClaims, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(empty, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("nil %s != empty %s", a, b)
	}
	if !strings.Contains(string(a), `"claims":{}`) || strings.Contains(string(a), "null") {
		t.Fatalf("body = %s", a)
	}
	if !strings.Contains(string(a), `"owner":"o"`) || !strings.Contains(string(a), `"kind":"K"`) {
		t.Fatalf("resource not flat: %s", a)
	}
	if nilClaims.Claims != nil {
		t.Fatal("marshaling changed the caller's request")
	}
}

func TestNilAndEmptyClaimsShareACacheEntry(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"allow": true}`)
	}))
	t.Cleanup(srv.Close)
	c, err := authz.NewClient(authz.Options{URL: srv.URL, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	req := authz.Request{Subject: "s", Action: "a", Resource: authz.NewResource("K", "1", nil)}
	if _, err := c.Authorize(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	req.Claims = map[string]any{}
	if _, err := c.Authorize(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || c.CacheLen() != 1 {
		t.Fatalf("calls=%d cache=%d; nil and empty claims are one request", calls, c.CacheLen())
	}
}

func TestFilterAdmits(t *testing.T) {
	var nilFilter *authz.Filter
	for _, tc := range []struct {
		name   string
		f      *authz.Filter
		owner  string
		labels map[string]string
		want   bool
	}{
		{"nil filter", nilFilter, "x", nil, true},
		{"empty filter", &authz.Filter{}, "", nil, true},
		{"owner listed", &authz.Filter{Owners: []string{"a", "b"}}, "b", nil, true},
		{"owner not listed", &authz.Filter{Owners: []string{"a", "b"}}, "c", nil, false},
		{"empty owner not listed", &authz.Filter{Owners: []string{"a"}}, "", nil, false},
		{"labels all present", &authz.Filter{Labels: map[string]string{"k": "v", "j": "w"}}, "", map[string]string{"k": "v", "j": "w", "x": "y"}, true},
		{"label value differs", &authz.Filter{Labels: map[string]string{"k": "v"}}, "", map[string]string{"k": "z"}, false},
		{"label missing", &authz.Filter{Labels: map[string]string{"k": "v", "j": "w"}}, "", map[string]string{"k": "v"}, false},
		{"no labels never passes", &authz.Filter{Labels: map[string]string{"k": "v"}}, "", nil, false},
		{"empty label value matches empty", &authz.Filter{Labels: map[string]string{"k": ""}}, "", map[string]string{"k": ""}, true},
		{"empty label value needs the label", &authz.Filter{Labels: map[string]string{"k": ""}}, "", nil, false},
		{"owner and labels both", &authz.Filter{Owners: []string{"a"}, Labels: map[string]string{"k": "v"}}, "a", map[string]string{"k": "v"}, true},
		{"owner ok labels not", &authz.Filter{Owners: []string{"a"}, Labels: map[string]string{"k": "v"}}, "a", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.Admits(tc.owner, tc.labels); got != tc.want {
				t.Fatalf("Admits = %v; want %v", got, tc.want)
			}
		})
	}
}

// FuzzFilterAdmits: a filter only narrows, so adding a requirement to it
// never admits a row the looser filter refused.
func FuzzFilterAdmits(f *testing.F) {
	f.Add("a", "k", "v", "a", "k", "v")
	f.Add("", "", "", "b", "x", "y")
	f.Fuzz(func(t *testing.T, owner, fk, fv, rowOwner, rk, rv string) {
		loose := &authz.Filter{Labels: map[string]string{fk: fv}}
		tight := &authz.Filter{Owners: []string{owner}, Labels: map[string]string{fk: fv}}
		row := map[string]string{rk: rv}
		if tight.Admits(rowOwner, row) && !loose.Admits(rowOwner, row) {
			t.Fatal("a tighter filter admitted a row the looser one refused")
		}
		var nilFilter *authz.Filter
		if !nilFilter.Admits(rowOwner, row) {
			t.Fatal("a nil filter narrowed")
		}
	})
}

func TestRestrictByClaims(t *testing.T) {
	covered := authz.Request{Action: "repo.read", Resource: authz.NewResource("Repository", grantedRepo, nil),
		Claims: map[string]any{"token_use": "pat", "authorization_details": []any{map[string]any{
			"type": "latere-authz", "actions": []any{"demo:repo.read"}}}}}
	uncovered := covered
	uncovered.Action = "repo.write"
	unreadable := covered
	unreadable.Claims = map[string]any{"token_use": "pat", "authorization_details": "nope"}
	allow := authz.Decision{Allow: true, Reason: "ok"}
	deny := authz.Decision{Reason: authz.ReasonNotOwner}

	if got := authz.RestrictByClaims("demo", allow, covered); !reflect.DeepEqual(got, allow) {
		t.Fatalf("covered = %+v", got)
	}
	if got := authz.RestrictByClaims("demo", allow, uncovered); got.Allow || got.Reason != authz.ReasonGrant {
		t.Fatalf("uncovered = %+v", got)
	}
	if got := authz.RestrictByClaims("demo", allow, unreadable); got.Allow || got.Reason != authz.ReasonGrant {
		t.Fatalf("unreadable allow = %+v", got)
	}
	if got := authz.RestrictByClaims("demo", deny, unreadable); !reflect.DeepEqual(got, deny) {
		t.Fatalf("unreadable deny = %+v", got)
	}
	if got := authz.RestrictByClaims("demo", allow, authz.Request{}); !reflect.DeepEqual(got, allow) {
		t.Fatalf("no claims = %+v", got)
	}
}
