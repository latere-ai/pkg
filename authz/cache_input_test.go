// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"latere.ai/x/pkg/authz"
)

func cacheInput() authz.Request {
	return authz.Request{Subject: "issuer|alice", Issuer: "issuer", Sub: "alice", Claims: map[string]any{"roles": []string{"owner"}}, Workload: map[string]any{"environment": "prod"}, Action: "key.update", Resource: authz.Resource{Kind: "Key", ID: "key-1", Fields: map[string]any{"owner": "issuer|alice", "proposed": map[string]any{"org": "a"}}}, Request: authz.Caller{ID: "req-1", IP: "192.0.2.1", UserAgent: "client-a"}}
}
func TestCacheIncludesEveryDecisionInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*authz.Request)
	}{
		{"claims", func(r *authz.Request) { r.Claims["roles"] = []string{"member"} }},
		{"personal key grants", func(r *authz.Request) {
			r.Claims["authorization_details"] = []any{map[string]any{"actions": []string{"read"}}}
		}},
		{"proposal", func(r *authz.Request) { r.Resource.Fields["proposed"] = map[string]any{"org": "b"} }},
		{"kind", func(r *authz.Request) { r.Resource.Kind = "Budget" }},
		{"issuer", func(r *authz.Request) { r.Issuer = "other" }},
		{"sub", func(r *authz.Request) { r.Sub = "other" }},
		{"workload", func(r *authz.Request) { r.Workload["environment"] = "test" }},
		{"IP", func(r *authz.Request) { r.Request.IP = "192.0.2.2" }},
		{"user agent", func(r *authz.Request) { r.Request.UserAgent = "client-b" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				allow := calls.Add(1) == 1
				_ = json.NewEncoder(w).Encode(map[string]bool{"allow": allow})
			}))
			defer srv.Close()
			c, err := authz.NewClient(authz.Options{URL: srv.URL, HTTP: srv.Client()})
			if err != nil {
				t.Fatal(err)
			}
			r := cacheInput()
			if d, err := c.Authorize(t.Context(), r); err != nil || !d.Allow {
				t.Fatal(d, err)
			}
			tc.change(&r)
			if d, err := c.Authorize(t.Context(), r); err != nil || d.Allow {
				t.Fatalf("changed %s reused an allow: %+v %v", tc.name, d, err)
			}
			if calls.Load() != 2 {
				t.Fatal("changed request did not reach authorizer")
			}
		})
	}
}
func TestCacheIgnoresOnlyCorrelationIDAndMapOrder(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{"allow":true}`)) }))
	defer srv.Close()
	c, err := authz.NewClient(authz.Options{URL: srv.URL, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	r := cacheInput()
	r.Claims["first"] = "a"
	r.Claims["second"] = "b"
	if _, err := c.Authorize(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	r.Request.ID = "req-2"
	r.Claims = map[string]any{"second": "b", "first": "a", "roles": []string{"owner"}}
	if _, err := c.Authorize(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("correlation ID or map insertion order changed identity")
	}
	r.Resource.Fields["invalid"] = make(chan int)
	if _, err := c.Authorize(t.Context(), r); err == nil {
		t.Fatal("invalid updated resource reused cached allow")
	} else {
		var unavailable *authz.Unavailable
		if !errors.As(err, &unavailable) {
			t.Fatal(err)
		}
	}
}

type changingPolicy struct{ calls *atomic.Int32 }

func (p changingPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]int32{"version": p.calls.Add(1)})
}
func TestCacheAndWireShareOneSerializedSnapshot(t *testing.T) {
	var encodes, calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request authz.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		version := request.Resource.Fields["policy"].(map[string]any)["version"].(float64)
		expected := calls.Add(1)
		if version != float64(expected) {
			t.Errorf("wire version %v, expected %d", version, expected)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"allow": expected == 1})
	}))
	defer srv.Close()
	c, err := authz.NewClient(authz.Options{URL: srv.URL, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	r := cacheInput()
	r.Resource.Fields["policy"] = changingPolicy{&encodes}
	first, err := c.Authorize(t.Context(), r)
	if err != nil || !first.Allow {
		t.Fatal(first, err)
	}
	second, err := c.Authorize(t.Context(), r)
	if err != nil || second.Allow {
		t.Fatal(second, err)
	}
	if encodes.Load() != 2 || calls.Load() != 2 {
		t.Fatalf("input encoded %d times for %d calls", encodes.Load(), calls.Load())
	}
}
