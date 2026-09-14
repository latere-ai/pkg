// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/stub"
)

// TestTheStubConforms: the stub authorizer the cores' test tiers run
// passes, with a table that exercises every optional field of an answer.
func TestTheStubConforms(t *testing.T) {
	s := stub.New(t, stub.WithToken("secret"))
	s.Allow(stub.Rule{Subject: "https://issuer.example|alice", TTL: 30,
		Limits: map[string]any{"requests_per_minute": 60},
		Filter: &authz.Filter{Owners: []string{"https://issuer.example|alice"}, Labels: map[string]string{"team": "a"}}})
	s.Deny(stub.Rule{Subject: "https://issuer.example|bob"}, "bob is refused by the table")
	Run(t, s.URL(), "secret")
	// A core's own vocabulary and subjects.
	Run(t, s.URL(), "secret",
		WithActions(Action{"model.use", "Model"}, Action{"key.create", "Key"}),
		WithSubjects("https://auth.latere.ai|0f5c1d2e"),
		WithHTTPClient(&http.Client{}))
}

// recorder is a TB that records failures instead of stopping the test, so
// the suite can be shown to fail a non-conforming authorizer. Fatalf
// panics the way testing.T's runtime.Goexit ends a test, and run catches
// it.
type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
	panic(fatal{})
}

type fatal struct{}

func run(t *testing.T, url, token string, opts ...Option) []string {
	t.Helper()
	r := &recorder{TB: t}
	func() {
		defer func() {
			if v := recover(); v != nil {
				if _, ok := v.(fatal); !ok {
					panic(v)
				}
			}
		}()
		Run(r, url, token, opts...)
	}()
	return r.failures
}

// answering is an authorizer that checks the bearer and answers every
// request with the same body.
func answering(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			http.Error(w, "bearer required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestABrokenAuthorizerFails: each way an endpoint can break the
// contract is a failure the suite reports, and the message names it.
func TestABrokenAuthorizerFails(t *testing.T) {
	// The endpoint that does not read the request: everything is allowed,
	// the probe included, under any bearer.
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"allow": true}`)
	}))
	t.Cleanup(open.Close)
	failures := run(t, open.URL, "good")
	if !mentions(failures, "was allowed; every authorizer denies the probe id") || !mentions(failures, "a wrong bearer was answered with a 200") || !mentions(failures, "no bearer was answered with a 200") {
		t.Fatalf("an open authorizer passed: %q", failures)
	}
	// The probe denied but everything else broken in one way each.
	for _, tc := range []struct {
		name, body, want string
	}{
		{"not JSON", `{not json`, "is not a JSON object"},
		{"no allow", `{"reason": "?"}`, "has no allow field"},
		{"allow not a boolean", `{"allow": "false"}`, "it is a boolean"},
		{"a deny with no reason", `{"allow": false}`, "a deny with no reason"},
		{"a deny with a null reason", `{"allow": false, "reason": null}`, "a deny with no reason"},
		{"reason not a string", `{"allow": false, "reason": 7}`, "reason is 7; it is a string"},
		{"ttl a string", `{"allow": false, "reason": "r", "ttl": "60"}`, `ttl is "60"; it is a positive integer`},
		{"ttl a fraction", `{"allow": false, "reason": "r", "ttl": 1.5}`, "ttl is 1.5; it is a positive integer"},
		{"ttl zero", `{"allow": false, "reason": "r", "ttl": 0}`, "ttl is 0; it is a positive integer"},
		{"ttl negative", `{"allow": false, "reason": "r", "ttl": -5}`, "ttl is -5; it is a positive integer"},
		{"limits a list", `{"allow": false, "reason": "r", "limits": [1]}`, "limits is [1]; it is an object"},
		{"filter a list", `{"allow": false, "reason": "r", "filter": []}`, "filter is []; it is an object"},
		{"filter owners not strings", `{"allow": false, "reason": "r", "filter": {"owners": [1]}}`, "filter.owners is [1]"},
		{"filter labels not strings", `{"allow": false, "reason": "r", "filter": {"labels": {"a": 1}}}`, `filter.labels is {"a": 1}`},
		{"filter with another key", `{"allow": false, "reason": "r", "filter": {"kinds": ["x"]}}`, `filter carries "kinds"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := answering(t, tc.body)
			failures := run(t, srv.URL, "good")
			if !mentions(failures, tc.want) {
				t.Fatalf("failures %q do not mention %q", failures, tc.want)
			}
		})
	}
	// A status other than 200 on a decision, and one on the probe.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	failures = run(t, down.URL, "good")
	if !mentions(failures, "the probe as \"\" for resource.read answered 503") || !mentions(failures, "resource.read by \"https://issuer.example|alice\" answered 503") {
		t.Fatalf("a 503 passed: %q", failures)
	}
	// An endpoint that does not answer at all fails the run outright.
	failures = run(t, "http://127.0.0.1:1", "good")
	if len(failures) != 1 || !strings.Contains(failures[0], "did not answer") {
		t.Fatalf("a refused connection: %q", failures)
	}
	// A run with nothing to send is a misuse the suite names.
	if failures := run(t, "", "good"); len(failures) != 1 || !strings.Contains(failures[0], "needs the authorizer's URL") {
		t.Fatalf("no URL: %q", failures)
	}
	if failures := run(t, open.URL, "good", WithActions()); len(failures) != 1 || !strings.Contains(failures[0], "at least one action") {
		t.Fatalf("no actions: %q", failures)
	}
}

// TestAValidAnswerWithEveryOptionalFieldPasses: null for an optional field
// is the field absent, and a filter of owners and labels is the shape.
func TestAValidAnswerWithEveryOptionalFieldPasses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			http.Error(w, "bearer required", http.StatusUnauthorized)
			return
		}
		var req authz.Request
		_ = readJSON(r, &req)
		if req.Resource.ID == authz.ProbeID {
			_, _ = io.WriteString(w, `{"allow": false, "reason": "probe", "ttl": null, "limits": null, "filter": null}`)
			return
		}
		_, _ = io.WriteString(w, `{"allow": true, "ttl": 600, "limits": {"rpm": 1}, "filter": {"owners": ["a"], "labels": {"k": "v"}}}`)
	}))
	t.Cleanup(srv.Close)
	if failures := run(t, srv.URL, "good"); len(failures) != 0 {
		t.Fatalf("a conforming authorizer failed: %q", failures)
	}
	first, second := freshID(), freshID()
	if first == second || len(first) != 36 {
		t.Fatalf("fresh ids %q and %q", first, second)
	}
}

func readJSON(r *http.Request, v any) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func mentions(failures []string, s string) bool {
	for _, f := range failures {
		if strings.Contains(f, s) {
			return true
		}
	}
	return false
}
