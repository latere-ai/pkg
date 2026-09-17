// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
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
		WithActions(Action{Name: "model.use", Kind: "Model"}, Action{Name: "key.create", Kind: "Key"}),
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

// theVocabulary is a four-row table with a list action, the shape Origo
// spec 028 declares.
func theVocabulary(t *testing.T) authz.Vocabulary {
	t.Helper()
	v, err := authz.NewVocabulary("origo",
		authz.Action{Name: "repo.read", Kind: "Repository"},
		authz.Action{Name: "repo.write", Kind: "Repository"},
		authz.Action{Name: "repo.admin", Kind: "Repository"},
		authz.Action{Name: "repo.list", Kind: "Repository"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestWithVocabularyDrivesTheWholeTable: the run covers a case per row,
// answers a list action's page without asking it to be a decision, and
// adds the check that an action outside the table is a 400.
func TestWithVocabularyDrivesTheWholeTable(t *testing.T) {
	v := theVocabulary(t)
	s := stub.New(t, stub.WithToken("secret"), stub.WithVocabulary(v),
		stub.WithAction("repo.list", func(authz.Request) any {
			return map[string]any{"repos": []any{}, "next_cursor": ""}
		}))
	if failures := run(t, s.URL(), "secret", WithVocabulary(v)); len(failures) != 0 {
		t.Fatalf("the stub under its own vocabulary failed: %q", failures)
	}
	seen := map[string]int{}
	for _, req := range s.Requests() {
		seen[req.Action]++
	}
	for _, a := range v.Actions {
		if seen[a.Name] == 0 {
			t.Fatalf("no case sent %q; WithVocabulary drives every row: %v", a.Name, seen)
		}
	}
	if seen["repo.list"] < 2 {
		t.Fatalf("the list action was sent %d times; the probe and a well-formed request both carry it", seen["repo.list"])
	}
}

// TestAnUnknownActionMustBeRefused: an endpoint that answers a string
// outside the table with a deny fails the run, and the check is silent
// without a vocabulary, where the suite cannot know the table is whole.
func TestAnUnknownActionMustBeRefused(t *testing.T) {
	v := theVocabulary(t)
	lenient := stub.New(t, stub.WithToken("secret"),
		stub.WithAction("repo.list", func(authz.Request) any { return map[string]any{"repos": []any{}} }))
	failures := run(t, lenient.URL(), "secret", WithVocabulary(v))
	if !mentions(failures, "is a malformed request and answers 400, never a deny") {
		t.Fatalf("an endpoint that decides about an unknown action passed: %q", failures)
	}
	if !mentions(failures, "origo") {
		t.Fatalf("the failure does not name the core: %q", failures)
	}
	if failures := run(t, lenient.URL(), "secret",
		WithActions(Action{Name: "repo.read", Kind: "Repository"})); len(failures) != 0 {
		t.Fatalf("WithActions ran the unknown-action check: %q", failures)
	}
}

// TestWithActionsAfterWithVocabularyDropsTheTable: the last option wins,
// so a caller that narrows to a hand-written list also drops the check
// that list cannot support.
func TestWithActionsAfterWithVocabularyDropsTheTable(t *testing.T) {
	lenient := stub.New(t, stub.WithToken("secret"))
	if failures := run(t, lenient.URL(), "secret",
		WithVocabulary(theVocabulary(t)),
		WithActions(Action{Name: "repo.read", Kind: "Repository"})); len(failures) != 0 {
		t.Fatalf("the narrowed run failed: %q", failures)
	}
}

// shaped is an authorizer over a vocabulary that denies the probe,
// refuses an unknown action with a 400, answers `page` for each action in
// pages, and a decision with a filter for every other, narrowed by the
// grants the request's token carries. It is the two shapes of list answer
// in one endpoint.
func shaped(t *testing.T, v authz.Vocabulary, page string, pages ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "bearer required", http.StatusUnauthorized)
			return
		}
		var req authz.Request
		_ = readJSON(r, &req)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case !v.Known(req.Action):
			http.Error(w, "unknown action", http.StatusBadRequest)
		case req.Resource.ID == authz.ProbeID:
			_, _ = io.WriteString(w, `{"allow": false, "reason": "probe"}`)
		case slices.Contains(pages, req.Action):
			_, _ = io.WriteString(w, page)
		default:
			grants, err := authz.ParseGrants(req.Claims)
			if err != nil || !authz.Restrict(v.Core, authz.Decision{Allow: true}, req, grants).Allow {
				_, _ = io.WriteString(w, `{"allow": false, "reason": "`+authz.ReasonGrant+`"}`)
				return
			}
			_, _ = io.WriteString(w, `{"allow": true, "filter": {"owners": ["a"]}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAListAnswersEitherShapeWhenNoneIsDeclared: told no page actions,
// the run accepts a list action that answers a decision with a filter and
// one that answers a page, because both conform and only the endpoint
// knows which it serves.
func TestAListAnswersEitherShapeWhenNoneIsDeclared(t *testing.T) {
	v := theVocabulary(t)
	decides := shaped(t, v, "")
	if failures := run(t, decides.URL, "secret", WithVocabulary(v)); len(failures) != 0 {
		t.Fatalf("a core that decides its list failed: %q", failures)
	}
	paging := shaped(t, v, `{"repos": [], "next_cursor": "c2"}`, "repo.list")
	if failures := run(t, paging.URL, "secret", WithVocabulary(v)); len(failures) != 0 {
		t.Fatalf("a core whose list is a directory page failed: %q", failures)
	}
}

// TestWithPageActionsFixesTheShapePerAction: told which actions are
// pages, the run requires a decision of every other action, a list
// included, and of a page requires the 200 and a JSON object — the
// contract fixes no field of a body whose shape is the core's own.
func TestWithPageActionsFixesTheShapePerAction(t *testing.T) {
	v := theVocabulary(t)
	paging := shaped(t, v, `{"repos": [], "next_cursor": "c2"}`, "repo.list")
	if failures := run(t, paging.URL, "secret", WithVocabulary(v), WithPageActions("repo.list")); len(failures) != 0 {
		t.Fatalf("the declared page failed: %q", failures)
	}
	// A page action may answer a refusal in the core's own shape; that is
	// a JSON object and passes.
	decides := shaped(t, v, "")
	if failures := run(t, decides.URL, "secret", WithVocabulary(v), WithPageActions("repo.list")); len(failures) != 0 {
		t.Fatalf("a refusal in the core's own shape failed: %q", failures)
	}
	// Declared as pages, and no page: the run names the action.
	if failures := run(t, decides.URL, "secret", WithVocabulary(v), WithPageActions()); len(failures) != 0 {
		t.Fatalf("a core that decides every list failed under WithPageActions(): %q", failures)
	}
	failures := run(t, paging.URL, "secret", WithVocabulary(v), WithPageActions())
	if !mentions(failures, "has no allow field") {
		t.Fatalf("a page where a decision was declared passed: %q", failures)
	}
	broken := shaped(t, v, `{not json`, "repo.list")
	failures = run(t, broken.URL, "secret", WithVocabulary(v), WithPageActions("repo.list"))
	if !mentions(failures, "the body is not a JSON object") {
		t.Fatalf("a page that is not JSON passed: %q", failures)
	}
}

// grantsHandler is an endpoint over a vocabulary whose every answer is
// decide, so a case can stand up an endpoint that reads the grants claim
// and one that does not.
func grantsHandler(t *testing.T, v authz.Vocabulary, decide func(authz.Request) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "bearer required", http.StatusUnauthorized)
			return
		}
		var req authz.Request
		_ = readJSON(r, &req)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case !v.Known(req.Action):
			http.Error(w, "unknown action", http.StatusBadRequest)
		case req.Resource.ID == authz.ProbeID:
			_, _ = io.WriteString(w, `{"allow": false, "reason": "probe"}`)
		default:
			_, _ = io.WriteString(w, decide(req))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestTheStubIsNarrowedByTheTokensGrants is id-13's A13 against the stub
// authorizer the cores' test tiers run: a token granted one action on one
// resource is refused every other action on it and that action anywhere
// else. The stub knows its core because the run told it the vocabulary,
// which is what qualifies a bare action against the claim's core:action.
func TestTheStubIsNarrowedByTheTokensGrants(t *testing.T) {
	v := theVocabulary(t)
	s := stub.New(t, stub.WithToken("secret"), stub.WithVocabulary(v))
	if failures := run(t, s.URL(), "secret", WithVocabulary(v), WithPageActions()); len(failures) != 0 {
		t.Fatalf("the stub failed the grants case: %q", failures)
	}
}

// TestTheGrantsCaseHasTeeth: the case fails an endpoint that reads the
// token and applies nothing, which is the failure it exists to catch, and
// it fails one that refuses a request the token's own grant names, which
// is the other direction.
func TestTheGrantsCaseHasTeeth(t *testing.T) {
	v := theVocabulary(t)

	ignores := grantsHandler(t, v, func(authz.Request) string { return `{"allow": true}` })
	failures := run(t, ignores.URL, "secret", WithVocabulary(v), WithPageActions())
	if !mentions(failures, "so no grant covers this request and the answer is a deny") {
		t.Fatalf("an endpoint that ignores the grants claim passed: %q", failures)
	}

	overzealous := grantsHandler(t, v, func(authz.Request) string {
		return `{"allow": false, "reason": "` + authz.ReasonGrant + `"}`
	})
	failures = run(t, overzealous.URL, "secret", WithVocabulary(v), WithPageActions())
	if !mentions(failures, "so the grants are not what refuses it") {
		t.Fatalf("an endpoint that refuses a granted request passed: %q", failures)
	}

	// An endpoint that answers no decision at all fails the case, as it
	// fails every other: a decision, allow or deny, is a 200.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	failures = run(t, down.URL, "secret", WithVocabulary(v), WithPageActions())
	if !mentions(failures, "on the resource its own grant names answered 503") {
		t.Fatalf("a 503 passed the grants case: %q", failures)
	}

	// An endpoint that refuses for a reason of its own is conforming: the
	// resources the case names are ids no object has, and the grants are
	// not the only thing that may refuse one.
	owns := grantsHandler(t, v, func(authz.Request) string {
		return `{"allow": false, "reason": "` + authz.ReasonNotOwner + `"}`
	})
	if failures := run(t, owns.URL, "secret", WithVocabulary(v), WithPageActions()); len(failures) != 0 {
		t.Fatalf("an endpoint that denies for its own reason failed: %q", failures)
	}
}

// TestTheGrantsCaseNeedsTheCore: without a vocabulary there is no core to
// qualify an action with, so there is no grant to write and the case is
// silent, the way the unknown-action check is.
func TestTheGrantsCaseNeedsTheCore(t *testing.T) {
	// The run sends its default actions, so the endpoint answers those.
	v, err := authz.NewVocabulary("example", defaultActions...)
	if err != nil {
		t.Fatal(err)
	}
	ignores := grantsHandler(t, v, func(authz.Request) string { return `{"allow": true}` })
	if failures := run(t, ignores.URL, "secret"); len(failures) != 0 {
		t.Fatalf("the grants case ran without a vocabulary: %q", failures)
	}
}

// TestTheGrantsCaseSkipsAPage: a page carries no verdict, so an action
// declared one is not a request the grants can narrow. A vocabulary whose
// every action is a page leaves the case nothing to send.
func TestTheGrantsCaseSkipsAPage(t *testing.T) {
	v, err := authz.NewVocabulary("origo", authz.Action{Name: "repo.list", Kind: "Repository"})
	if err != nil {
		t.Fatal(err)
	}
	s := stub.New(t, stub.WithToken("secret"), stub.WithVocabulary(v),
		stub.WithAction("repo.list", func(authz.Request) any { return map[string]any{"repos": []any{}} }))
	if failures := run(t, s.URL(), "secret", WithVocabulary(v), WithPageActions("repo.list")); len(failures) != 0 {
		t.Fatalf("a vocabulary of one page action failed: %q", failures)
	}
}
