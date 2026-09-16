// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stub_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/stub"
)

func call(t *testing.T, s *stub.Server, token, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", s.URL(), strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func control(t *testing.T, s *stub.Server, method, path, body string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, s.URL()+path, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

const (
	repoA = `{"kind":"Repository","id":"0f5c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f","owner":"acme","slug":"app"}`
	repoB = `{"kind":"Repository","id":"1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"}`
)

func body(subject, action, resource string) string {
	return `{"subject":"` + subject + `","issuer":"https://iss","sub":"` + strings.TrimPrefix(subject, "https://iss|") + `","claims":{},"action":"` + action + `","resource":` + resource + `,"request":{"id":"r","ip":"1.2.3.4","user_agent":"t"}}`
}

func TestRulesAndProbe(t *testing.T) {
	s := stub.New(t, stub.WithResourceName(func(r authz.Resource) string {
		if r.String("owner") == "" {
			return ""
		}
		return r.String("owner") + "/" + r.String("slug")
	}))
	if s.Token() != stub.DefaultToken {
		t.Fatalf("token %q", s.Token())
	}
	if status, _ := call(t, s, "wrong", body("alice", "repo.read", repoA)); status != 401 {
		t.Fatalf("wrong bearer: %d", status)
	}
	if status, _ := call(t, s, s.Token(), "{"); status != 400 {
		t.Fatalf("malformed body: %d", status)
	}
	if status, out := call(t, s, s.Token(), body("alice", "repo.admin", repoA)); status != 200 || out["allow"] != true || out["ttl"] != nil || out["limits"] != nil {
		t.Fatalf("default allow: %d %v", status, out)
	}
	if _, out := call(t, s, s.Token(), body("alice", "repo.read", `{"kind":"Repository","id":"`+authz.ProbeID+`"}`)); out["allow"] != false || out["reason"] == "" {
		t.Fatalf("probe: %v", out)
	}
	if _, out := call(t, s, s.Token(), body("", "repo.read", `{"kind":"Repository","id":"`+strings.ToUpper(authz.ProbeID)+`"}`)); out["allow"] != false {
		t.Fatalf("probe for the anonymous subject: %v", out)
	}
	// Rules: by id, by name; the later rule wins; the figures travel.
	s.Deny(stub.Rule{Subject: "alice", Resource: "0f5c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f", Action: "repo.write"}, "read only")
	s.Allow(stub.Rule{Subject: "*", Resource: "acme/app", Action: "repo.read", TTL: 5, Limits: map[string]any{"replicas": 3}, Filter: &authz.Filter{Owners: []string{"acme"}}})
	s.Deny(stub.Rule{Subject: "svc", Action: "*"}, "no service")
	s.Allow(stub.Rule{Subject: "bob"})
	if _, out := call(t, s, s.Token(), body("alice", "repo.write", repoA)); out["allow"] != false || out["reason"] != "read only" {
		t.Fatalf("deny by id: %v", out)
	}
	if _, out := call(t, s, s.Token(), body("carol", "repo.read", repoA)); out["allow"] != true || out["ttl"] != 5.0 || out["limits"].(map[string]any)["replicas"] != 3.0 || out["filter"] == nil {
		t.Fatalf("allow by name with figures: %v", out)
	}
	if _, out := call(t, s, s.Token(), body("svc", "repo.read", repoB)); out["allow"] != false || out["reason"] != "no service" {
		t.Fatalf("deny by subject: %v", out)
	}
	if _, out := call(t, s, s.Token(), body("bob", "repo.admin", repoB)); out["allow"] != true {
		t.Fatalf("later allow wins: %v", out)
	}
	reqs := s.Requests()
	if len(reqs) != 7 || reqs[3].Subject != "alice" || reqs[3].Action != "repo.write" || reqs[4].Resource.String("owner") != "acme" || reqs[4].Request.IP != "1.2.3.4" {
		t.Fatalf("requests: %+v", reqs)
	}
	status, raw := control(t, s, "GET", "/requests", "")
	var listed []authz.Request
	if err := json.Unmarshal(raw, &listed); err != nil || status != 200 || len(listed) != 7 {
		t.Fatalf("GET /requests: %d %s %v", status, raw, err)
	}
	if status, _ := control(t, s, "DELETE", "/requests", ""); status != 204 || len(s.Requests()) != 0 {
		t.Fatalf("DELETE /requests: %d", status)
	}
	if status, _ := control(t, s, "PUT", "/rules", `{"rules":[{"subject":"*","resource":"*","action":"*","allow":false,"reason":"closed"}]}`); status != 204 {
		t.Fatalf("PUT /rules: %d", status)
	}
	if _, out := call(t, s, s.Token(), body("bob", "repo.admin", repoB)); out["allow"] != false || out["reason"] != "closed" {
		t.Fatalf("replaced table: %v", out)
	}
	if status, _ := control(t, s, "PUT", "/rules", `nope`); status != 400 {
		t.Fatalf("malformed rules: %d", status)
	}
	s.SetRules()
	if _, out := call(t, s, s.Token(), body("bob", "repo.admin", repoB)); out["allow"] != true {
		t.Fatalf("empty table falls back to the default: %v", out)
	}
	named := stub.New(t, stub.WithAllow("dev"), stub.WithToken("t"))
	if _, out := call(t, named, "t", body("dev", "repo.read", repoB)); out["allow"] != true {
		t.Fatalf("named default: %v", out)
	}
	if _, out := call(t, named, "t", body("eve", "repo.read", repoB)); out["allow"] != false || !strings.Contains(out["reason"].(string), "eve") {
		t.Fatalf("subject outside the default: %v", out)
	}
	if rule := named.Decide(authz.Request{Subject: "eve", Action: "repo.read"}); rule.Allow {
		t.Fatal("Decide allowed eve")
	}
	// A name rule matches nothing when no name function is set.
	named.Allow(stub.Rule{Resource: "acme/app"})
	if _, out := call(t, named, "t", body("eve", "repo.read", repoA)); out["allow"] != false {
		t.Fatalf("a name matched with no name function: %v", out)
	}
}

func TestFailHangAndActions(t *testing.T) {
	s := stub.New(t, stub.WithAction("repo.list", func(req authz.Request) any {
		return map[string]any{"repos": []string{}, "cursor": req.Resource.String("cursor")}
	}))
	b := body("alice", "repo.read", repoA)
	s.Fail(500)
	if status, _ := call(t, s, s.Token(), b); status != 500 {
		t.Fatalf("Fail(500): %d", status)
	}
	if status, _ := control(t, s, "PUT", "/fail", `{"status":0}`); status != 204 {
		t.Fatalf("PUT /fail: %d", status)
	}
	if status, out := call(t, s, s.Token(), b); status != 200 || out["allow"] != true {
		t.Fatalf("after Fail(0): %d %v", status, out)
	}
	if status, _ := control(t, s, "PUT", "/fail", `x`); status != 400 {
		t.Fatalf("malformed fail: %d", status)
	}
	if status, _ := control(t, s, "POST", "/hang", ""); status != 204 {
		t.Fatalf("POST /hang: %d", status)
	}
	done := make(chan int, 1)
	go func() { status, _ := call(t, s, s.Token(), b); done <- status }()
	select {
	case status := <-done:
		t.Fatalf("a hung request answered %d", status)
	case <-time.After(200 * time.Millisecond):
	}
	if status, _ := control(t, s, "POST", "/resume", ""); status != 204 {
		t.Fatalf("POST /resume: %d", status)
	}
	if status := <-done; status != 200 {
		t.Fatalf("resumed request: %d", status)
	}
	// A core's own action answers its own body, still recorded and still
	// under the outage modes.
	if _, out := call(t, s, s.Token(), body("alice", "repo.list", `{"kind":"Repository","cursor":"c1"}`)); out["cursor"] != "c1" || out["allow"] != nil {
		t.Fatalf("custom action: %v", out)
	}
	if got := s.Requests(); got[len(got)-1].Action != "repo.list" {
		t.Fatal("the custom action was not recorded")
	}
	s.Fail(503)
	if status, _ := call(t, s, s.Token(), body("alice", "repo.list", `{"kind":"Repository"}`)); status != 503 {
		t.Fatalf("custom action under an outage: %d", status)
	}
	// Close releases a hung request with a 503.
	held := stub.New(t)
	held.Hang()
	go func() { status, _ := call(t, held, held.Token(), b); done <- status }()
	time.Sleep(100 * time.Millisecond)
	held.Close()
	if status := <-done; status != 503 {
		t.Fatalf("closed while hung: %d", status)
	}
	held.Close()
	h := stub.NewHandler()
	if h.Handler() == nil {
		t.Fatal("no handler")
	}
	h.Close()
}

// TestBodyOutagesAreUnavailableToTheClient: the two 200s that are no
// answer, a body that is not JSON and one with no allow field, are
// selected by method and by PUT /fail, and authz.Client fails closed on
// each as it does on a status (Lux spec 006's forms of unavailability).
func TestBodyOutagesAreUnavailableToTheClient(t *testing.T) {
	s := stub.New(t)
	ctx := context.Background()
	var req authz.Request
	if err := json.Unmarshal([]byte(body("https://iss|alice", "repo.read", repoA)), &req); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []stub.Body{stub.BodyMalformed, stub.BodyNoAllow} {
		// A client per mode: an allow the previous mode's recovery cached
		// would otherwise answer without reaching the stub.
		c, err := authz.NewClient(authz.Options{URL: s.URL(), Token: s.Token(), HTTP: &http.Client{}})
		if err != nil {
			t.Fatal(err)
		}
		// By method.
		s.FailBody(mode)
		var u *authz.Unavailable
		if _, err := c.Authorize(ctx, req); !errors.As(err, &u) || u.Status != 200 || u.Err == nil {
			t.Fatalf("FailBody(%s): %v", mode, err)
		}
		// The raw answer is a 200, which is what makes it the second kind.
		status, out := call(t, s, s.Token(), body("https://iss|alice", "repo.read", repoA))
		if status != 200 || out["allow"] != nil {
			t.Fatalf("FailBody(%s) answered %d %v", mode, status, out)
		}
		// Nothing of it was cached, and Fail(0) restores the table.
		s.Fail(0)
		if d, err := c.Authorize(ctx, req); err != nil || !d.Allow {
			t.Fatalf("after FailBody(%s) and Fail(0): %+v %v", mode, d, err)
		}
		// Over HTTP.
		if status, _ := control(t, s, "PUT", "/fail", `{"body":"`+string(mode)+`"}`); status != 204 {
			t.Fatalf("PUT /fail body %s: %d", mode, status)
		}
		if _, err := c.Authorize(ctx, authz.Request{Subject: req.Subject, Action: "repo.write", Resource: req.Resource}); !errors.As(err, &u) || u.Status != 200 {
			t.Fatalf("PUT /fail body %s: %v", mode, err)
		}
		// {"status": 0} clears it, as it clears a status outage.
		if status, _ := control(t, s, "PUT", "/fail", `{"status":0}`); status != 204 {
			t.Fatalf("PUT /fail status 0: %d", status)
		}
		if _, err := c.Authorize(ctx, authz.Request{Subject: req.Subject, Action: "repo.admin", Resource: req.Resource}); err != nil {
			t.Fatalf("after PUT /fail status 0: %v", err)
		}
	}
	// A status outage replaces a body one and Resume clears both.
	s.FailBody(stub.BodyNoAllow)
	s.Fail(503)
	if status, _ := call(t, s, s.Token(), body("https://iss|alice", "repo.read", repoA)); status != 503 {
		t.Fatalf("Fail after FailBody: %d", status)
	}
	s.FailBody(stub.BodyMalformed)
	s.Resume()
	if status, out := call(t, s, s.Token(), body("https://iss|alice", "repo.read", repoA)); status != 200 || out["allow"] != true {
		t.Fatalf("after Resume: %d %v", status, out)
	}
	// A mode the stub does not know is refused, and the table still answers.
	if status, _ := control(t, s, "PUT", "/fail", `{"body":"teapot"}`); status != 400 {
		t.Fatalf("unknown body mode: %d", status)
	}
	if status, _ := call(t, s, s.Token(), body("https://iss|alice", "repo.read", repoA)); status != 200 {
		t.Fatalf("after an unknown mode: %d", status)
	}
}

// TestVocabularyRefusesAnUnknownAction: told a core's table, the stub
// answers a string outside it with a 400, the way the scaffold does, and
// still records the request that arrived. A stub told no table answers
// every action from the rule table, as before.
func TestVocabularyRefusesAnUnknownAction(t *testing.T) {
	v, err := authz.NewVocabulary("origo",
		authz.Action{Name: "repo.read", Kind: "Repository"},
		authz.Action{Name: "repo.list", Kind: "Repository"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		opts   []stub.Option
		action string
		want   int
	}{
		{"an action of the table", []stub.Option{stub.WithVocabulary(v)}, "repo.read", http.StatusOK},
		{"an action outside it", []stub.Option{stub.WithVocabulary(v)}, "repo.write", http.StatusBadRequest},
		{"no table validates nothing", nil, "repo.write", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stub.New(t, tc.opts...)
			status, _ := call(t, s, s.Token(), body("https://iss|alice", tc.action, repoA))
			if status != tc.want {
				t.Fatalf("%s answered %d; want %d", tc.action, status, tc.want)
			}
			if reqs := s.Requests(); len(reqs) != 1 || reqs[0].Action != tc.action {
				t.Fatalf("Requests = %+v; a request that arrived is recorded whatever the answer", reqs)
			}
		})
	}
}

// TestTheProbeIsDeniedBeforeACoresOwnAnswer: an action registered through
// WithAction answers a page that carries no verdict, so the reserved id
// must not reach it — the rule binds every action.
func TestTheProbeIsDeniedBeforeACoresOwnAnswer(t *testing.T) {
	s := stub.New(t, stub.WithAction("repo.list", func(authz.Request) any {
		return map[string]any{"repos": []string{}}
	}))
	probe := `{"kind":"Repository","id":"` + authz.ProbeID + `"}`
	status, out := call(t, s, s.Token(), body("https://iss|alice", "repo.list", probe))
	if status != http.StatusOK || out["allow"] != false {
		t.Fatalf("the probe on a registered action answered %d %v; it is denied", status, out)
	}
	if _, page := out["repos"]; page {
		t.Fatalf("the probe was answered with a page: %v", out)
	}
	status, out = call(t, s, s.Token(), body("https://iss|alice", "repo.list", repoA))
	if status != http.StatusOK || out["repos"] == nil {
		t.Fatalf("a real list answered %d %v; it is the core's page", status, out)
	}
}

// TestAnUnregisteredListIsADecision: the verb is not the routing here
// either. sandbox.list is registered through no WithAction, so it is
// answered from the rule table like every other action, filter included,
// which is the shape a core whose lists are decisions expects. The
// registered repo.list beside it still answers its page.
func TestAnUnregisteredListIsADecision(t *testing.T) {
	s := stub.New(t, stub.WithAction("repo.list", func(authz.Request) any {
		return map[string]any{"repos": []string{}, "next_cursor": "c2"}
	}))
	s.Allow(stub.Rule{Subject: "https://iss|alice", Action: "sandbox.list",
		Filter: &authz.Filter{Owners: []string{"https://iss|alice"}, Labels: map[string]string{"team": "a"}}})
	sandbox := `{"kind":"Sandbox"}`
	status, out := call(t, s, s.Token(), body("https://iss|alice", "sandbox.list", sandbox))
	if status != http.StatusOK || out["allow"] != true {
		t.Fatalf("sandbox.list answered %d %v; an unregistered list is a decision", status, out)
	}
	filter, ok := out["filter"].(map[string]any)
	if !ok {
		t.Fatalf("the decision carries no filter: %v", out)
	}
	if owners, _ := filter["owners"].([]any); len(owners) != 1 || owners[0] != "https://iss|alice" {
		t.Fatalf("filter = %v", filter)
	}
	if status, out := call(t, s, s.Token(), body("https://iss|alice", "repo.list", repoA)); status != http.StatusOK || out["next_cursor"] != "c2" {
		t.Fatalf("repo.list answered %d %v; a registered action is the core's page", status, out)
	}
}
