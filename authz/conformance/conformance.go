// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package conformance is the test every authorizer passes: the rules of
// the one authorizer contract the open cores share (latere-ai/specs
// decisions/2026-09-13-one-platform-open-cores.md, C3 and C4; Lux spec
// 006) as checks against a running endpoint. A core runs it against the
// stub authorizer in its test tier and against the authorizer it deploys,
// and an operator who writes a twenty-line authorizer runs it against
// that. The package proves the shape of what the endpoint answers; the
// client's cache, retry and timeout are latere.ai/x/pkg/authz's own and
// are proved there.
//
// One call:
//
//	conformance.Run(t, authorizerURL, bearer)
//
// checks, in order, that the probe id is denied for every subject and
// action, that a wrong bearer is refused, that an action outside the
// grants a personal access token carries is denied, and that a
// well-formed request answers a 200 whose body has the contract's shape: allow a boolean, ttl
// when present a positive integer, limits when present an object, filter
// when present owners and labels, and a deny carrying a reason. The
// subjects and the action vocabulary have defaults an authorizer that
// reads the request answers; a core names its own with WithSubjects and
// WithVocabulary, which drives a case per row of the core's declared
// table and adds the check that an action outside it is refused.
//
// An action whose answer is a page of the core's own shape rather than a
// decision — Origo's repo.list, a directory page — is named with
// WithPageActions. A run that names none accepts either shape for an
// action whose verb is list and requires a decision for every other,
// because both are conforming and only the endpoint knows which it
// serves.
package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"testing"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/otel"
)

// Action is one entry of a core's vocabulary, latere.ai/x/pkg/authz's
// type: the action name and the resource kind it acts on.
type Action = authz.Action

// Option configures a run.
type Option func(*suite)

// WithActions names the actions the checks send, for an endpoint that is
// not a core's and declares no table. The default is two actions on one
// kind an authorizer that reads the request answers. A core passes
// WithVocabulary instead.
func WithActions(actions ...Action) Option {
	return func(s *suite) { s.actions, s.vocabulary = actions, authz.Vocabulary{} }
}

// WithVocabulary drives the checks from a core's declared table: a case
// per row, so the run covers the whole vocabulary rather than the rows
// somebody wrote out by hand. It also turns on the check that an action
// outside the table is refused with a 400, which only a complete table
// makes meaningful.
func WithVocabulary(v authz.Vocabulary) Option {
	return func(s *suite) { s.actions, s.vocabulary = v.Actions, v }
}

// WithPageActions names the actions whose 200 is a page of the core's own
// shape — its fields, its cursor — rather than a decision, which is what
// authz/server's Options.PageActions routes to a Lister. An action named
// here is checked as a page: the 200 and a JSON object, and no field,
// because the contract fixes none. Every action not named is checked as a
// decision, so a core that declares its table gets both halves checked.
//
// A run that does not call it accepts either shape for an action whose
// verb is list, because the contract allows both: the ordinary list
// answers a decision the authorizer may have narrowed with a filter, and
// a directory page is the core's exception. WithPageActions() with no
// action is a declaration too — every action, list included, answers a
// decision.
func WithPageActions(actions ...string) Option {
	return func(s *suite) { s.pages, s.pagesSet = actions, true }
}

// WithSubjects names the rendered subjects the checks send. The anonymous
// subject, the empty string, is always sent to the probe as well. The
// default is two subjects of an example issuer.
func WithSubjects(subjects ...string) Option {
	return func(s *suite) { s.subjects = subjects }
}

// WithHTTPClient sends the calls through the given client; the default
// is an instrumented client with the contract's timeout.
func WithHTTPClient(c *http.Client) Option {
	return func(s *suite) { s.http = c }
}

// The defaults a run sends when a core names none.
var (
	defaultActions  = []Action{{Name: "resource.read", Kind: "Resource"}, {Name: "resource.write", Kind: "Resource"}}
	defaultSubjects = []string{"https://issuer.example|alice", "https://issuer.example|bob"}
)

type suite struct {
	url, token string
	actions    []Action
	vocabulary authz.Vocabulary
	subjects   []string
	pages      []string
	pagesSet   bool
	http       *http.Client
}

// isPage reports whether the run was told this action answers a page.
func (s *suite) isPage(action string) bool { return slices.Contains(s.pages, action) }

// Run runs every check against the authorizer at url, which requires the
// bearer token, and fails t when any does not hold. It is the one call a
// repository makes. Each failure names the check and the request that
// broke it.
func Run(t testing.TB, url, token string, opts ...Option) {
	t.Helper()
	s := &suite{url: url, token: token, actions: defaultActions, subjects: defaultSubjects,
		http: &http.Client{Timeout: authz.Timeout, Transport: otel.Transport(nil)}}
	for _, o := range opts {
		o(s)
	}
	if url == "" {
		t.Fatalf("conformance: Run needs the authorizer's URL")
	}
	if len(s.actions) == 0 || len(s.subjects) == 0 {
		t.Fatalf("conformance: Run needs at least one action and one subject")
	}
	s.deniesTheProbe(t)
	s.refusesAWrongBearer(t)
	s.refusesAnUnknownAction(t)
	s.refusesAnActionOutsideTheGrants(t)
	s.answersAWellFormedRequest(t)
}

// refusesAnActionOutsideTheGrants is id-13's A13. A personal access token
// carries the grants its holder chose, and a decision point intersects
// its own answer with them: a key granted one action on one resource is
// refused every other action on that resource and that action on every
// other resource.
//
// Both of those are denials, so the check needs to know nothing about who
// owns what. It does not read the deny's reason either: the reason is
// "grant" when the decision point would otherwise have allowed, and the
// resources here are ids no object has, which many an endpoint refuses
// for a reason of its own first. What it does pin is the other direction,
// which ownership cannot fake: a request a grant does name is never
// refused as "grant".
//
// The check runs only under [WithVocabulary]. The claim carries the
// action qualified by its core, so without the core's own table there is
// no grant to write.
func (s *suite) refusesAnActionOutsideTheGrants(t testing.TB) {
	t.Helper()
	decided := s.decided()
	if len(decided) == 0 {
		return
	}
	granted, subject := decided[0], s.subjects[0]
	here, elsewhere := freshID(), freshID()
	entry := authz.Grant{
		Type:       authz.GrantType,
		Actions:    []string{s.vocabulary.Core + ":" + granted.Name},
		Datatypes:  []string{granted.Kind},
		Identifier: here,
	}

	what := fmt.Sprintf("%s on the resource its own grant names", granted.Name)
	if d, ok := s.decide(t, s.scoped(subject, granted, here, entry), what); ok && !d.Allow && d.Reason == authz.ReasonGrant {
		t.Errorf("%s was denied %q; the token carries a grant that names this action on this resource, so the grants are not what refuses it", what, authz.ReasonGrant)
	}

	// Another action on the granted resource. One entry is one selector,
	// so the actions it lists are the whole of what it allows.
	if len(decided) > 1 {
		other := decided[1]
		what := fmt.Sprintf("%s on the granted resource", other.Name)
		if d, ok := s.decide(t, s.scoped(subject, other, here, entry), what); ok && d.Allow {
			t.Errorf("%s was allowed; the token's only grant names %s, so no grant covers this request and the answer is a deny", what, granted.Name)
		}
	}

	// The granted action on another resource. The selector names one
	// resource, so it covers that one and nothing else.
	what = fmt.Sprintf("%s on a resource no grant names", granted.Name)
	if d, ok := s.decide(t, s.scoped(subject, granted, elsewhere, entry), what); ok && d.Allow {
		t.Errorf("%s was allowed; the token's only grant names another resource, so no grant covers this request and the answer is a deny", what)
	}
}

// decided is the vocabulary's actions that answer a decision: not one the
// run declared a page, and, where it declared none, not a list either,
// whose answer may be the core's own page. A page carries no verdict, so
// there is nothing in it for a grant to narrow.
func (s *suite) decided() []Action {
	if len(s.vocabulary.Actions) == 0 {
		return nil
	}
	var out []Action
	for _, a := range s.vocabulary.Actions {
		if s.isPage(a.Name) || (!s.pagesSet && authz.IsList(a.Name)) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// scoped is one envelope from a personal access token: the claims a PEP
// forwards verbatim, carrying the token_use that names the credential
// class and the grants its holder chose.
func (s *suite) scoped(subject string, a Action, id string, grants ...authz.Grant) authz.Request {
	req := authz.Request{
		Action:   a.Name,
		Resource: authz.NewResource(a.Kind, id, map[string]any{"owner": subject}),
		Request:  authz.Caller{ID: "conformance-" + freshID(), IP: "203.0.113.4", UserAgent: "authz/conformance"},
		Claims: map[string]any{
			"token_use":             authz.TokenUsePAT,
			"authorization_details": grants,
		},
	}
	setSubject(&req, subject)
	return req
}

// decide sends one envelope and reads the decision out of the answer. ok
// is false when the endpoint answered something that is no decision,
// which the other checks report on their own.
func (s *suite) decide(t testing.TB, req authz.Request, what string) (authz.Decision, bool) {
	t.Helper()
	status, raw := s.post(t, s.token, req, what)
	if status != http.StatusOK {
		t.Errorf("%s answered %d; a decision, allow or deny, is a 200", what, status)
		return authz.Decision{}, false
	}
	return checkShape(t, what, raw)
}

// refusesAnUnknownAction: an action the core's table does not name is a
// malformed request and answers 400, not a deny. A reason is for a
// decision a core can act on, and there is no decision to be had about a
// string the vocabulary does not carry. The check runs only under
// WithVocabulary: with a hand-written list the suite cannot tell an
// action the core omitted from one it does not have.
func (s *suite) refusesAnUnknownAction(t testing.TB) {
	t.Helper()
	if len(s.vocabulary.Actions) == 0 {
		return
	}
	action := "conformance.unknown." + freshID()
	req := authz.Request{
		Action:   action,
		Resource: authz.NewResource(s.actions[0].Kind, freshID(), map[string]any{}),
		Request:  authz.Caller{ID: "conformance-" + freshID(), IP: "203.0.113.4", UserAgent: "authz/conformance"},
		Claims:   map[string]any{},
	}
	setSubject(&req, s.subjects[0])
	what := fmt.Sprintf("the unknown action %q", action)
	if status, _ := s.post(t, s.token, req, what); status != http.StatusBadRequest {
		t.Errorf("%s answered %d; an action outside %s's vocabulary is a malformed request and answers 400, never a deny", what, status, s.vocabulary.Core)
	}
}

// deniesTheProbe: the reserved id is denied for every subject, the
// anonymous one included, and every action, with a reason. A page action
// is no exception: an endpoint denies the probe before it routes, because
// a page carries no verdict and a check command reads a probe that is not
// denied as an endpoint that does not read the request.
func (s *suite) deniesTheProbe(t testing.TB) {
	t.Helper()
	for _, subject := range append([]string{""}, s.subjects...) {
		for _, a := range s.actions {
			req := authz.Probe(a.Name, a.Kind)
			setSubject(&req, subject)
			what := fmt.Sprintf("the probe as %q for %s", subject, a.Name)
			status, raw := s.post(t, s.token, req, what)
			if status != http.StatusOK {
				t.Errorf("%s answered %d; the probe is a request like any other and is denied with a 200", what, status)
				continue
			}
			d, ok := checkShape(t, what, raw)
			if ok && d.Allow {
				t.Errorf("%s was allowed; every authorizer denies the probe id %s, and a core's check command reads an allow as an endpoint that does not read the request", what, authz.ProbeID)
			}
		}
	}
}

// refusesAWrongBearer: a request under another bearer, and one under
// none, is not answered with a 200.
func (s *suite) refusesAWrongBearer(t testing.TB) {
	t.Helper()
	req := authz.Probe(s.actions[0].Name, s.actions[0].Kind)
	for _, tc := range []struct {
		name, token string
	}{{"a wrong bearer", s.token + "-wrong"}, {"no bearer", ""}} {
		if status, _ := s.post(t, tc.token, req, tc.name); status == http.StatusOK {
			t.Errorf("%s was answered with a 200; the authorizer does not check its bearer", tc.name)
		}
	}
}

// answersAWellFormedRequest: a request from each subject for each action
// on a fresh id is a 200 whose body has the contract's shape, and a deny
// carries a reason. An action WithPageActions named answers a page of the
// core's own shape, which the contract fixes nothing about beyond the 200
// and a JSON object. Told no page actions, the run accepts either shape
// for an action whose verb is list — a body carrying allow is read as a
// decision and checked as one — and requires a decision everywhere else.
func (s *suite) answersAWellFormedRequest(t testing.TB) {
	t.Helper()
	for _, subject := range s.subjects {
		for _, a := range s.actions {
			req := authz.Request{
				Action:   a.Name,
				Resource: authz.NewResource(a.Kind, freshID(), map[string]any{"owner": subject}),
				Request:  authz.Caller{ID: "conformance-" + freshID(), IP: "203.0.113.4", UserAgent: "authz/conformance"},
				Claims:   map[string]any{},
			}
			setSubject(&req, subject)
			what := fmt.Sprintf("%s by %q", a.Name, subject)
			status, raw := s.post(t, s.token, req, what)
			if status != http.StatusOK {
				t.Errorf("%s answered %d; a decision, allow or deny, is a 200", what, status)
				continue
			}
			switch {
			case s.pagesSet:
				// The run was told which actions are pages, so each
				// answer is held to the shape its action declares.
				if s.isPage(a.Name) {
					checkPage(t, what, raw)
				} else {
					checkShape(t, what, raw)
				}
			case authz.IsList(a.Name) && !carriesAllow(raw):
				// Told none, a list that answers no verdict is the core's
				// page; one that carries allow is a decision and is read
				// as one.
				checkPage(t, what, raw)
			default:
				checkShape(t, what, raw)
			}
		}
	}
}

// setSubject fills the three subject fields from a rendered subject.
func setSubject(req *authz.Request, subject string) {
	req.Subject = subject
	req.Issuer, req.Sub, _ = authz.SplitSubject(subject)
}

// post sends one envelope and returns the status and body. A call that
// produces no response fails the run: nothing else can be checked.
func (s *suite) post(t testing.TB, token string, req authz.Request, what string) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("%s: encoding the envelope: %v", what, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), authz.Timeout)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(r)
	if err != nil {
		t.Fatalf("%s: the authorizer at %s did not answer: %v", what, s.url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("%s: reading the answer: %v", what, err)
	}
	return resp.StatusCode, raw
}

// checkPage reads a 200 body that is a page of the core's own shape. The
// contract fixes no field of it: an endpoint answers a directory page, a
// refusal in its own shape, or an object saying there is no directory. A
// JSON object is all that is checked.
func checkPage(t testing.TB, what string, raw []byte) {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Errorf("%s: the body is not a JSON object: %v", what, err)
	}
}

// carriesAllow reports whether a body is an object with an allow field,
// which is a decision and is checked as one.
func carriesAllow(raw []byte) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	_, ok := obj["allow"]
	return ok
}

// checkShape reads a 200 body against the contract: allow a boolean, ttl
// when present a positive integer, limits when present an object, filter
// when present an object of owners ([]string) and labels
// (map[string]string) and nothing else, reason when present a string,
// and a deny carrying a non-empty reason. ok is false when the body is
// no decision at all.
func checkShape(t testing.TB, what string, raw []byte) (authz.Decision, bool) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Errorf("%s: the body is not a JSON object: %v", what, err)
		return authz.Decision{}, false
	}
	allow, present := fields["allow"]
	if !present {
		t.Errorf("%s: the body has no allow field; a 200 without one is no answer and a core fails closed on it", what)
		return authz.Decision{}, false
	}
	var verdict bool
	if err := json.Unmarshal(allow, &verdict); err != nil {
		t.Errorf("%s: allow is %s; it is a boolean", what, allow)
		return authz.Decision{}, false
	}
	if ttl, present := fields["ttl"]; present && !isNull(ttl) && !isPositiveInteger(ttl) {
		t.Errorf("%s: ttl is %s; it is a positive integer of seconds", what, ttl)
	}
	if limits, present := fields["limits"]; present && !isNull(limits) {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(limits, &obj); err != nil {
			t.Errorf("%s: limits is %s; it is an object of the core's figures", what, limits)
		}
	}
	if filter, present := fields["filter"]; present && !isNull(filter) {
		checkFilter(t, what, filter)
	}
	var reason string
	if r, present := fields["reason"]; present && !isNull(r) {
		if err := json.Unmarshal(r, &reason); err != nil {
			t.Errorf("%s: reason is %s; it is a string", what, r)
		}
	}
	if !verdict && reason == "" {
		t.Errorf("%s: a deny with no reason; the reason is the developer detail of the core's 403", what)
	}
	d, err := authz.ParseDecision(raw)
	if err != nil {
		t.Errorf("%s: the client reads the body as no decision: %v", what, err)
		return authz.Decision{}, false
	}
	return d, true
}

// checkFilter reads a filter object: owners a list of strings, labels a
// map of strings, and no other key.
func checkFilter(t testing.TB, what string, filter json.RawMessage) {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(filter, &obj); err != nil {
		t.Errorf("%s: filter is %s; it is an object of owners and labels", what, filter)
		return
	}
	for k, v := range obj {
		switch k {
		case "owners":
			var owners []string
			if !isNull(v) && json.Unmarshal(v, &owners) != nil {
				t.Errorf("%s: filter.owners is %s; it is a list of rendered subjects", what, v)
			}
		case "labels":
			var labels map[string]string
			if !isNull(v) && json.Unmarshal(v, &labels) != nil {
				t.Errorf("%s: filter.labels is %s; it is a map of string to string", what, v)
			}
		default:
			t.Errorf("%s: filter carries %q; the contract's filter is owners and labels", what, k)
		}
	}
}

func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// isPositiveInteger reports whether raw is a JSON number, not a quoted
// one, that is a whole number above zero.
func isPositiveInteger(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, err := n.Int64()
	return err == nil && i > 0
}

// freshID is a random id no object has, so a well-formed request is about
// an object the authorizer has never seen and the answer is not a cached
// one.
func freshID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
