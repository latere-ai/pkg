// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package stub is the stub authorizer the cores' test tiers run: a rule
// table a test chooses the answers from, a record of every request in
// order, and two failure modes for the outage cases, behind the contract
// of latere.ai/x/pkg/authz. It speaks that contract alone.
//
// One rule of the contract binds every authorizer, this one included: the
// probe id is denied for every subject and action, because a core's check
// command treats an allow on it as a misconfigured authorizer.
//
// Told a core's vocabulary through WithVocabulary, the stub refuses an
// action outside it with a 400, the one answer the contract gives an
// unknown action, and narrows an allow by the grants the request's token
// carries, the way every conforming endpoint does. The vocabulary is what
// makes the second possible: the claim names an action qualified by its
// core, and the core is the table's.
//
// The control API is HTTP as well as methods, so a stack run drives the
// stub through a host port: PUT /rules, GET and DELETE /requests, PUT
// /fail, POST /hang, POST /resume. A core adds an action with an answer
// shape of its own through WithAction, which is the stub's half of
// authz/server's Options.PageActions: an action registered there answers
// a page and every other answers a decision from the rule table, a list
// action included. The verb decides nothing.
//
// The outage modes are the forms of unavailability the contract names
// (Lux spec 006): a status other than 200 (Fail), a 200 whose body is not
// JSON or parses but carries no allow (FailBody), and no answer at all
// (Hang). A core's client treats every one of them as *authz.Unavailable
// and fails closed.
package stub

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"latere.ai/x/pkg/authz"
)

// DefaultToken is the bearer the stub expects unless WithToken sets
// another.
const DefaultToken = "stub-authorizer-token"

// Rule is one row of the table. Subject, Action, and Resource are `*` or
// a value; Resource is the resource id, or the name WithResourceName
// renders. An empty field matches everything, the same as `*`. TTL and
// Limits are sent only when set, so the core applies its defaults
// otherwise; Limits is the limits object as the core's spec names it.
type Rule struct {
	Subject  string         `json:"subject"`
	Action   string         `json:"action"`
	Resource string         `json:"resource"`
	Allow    bool           `json:"allow"`
	Reason   string         `json:"reason,omitempty"`
	TTL      int            `json:"ttl,omitempty"`
	Limits   map[string]any `json:"limits,omitempty"`
	Filter   *authz.Filter  `json:"filter,omitempty"`
}

func star(pattern, value string) bool {
	return pattern == "" || pattern == "*" || pattern == value
}

// Answer builds a core's own answer to one request; it is what WithAction
// registers. The body it returns is written as the 200.
type Answer func(req authz.Request) any

// Body is a 200 that is no answer, the second kind of outage: FailBody
// selects one, and PUT /fail takes it as {"body": "<mode>"}.
type Body string

const (
	// BodyMalformed is a 200 whose body is not JSON.
	BodyMalformed Body = "malformed"
	// BodyNoAllow is a 200 whose body parses but carries no allow field.
	BodyNoAllow Body = "no-allow"
)

// bodies are the bytes each Body mode writes.
var bodies = map[Body]string{
	BodyMalformed: "{not json",
	BodyNoAllow:   `{"reason":"an answer with no verdict"}`,
}

// Option configures a Server.
type Option func(*Server)

// WithToken sets the bearer the endpoint requires.
func WithToken(token string) Option {
	return func(s *Server) { s.token = token }
}

// WithAllow sets the subjects allowed when no rule matches, `*` for all.
// The default is `*`; WithAllow() with no subject allows nobody by
// default.
func WithAllow(subjects ...string) Option {
	return func(s *Server) { s.allow = subjects }
}

// WithResourceName sets how a rule's Resource matches a resource that is
// not named by its id: the function renders the name, Origo's
// owner/slug for one.
func WithResourceName(name func(authz.Resource) string) Option {
	return func(s *Server) { s.name = name }
}

// WithVocabulary gives the stub the core's action table, so an action
// outside it is refused with a 400 the way latere.ai/x/pkg/authz/server
// refuses one, rather than answered from the rule table. A stub told no
// vocabulary answers every action, which is how it behaved before.
func WithVocabulary(v authz.Vocabulary) Option {
	return func(s *Server) { s.vocabulary = v }
}

// WithAction registers an action whose 200 body is a page of the core's
// own shape rather than a decision — the stub's half of authz/server's
// Options.PageActions, and the one way an action here stops answering a
// decision. An action left unregistered answers from the rule table
// whatever its verb, so a list action answers the decision the table
// names, Rule.Filter included, which is what a core whose lists are
// decisions gets.
//
// The rule table, the recording, and the outage modes still apply: the
// answer is built only for a request that reached the table, and never
// for the probe id, which is denied for every action.
func WithAction(action string, answer Answer) Option {
	return func(s *Server) { s.actions[action] = answer }
}

// Server is one stub authorizer.
type Server struct {
	mu         sync.Mutex
	token      string
	allow      []string
	name       func(authz.Resource) string
	vocabulary authz.Vocabulary
	actions    map[string]Answer
	rules      []Rule
	requests   []authz.Request
	fail       int
	failBody   Body
	hung       chan struct{}
	closed     chan struct{}
	srv        *httptest.Server
	mux        *http.ServeMux
}

// New starts a stub for the test and stops it with the test.
func New(t testing.TB, opts ...Option) *Server {
	t.Helper()
	s := NewHandler(opts...)
	s.srv = httptest.NewServer(s.mux)
	t.Cleanup(s.Close)
	return s
}

// NewHandler builds a stub without a listener, for a binary that serves
// Handler itself.
func NewHandler(opts ...Option) *Server {
	s := &Server{token: DefaultToken, allow: []string{"*"}, actions: map[string]Answer{}, closed: make(chan struct{}), mux: http.NewServeMux()}
	for _, o := range opts {
		o(s)
	}
	s.mux.HandleFunc("POST /{$}", s.decide)
	s.mux.HandleFunc("PUT /rules", s.putRules)
	s.mux.HandleFunc("GET /requests", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Requests()) })
	s.mux.HandleFunc("DELETE /requests", func(w http.ResponseWriter, _ *http.Request) { s.ClearRequests(); w.WriteHeader(http.StatusNoContent) })
	s.mux.HandleFunc("PUT /fail", s.putFail)
	s.mux.HandleFunc("POST /hang", func(w http.ResponseWriter, _ *http.Request) { s.Hang(); w.WriteHeader(http.StatusNoContent) })
	s.mux.HandleFunc("POST /resume", func(w http.ResponseWriter, _ *http.Request) { s.Resume(); w.WriteHeader(http.StatusNoContent) })
	return s
}

// Handler serves the endpoint and the control API.
func (s *Server) Handler() http.Handler { return s.mux }

// Close stops the listener and releases every hung request.
func (s *Server) Close() {
	s.mu.Lock()
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.mu.Unlock()
	if s.srv != nil {
		s.srv.Close()
	}
}

// URL is the endpoint, the value a core's authorizer URL variable takes.
func (s *Server) URL() string { return s.srv.URL }

// Token is the bearer the endpoint requires.
func (s *Server) Token() string { return s.token }

// Allow adds an allow rule. A later rule wins over an earlier one that
// matches the same request.
func (s *Server) Allow(rule Rule) {
	rule.Allow = true
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, rule)
}

// Deny adds a deny rule with the reason.
func (s *Server) Deny(rule Rule, reason string) {
	rule.Allow, rule.Reason = false, reason
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, rule)
}

// SetRules replaces the table, what a PUT of /rules does.
func (s *Server) SetRules(rules ...Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = slices.Clone(rules)
}

// Requests lists every request seen, in order.
func (s *Server) Requests() []authz.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// ClearRequests empties the list.
func (s *Server) ClearRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
}

// Fail makes every answer the given status; 0 restores the rule table.
// It replaces a FailBody in force.
func (s *Server) Fail(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail, s.failBody = status, ""
}

// FailBody makes every answer a 200 with a body that is no answer, the
// mode's; "" restores the rule table. It replaces a Fail in force.
func (s *Server) FailBody(mode Body) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail, s.failBody = 0, mode
}

// Hang makes the endpoint never answer until Resume or Close.
func (s *Server) Hang() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hung == nil {
		s.hung = make(chan struct{})
	}
}

// Resume clears Hang, Fail, and FailBody: the next request is answered
// from the rule table.
func (s *Server) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail, s.failBody = 0, ""
	if s.hung != nil {
		close(s.hung)
		s.hung = nil
	}
}

// Decide answers one request from the table, the way the endpoint does.
func (s *Server) Decide(req authz.Request) Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.EqualFold(req.Resource.ID, authz.ProbeID) {
		return Rule{Allow: false, Reason: "the probe id is reserved"}
	}
	for _, v := range slices.Backward(s.rules) {
		if s.matches(v, req) {
			return v
		}
	}
	if slices.Contains(s.allow, "*") || slices.Contains(s.allow, req.Subject) {
		return Rule{Allow: true}
	}
	return Rule{Allow: false, Reason: "no rule allows " + req.Subject}
}

// matches reports whether a rule covers a request. Called with mu held.
func (s *Server) matches(r Rule, req authz.Request) bool {
	if !star(r.Subject, req.Subject) || !star(r.Action, req.Action) {
		return false
	}
	if star(r.Resource, req.Resource.ID) {
		return true
	}
	return s.name != nil && s.name(req.Resource) != "" && r.Resource == s.name(req.Resource)
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	raw, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(raw)), []byte(s.token)) != 1 {
		http.Error(w, "bearer required", http.StatusUnauthorized)
		return
	}
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req authz.Request
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, req)
	fail, failBody, hung, answer, vocabulary := s.fail, s.failBody, s.hung, s.actions[req.Action], s.vocabulary
	s.mu.Unlock()
	// Validation precedes the outage modes, the way the scaffold validates
	// before it reaches a decider: a request the endpoint refuses to read
	// is refused whatever else is in force. It is recorded first, so
	// Requests still lists every request that arrived.
	if len(vocabulary.Actions) > 0 && !vocabulary.Known(req.Action) {
		http.Error(w, req.Action+" is not one of "+vocabulary.Core+"'s actions", http.StatusBadRequest)
		return
	}
	if hung != nil {
		select {
		case <-hung:
		case <-s.closed:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	if fail != 0 {
		http.Error(w, "failing on request", fail)
		return
	}
	if failBody != "" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, bodies[failBody])
		return
	}
	// The probe is denied before a core's own answer is built: the rule
	// that the reserved id is never allowed binds every action, and an
	// action registered through WithAction answers a page that carries no
	// verdict at all. The scaffold of latere.ai/x/pkg/authz/server denies
	// it before it routes a PageActions to its Lister, for the same
	// reason.
	if answer != nil && !strings.EqualFold(req.Resource.ID, authz.ProbeID) {
		writeJSON(w, answer(req))
		return
	}
	rule := s.Decide(req)
	if vocabulary.Core != "" {
		rule = restrict(vocabulary.Core, rule, req)
	}
	if !rule.Allow {
		writeJSON(w, map[string]any{"allow": false, "reason": rule.Reason})
		return
	}
	out := map[string]any{"allow": true}
	if rule.TTL != 0 {
		out["ttl"] = rule.TTL
	}
	if len(rule.Limits) != 0 {
		out["limits"] = rule.Limits
	}
	if rule.Filter != nil {
		out["filter"] = rule.Filter
	}
	writeJSON(w, out)
}

// restrict narrows one answer by the grants the request's token carries,
// the way a conforming endpoint does (latere.ai/x/pkg/authz.Restrict). A
// stub told a vocabulary knows its core, which is what qualifies the
// request's bare action against the claim's core:action; a stub told none
// answers the rule table alone, which is how it behaved before.
//
// A claim that cannot be read as grants is a deny, the same closed answer
// authz/server gives one.
func restrict(core string, rule Rule, req authz.Request) Rule {
	grants, err := authz.ParseGrants(req.Claims)
	if err != nil {
		return Rule{Reason: authz.ReasonGrant}
	}
	d := authz.Restrict(core, authz.Decision{Allow: rule.Allow, Reason: rule.Reason}, req, grants)
	if !d.Allow {
		return Rule{Reason: d.Reason}
	}
	return rule
}

func (s *Server) putRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.SetRules(body.Rules...)
	w.WriteHeader(http.StatusNoContent)
}

// putFail reads {"status": <int>} and calls Fail with it, or {"body":
// "malformed"} or {"body": "no-allow"} and calls FailBody; {"status": 0}
// clears either outage. A body mode it does not know is a 400.
func (s *Server) putFail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status int  `json:"status"`
		Body   Body `json:"body"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Body != "" {
		if _, ok := bodies[body.Body]; !ok {
			http.Error(w, "unknown body mode "+string(body.Body), http.StatusBadRequest)
			return
		}
		s.FailBody(body.Body)
	} else {
		s.Fail(body.Status)
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
