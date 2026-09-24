// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package server is the endpoint half of the one authorizer contract the
// open cores share. It is the scaffold every authorizer needs and no
// authorizer should write twice:
// the bearer and its successor, the body bound, the decode into
// [authz.Request], the validation against the core's [authz.Vocabulary],
// the probe rule, the failure mapping, and the 200 body. What it does not
// own is the answer.
//
//	core                  authz/server                  the control plane
//	----                  ------------                  -----------------
//	POST envelope  ---->  bearer: current or next
//	                      max body, decode
//	                      action and kind
//	                      the probe id
//	                      route: decision or page
//	                      --------------------------->  Decider.Decide, or
//	                                                    Lister.List for an
//	                                                    action of PageActions
//	                      <---------------------------  (Decision, error)
//	                      ErrUnavailable -> 503
//	                      intersect with the token's grants
//	                      write the decision, count it
//	<---- 200 / 400 / 401 / 405 / 500 / 503
//
// One call wires an endpoint:
//
//	http.Handle("POST /internal/authz/origo", server.New(server.Options{
//	        Bearer:     os.Getenv("PLATFORM_AUTHZ_TOKEN_ORIGO"),
//	        BearerNext: os.Getenv("PLATFORM_AUTHZ_TOKEN_ORIGO_NEXT"),
//	        Vocabulary: origoauthorizer.Vocabulary(),
//	        Decider:    snapshots,
//	}))
//
// Every action of the vocabulary is decided, one whose verb is list
// included: its answer is a decision whose [authz.Decision.Filter]
// narrows the core's own list. The exception is an action whose answer is
// a page of the core's own shape (Origo's repo.list, a directory page
// with fields and a cursor this contract does not fix), which a core
// names in [Options.PageActions] and a [Lister] answers.
//
// Everything a decision reads (the tables, the roles, the plans) stays
// with whoever wrote the [Decider]. What the scaffold adds to the answer
// is one thing: the grants the caller's own credential carries.
// A personal access token is narrowed by
// what its holder chose, and [authz.Restrict] intersects the decider's
// answer with that set before it is written and before it is counted. It
// is not an option and there is no way to switch it off, so an endpoint
// on this scaffold enforces grants by construction.
//
// Nothing here names a product, and a self-hoster writing a twenty-line
// authorizer for one core gets the bearer, the envelope, the validation,
// the grants and the failure rules right by construction.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/httpjson"
)

// Decider answers one request from the control plane's own state, every
// action of the vocabulary but the ones [Options.PageActions] names. A
// deny is an [authz.Decision] and never an error; an error is a call that
// produced no decision. A list action is a decision like any other, and
// [authz.Decision.Filter] is how the answer narrows the core's own list.
type Decider interface {
	Decide(ctx context.Context, req authz.Request) (authz.Decision, error)
}

// Lister answers an action whose reply has a shape of the core's own: a
// directory page, with the fields and the cursor the core's spec names.
// The handler writes what it returns and caches nothing. Which actions
// those are is [Options.PageActions] and never the action's verb: a page
// is the exception a core declares, not what every list does.
//
// The return is untyped on purpose, and symmetric with the client half:
// [authz.Client.Ask] returns the bytes of such an answer and leaves the
// core to parse them, because the contract fixes the envelope going in
// and not the page coming back. Origo's page, for one, is
// {"repos": [...], "next_cursor": "..."} for a page,
// {"allow": false, "reason": "..."} for a refusal and {"directory":
// false} for an installation with no directory — three shapes of Origo's
// own that this package must not name.
type Lister interface {
	List(ctx context.Context, req authz.Request) (any, error)
}

// ErrUnavailable is the decider's "I cannot answer": no snapshot, a
// snapshot too stale for this action, a store the section cannot read. It
// is rendered as a 503, which a core reads as authorizer_unavailable and
// never as an allow. A decider returns it wrapped or bare, or through
// [Unavailable] to name the reason the 503 is counted with.
var ErrUnavailable = errors.New("authz: the decider cannot answer")

// unavailable is ErrUnavailable carrying a decider's reason.
type unavailable struct{ reason string }

func (u *unavailable) Error() string { return ErrUnavailable.Error() + ": " + u.reason }
func (u *unavailable) Unwrap() error { return ErrUnavailable }

// Unavailable is [ErrUnavailable] with the reason the decider could not
// answer — "no_snapshot", "stale_snapshot" — which the handler counts
// with the 503 and writes nowhere else: the body a core reads is the same
// whatever the reason. errors.Is(Unavailable(r), ErrUnavailable) holds,
// so a caller that only matches the sentinel is unaffected. The reasons
// are a decider's own bounded list, the way decision reasons are.
func Unavailable(reason string) error { return &unavailable{reason: reason} }

// DefaultMaxBody bounds one envelope when Options names no other. An
// envelope is a subject, an action, a resource of a few short fields and
// the token's claims; a body past this is not a core.
const DefaultMaxBody = 64 << 10

// The counter's attribute values. result is allow, deny, list — a page of
// [Options.PageActions], whose own verdict is the core's to count —
// unavailable, or error.
const (
	resultAllow       = "allow"
	resultDeny        = "deny"
	resultList        = "list"
	resultUnavailable = "unavailable"
	resultError       = "error"
	// reasonUnavailable is what a 503 is counted with when the decider
	// named no reason of its own; reasonError is every other failure.
	reasonUnavailable = "unavailable"
	reasonError       = "decider_error"
)

// Options configures a handler.
type Options struct {
	// Bearer is the token the endpoint requires and BearerNext its
	// successor, both accepted so a rotation is two deploys and no
	// outage. An unset token matches nothing, so an endpoint configured
	// with neither answers 401 to everything, which is the closed
	// failure.
	Bearer, BearerNext string
	// Vocabulary is the core's action table. Required: every action and
	// every resource kind is validated against it.
	Vocabulary authz.Vocabulary
	// MaxBody bounds one envelope. DefaultMaxBody when zero.
	MaxBody int64
	// Decider answers every action the vocabulary names but the ones
	// PageActions does. Required.
	Decider Decider
	// PageActions are the actions whose answer is a page of the core's
	// own shape rather than a decision — Origo's repo.list, which is a
	// directory page. Each must be an action of the Vocabulary, and each
	// is routed to the Lister. Empty is the ordinary case: every action,
	// a list included, is decided.
	//
	// The verb is not the rule. An action named list answers a decision
	// whose [authz.Decision.Filter] narrows the core's own list, which is
	// what Cella's and Lux's list actions do; a page is what a core
	// declares here.
	PageActions []string
	// Lister answers the PageActions. Required when PageActions names
	// one, unused otherwise.
	Lister Lister
	// Logger records a decider that failed. Optional; nothing is logged
	// without one, and no request field is ever logged.
	Logger *slog.Logger
	// Meter counts every answer past validation, {result, reason}.
	// Optional. Its scope name is what tells two endpoints of one process
	// apart.
	Meter metric.Meter
}

// The error document is the one a core's control plane already answers
// with: error the code, message the one user sentence fixed beside it,
// detail the developer's.
type errorDocument struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// The codes and their one sentence each.
const (
	codeMethod       = "method_not_allowed"
	codeUnauthorized = "unauthorized"
	codeInvalid      = "invalid_request"
	codeUnavailable  = "unavailable"
	codeInternal     = "internal_error"

	msgMethod       = "This endpoint answers POST."
	msgUnauthorized = "A bearer token is required."
	msgInvalid      = "The request body could not be read."
	msgUnavailable  = "Permissions cannot be checked right now. Try again in a few minutes."
	msgInternal     = "Something went wrong. Try again in a few minutes."
)

// answer is the wire form of a decision. allow is always written, so a
// 200 is never a body that is no answer; every other field is omitted
// when it is nothing.
type answer struct {
	Allow  bool            `json:"allow"`
	Reason string          `json:"reason,omitempty"`
	TTL    int             `json:"ttl,omitempty"`
	Limits json.RawMessage `json:"limits,omitempty"`
	Filter *authz.Filter   `json:"filter,omitempty"`
}

type handler struct {
	bearer, bearerNext string
	vocabulary         authz.Vocabulary
	maxBody            int64
	decider            Decider
	pages              map[string]struct{}
	lister             Lister
	logger             *slog.Logger
	decisions          metric.Int64Counter
}

// New builds the endpoint. It panics on a wiring mistake there is no
// runtime answer to — no Decider, no Vocabulary to validate against, a
// PageActions with no Lister to answer it, or a PageActions entry the
// vocabulary does not name — because each would turn a request into a
// fault or into a 400 nobody wrote, and an authorizer that faults is an
// outage of the core in front of it.
func New(o Options) http.Handler {
	switch {
	case o.Decider == nil:
		panic("authz/server: New needs a Decider")
	case len(o.Vocabulary.Actions) == 0:
		panic("authz/server: New needs a Vocabulary; every action is validated against it")
	case len(o.PageActions) > 0 && o.Lister == nil:
		panic("authz/server: New needs a Lister; PageActions names " + strings.Join(o.PageActions, ", "))
	}
	for _, a := range o.PageActions {
		if !o.Vocabulary.Known(a) {
			panic("authz/server: PageActions names " + a + ", which is not one of " + o.Vocabulary.Core + "'s actions")
		}
	}
	h := &handler{
		bearer: o.Bearer, bearerNext: o.BearerNext, vocabulary: o.Vocabulary,
		maxBody: o.MaxBody, decider: o.Decider, lister: o.Lister, logger: o.Logger,
		pages: make(map[string]struct{}, len(o.PageActions)),
	}
	for _, a := range o.PageActions {
		h.pages[a] = struct{}{}
	}
	if h.maxBody <= 0 {
		h.maxBody = DefaultMaxBody
	}
	if h.logger == nil {
		h.logger = slog.New(slog.DiscardHandler)
	}
	if o.Meter != nil {
		c, err := o.Meter.Int64Counter("latere.authz.decisions",
			metric.WithDescription("Authorization answers written, by result and reason."),
			metric.WithUnit("{decision}"))
		if err != nil {
			h.logger.Warn("authz/server: the decision counter is unavailable", "err", err)
		} else {
			h.decisions = c
		}
	}
	return h
}

// ServeHTTP answers one call. Transport first, then the envelope, then
// the rules that hold whatever the decider says:
//
//	another method                       405
//	a wrong bearer, or none              401
//	a body over the bound, or no JSON    400
//	an action outside the vocabulary     400
//	a resource.kind that is not the action's  400
//	the reserved probe id                200, denied
//	an action of PageActions             the Lister's page
//	anything else                        the Decider's decision
//
// The probe is answered before the routing, so it is denied for a page
// action too: a page carries no verdict, and a core's check command reads
// a probe that is not denied as an endpoint that does not read the
// request.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErr(w, http.StatusMethodNotAllowed, codeMethod, msgMethod, "")
		return
	}
	if !h.bearerOK(r) {
		// A wrong bearer or none is never a 200: a 200 without an answer
		// is what a core would read as a decision.
		writeErr(w, http.StatusUnauthorized, codeUnauthorized, msgUnauthorized, "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalid, msgInvalid, err.Error())
		return
	}
	var req authz.Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalid, msgInvalid, err.Error())
		return
	}
	// An action outside the vocabulary is a malformed request and not a
	// verdict: the reason vocabulary is for decisions a core can act on,
	// and there is no decision to be had about a string the core never
	// declared.
	kind, known := h.vocabulary.Kind(req.Action)
	if !known {
		writeErr(w, http.StatusBadRequest, codeInvalid, msgInvalid,
			"action must be one of "+h.vocabulary.Core+"'s vocabulary; got "+req.Action)
		return
	}
	// A create carries no kind, so an absent one is read as the action's.
	if req.Resource.Kind != "" && req.Resource.Kind != kind {
		writeErr(w, http.StatusBadRequest, codeInvalid, msgInvalid,
			"resource.kind must be "+kind+" for "+req.Action+"; got "+req.Resource.Kind)
		return
	}
	ctx := r.Context()
	if strings.EqualFold(req.Resource.ID, authz.ProbeID) {
		h.count(ctx, resultDeny, authz.ReasonProbe)
		httpjson.Write(w, http.StatusOK, answer{Reason: authz.ReasonProbe})
		return
	}
	if _, page := h.pages[req.Action]; page {
		h.list(w, r, req)
		return
	}
	d, err := h.decider.Decide(ctx, req)
	if err != nil {
		h.failed(w, r, req.Action, err)
		return
	}
	// The grants the caller's token carries narrow the answer, before it
	// is written and before it is counted, so the counter records the
	// answer the core actually got.
	d = h.restrict(req, d)
	result := resultDeny
	if d.Allow {
		result = resultAllow
	}
	h.count(ctx, result, d.Reason)
	httpjson.Write(w, http.StatusOK, render(d))
}

// restrict intersects one decision with the grants the caller's token
// carries. It is not an option and there
// is no way to switch it off: an endpoint on this scaffold enforces
// grants by construction, and a core that bumps this package gets the
// intersection with no code of its own.
//
// The core the actions are qualified by is the vocabulary's, which the
// handler already holds. A claim that cannot be read as grants is a deny:
// the verifier at the core's own door refuses such a token, so one that
// reached here arrived another way, and the closed answer is the only
// safe one.
func (h *handler) restrict(req authz.Request, d authz.Decision) authz.Decision {
	if !d.Allow {
		return d
	}
	grants, err := authz.ParseGrants(req.Claims)
	if err != nil {
		return authz.Decision{Reason: authz.ReasonGrant}
	}
	return authz.Restrict(h.vocabulary.Core, d, req, grants)
}

// list answers an action of PageActions, whose reply is the core's own
// page. A page carries no verdict, so there is nothing for the grants to
// narrow: a core whose directory listing must be narrowed narrows it in
// its own Lister, where the page is built. The verdict inside it is the core's too, so the counter records
// that a page was answered and a core that wants the split counts it in
// its Lister. There is no nil-Lister case: New refuses that wiring.
func (h *handler) list(w http.ResponseWriter, r *http.Request, req authz.Request) {
	page, err := h.lister.List(r.Context(), req)
	if err != nil {
		h.failed(w, r, req.Action, err)
		return
	}
	h.count(r.Context(), resultList, req.Action)
	httpjson.Write(w, http.StatusOK, page)
}

// failed answers a decider that produced no decision. ErrUnavailable,
// wrapped or not, is the 503 a core reads as authorizer_unavailable;
// every other error is a fault of the endpoint's own and a 500. Neither
// is ever an allow, and neither body carries the error: a core that is
// told nothing fails closed just the same, and the text is for the
// endpoint's log.
func (h *handler) failed(w http.ResponseWriter, r *http.Request, action string, err error) {
	if errors.Is(err, ErrUnavailable) {
		reason := reasonUnavailable
		var named *unavailable
		if errors.As(err, &named) && named.reason != "" {
			reason = named.reason
		}
		h.count(r.Context(), resultUnavailable, reason)
		h.logger.WarnContext(r.Context(), "authz/server: the decider cannot answer", "action", action, "reason", reason)
		writeErr(w, http.StatusServiceUnavailable, codeUnavailable, msgUnavailable, "")
		return
	}
	h.count(r.Context(), resultError, reasonError)
	h.logger.ErrorContext(r.Context(), "authz/server: the decider failed", "action", action, "err", err)
	writeErr(w, http.StatusInternalServerError, codeInternal, msgInternal, "")
}

// bearerOK compares the presented bearer with the endpoint's own and with
// its successor, in constant time and with no early exit, so a rotation
// is two deploys and no outage. An unconfigured endpoint accepts nothing.
func (h *handler) bearerOK(r *http.Request) bool {
	presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || presented == "" {
		return false
	}
	match := false
	for _, want := range []string{h.bearer, h.bearerNext} {
		if want == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(want)) == 1 {
			match = true
		}
	}
	return match
}

func (h *handler) count(ctx context.Context, result, reason string) {
	if h.decisions == nil {
		return
	}
	h.decisions.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", result), attribute.String("reason", reason)))
}

// render writes one decision. A ttl is seconds and never above the
// contract's cap, which the client applies anyway.
func render(d authz.Decision) answer {
	a := answer{Allow: d.Allow, Reason: d.Reason, Limits: d.Limits, Filter: d.Filter}
	if d.TTL > 0 {
		a.TTL = int(min(d.TTL, authz.MaxTTL) / time.Second)
	}
	return a
}

func writeErr(w http.ResponseWriter, status int, code, message, detail string) {
	httpjson.Write(w, status, errorDocument{Error: code, Message: message, Detail: detail})
}
