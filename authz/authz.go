// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package authz is the one authorizer contract the open cores share
// (latere-ai/specs, decisions/2026-09-13-one-platform-open-cores.md, C3
// and C4). A core verifies a token, renders its subject, and asks one
// endpoint whether that subject may do one action to one resource; the
// endpoint decides from the claims it is handed and its own state, and
// the core caches the answer, fails closed, and decides nothing itself.
//
// The package carries the envelope ([Request], [Decision]), the client
// with the cache and the failure rules every core runs ([Client]), the
// probe every authorizer must deny ([ProbeID], [Check]), the subject
// rendering ([Subject]), the owner policy a core applies when no
// authorizer is configured ([Policy]), and the intersection with the
// grants a credential carries ([Restrict]). The stub authorizer the
// cores' test tiers run is authz/stub, and the scaffold an endpoint is
// written on is authz/server. A core adds its action vocabulary and the
// fields of its resource kinds; nothing here names a product.
//
// A decision is the decision point's own answer, narrowed. [Restrict] is
// the narrowing: a personal access token carries the grants its holder
// chose, and a decision point intersects its answer with them, which
// turns an allow into a deny and never a deny into an allow. An endpoint
// written on authz/server gets it by construction.
//
// A core declares that vocabulary as data, [Vocabulary] over [Action],
// in a package it publishes at its module root. One declaration is then
// read by the client, which refuses an action outside it before the wire
// ([Options.Vocabulary]); by the endpoint, which answers 400 for one
// (authz/server); and by the conformance suite, which drives a case per
// row rather than the rows somebody wrote out by hand
// (conformance.WithVocabulary). The action strings stay the core's: this
// package names none.
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProbeID is the reserved resource id every authorizer denies for every
// subject and every action, the anonymous subject included. A core's
// check command sends it and reads an allow as an endpoint that does not
// read the request.
const ProbeID = "00000000-0000-0000-0000-000000000001"

// The cache and failure rules of the contract (C4).
const (
	// Timeout bounds one call, the retry included.
	Timeout = 5 * time.Second
	// DefaultTTL is how long an allow is cached when the answer names no
	// ttl; MaxTTL caps one it does name.
	DefaultTTL = 60 * time.Second
	MaxTTL     = 600 * time.Second
	// DenyTTL is how long a deny is cached. An unavailable answer is
	// never cached.
	DenyTTL = 5 * time.Second
	// CacheEntries bounds the decision cache; the least recently used
	// entry is evicted past it.
	CacheEntries = 65536
)

// Subject renders a token's issuer and subject as the one string every
// core stores and sends: the issuer with its trailing slash removed, a
// pipe, and the sub claim. Two issuers that agree on a sub are two
// subjects. An empty sub renders as the empty string, the anonymous
// subject, whatever the issuer.
func Subject(issuer, sub string) string {
	if sub == "" {
		return ""
	}
	return strings.TrimRight(issuer, "/") + "|" + sub
}

// SplitSubject takes a rendered subject apart. ok is false for the empty
// string and for a string that carries no separator, which is a bare sub
// from before the rendering or a subject a core minted itself.
func SplitSubject(subject string) (issuer, sub string, ok bool) {
	i := strings.LastIndexByte(subject, '|')
	if subject == "" || i < 0 {
		return "", "", false
	}
	return subject[:i], subject[i+1:], true
}

// Request is the envelope one call carries.
//
// Subject is the rendered subject, empty for an anonymous request and for
// the probe. Issuer and Sub are its two halves apart. Claims is every
// verified claim of the token, verbatim: the core reads none of them, and
// the authorizer reads whichever its policy needs. Action is the core's
// vocabulary. Resource names what the action touches.
type Request struct {
	Subject  string         `json:"subject"`
	Issuer   string         `json:"issuer"`
	Sub      string         `json:"sub"`
	Claims   map[string]any `json:"claims"`
	Workload map[string]any `json:"workload,omitempty"`
	Action   string         `json:"action"`
	Resource Resource       `json:"resource"`
	Request  Caller         `json:"request"`
}

// Caller is what the authorizer learns about the request itself: the
// core's request id, the peer address, and the user agent.
type Caller struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

// Resource is the object of an action: its kind, its id, and the fields
// the core's spec names for that kind. On the wire it is one flat object,
// kind and id beside the fields, so an authorizer reads resource.owner
// and not resource.fields.owner. A create carries no id.
type Resource struct {
	Kind   string
	ID     string
	Fields map[string]any
}

// NewResource builds a resource. fields may be nil.
func NewResource(kind, id string, fields map[string]any) Resource {
	return Resource{Kind: kind, ID: id, Fields: fields}
}

// String reads one field as a string, "" when it is absent or not one.
func (r Resource) String(field string) string {
	s, _ := r.Fields[field].(string)
	return s
}

// Int reads one field as an integer, 0 when it is absent or not a number.
// JSON numbers decode as float64, which is the form the read accepts.
func (r Resource) Int(field string) int {
	switch v := r.Fields[field].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// MarshalJSON renders the flat object.
func (r Resource) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(r.Fields)+2)
	for k, v := range r.Fields {
		if k == "kind" || k == "id" {
			continue
		}
		out[k] = v
	}
	out["kind"] = r.Kind
	if r.ID != "" {
		out["id"] = r.ID
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads the flat object.
func (r *Resource) UnmarshalJSON(b []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*r = Resource{}
	for k, v := range raw {
		switch k {
		case "kind":
			r.Kind, _ = v.(string)
		case "id":
			r.ID, _ = v.(string)
		default:
			if r.Fields == nil {
				r.Fields = map[string]any{}
			}
			r.Fields[k] = v
		}
	}
	return nil
}

// Decision is an authorizer's answer with the defaults applied.
//
// Limits is the answer's limits object as it came, for the core to decode
// into the figures its spec names; nil when the answer carried none.
// Filter is set on a list action the authorizer narrowed.
type Decision struct {
	Allow  bool
	Reason string
	TTL    time.Duration
	Limits json.RawMessage
	Filter *Filter
}

// Filter narrows a core's own list to owners and labels.
type Filter struct {
	Owners []string          `json:"owners,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// DecodeLimits reads the limits object into v. A decision with no limits
// leaves v untouched and returns nil.
func (d Decision) DecodeLimits(v any) error {
	if len(d.Limits) == 0 {
		return nil
	}
	return json.Unmarshal(d.Limits, v)
}

// answer is the wire form of a decision.
type answer struct {
	Allow  *bool           `json:"allow"`
	Reason string          `json:"reason"`
	TTL    *int            `json:"ttl"`
	Limits json.RawMessage `json:"limits"`
	Filter *Filter         `json:"filter"`
}

// ParseDecision reads one 200 body. A body with no allow field is no
// answer: it is an *Unavailable, never an allow.
func ParseDecision(raw []byte) (Decision, error) {
	var a answer
	if err := json.Unmarshal(raw, &a); err != nil {
		return Decision{}, fmt.Errorf("body: %w", err)
	}
	if a.Allow == nil {
		return Decision{}, errors.New("body: no allow field")
	}
	d := Decision{Allow: *a.Allow, Reason: a.Reason, TTL: DefaultTTL, Filter: a.Filter}
	if len(a.Limits) > 0 && string(a.Limits) != "null" {
		d.Limits = a.Limits
	}
	if a.TTL != nil && *a.TTL > 0 {
		d.TTL = min(time.Duration(*a.TTL)*time.Second, MaxTTL)
	}
	return d, nil
}

// Authorizer decides one request. A deny is a Decision, not an error; an
// error is a call that produced no decision, and a core fails closed on it.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (Decision, error)
}

// Probe is the request a check command sends: no subject, the reserved
// id, the action and kind the core names.
func Probe(action, kind string) Request {
	return Request{Action: action, Resource: Resource{Kind: kind, ID: ProbeID}}
}

// ErrProbeAllowed reports an authorizer that allowed the probe, which is
// an endpoint that does not read the request.
var ErrProbeAllowed = errors.New("authz: the authorizer allowed the probe id, so it does not read the request")

// Check sends the probe and reports an authorizer that answered nothing
// or allowed it. A deny is the one right answer.
func Check(ctx context.Context, a Authorizer, action, kind string) error {
	d, err := a.Authorize(ctx, Probe(action, kind))
	if err != nil {
		return err
	}
	if d.Allow {
		return ErrProbeAllowed
	}
	return nil
}
