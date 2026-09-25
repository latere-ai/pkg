// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package provenance carries the initiator of a call across service hops as
// W3C Baggage, and emits it on spans, log lines and audit records.
//
// It answers two questions identity does not: on whose behalf did a service
// act, and by what path did the call arrive. The answers are metadata. They
// decide nothing, they grant nothing, and a service that reads them still
// reaches its verdict from the token it verified and its own state.
//
// # Three members, set once
//
// The verified edge -- the first service that validated the person's token --
// calls [Stamp]. Every service downstream calls [From] and never sets:
//
//	MemberSubject  initiator.sub   the issuer-qualified subject, <iss>|<sub>
//	MemberIssuer   initiator.iss   the issuer that minted the verified token
//	MemberEntry    entry           the front door's host, e.g. code.latere.ai
//
// The carrier already exists. otel.Bootstrap installs a composite
// TraceContext+Baggage propagator (pkg/otel/telemetry.go), every outbound
// client is otel.Transport and every server is otel.Handler, so the three
// members ride every hop for free.
//
// # Stamp or Assert, never both
//
// A hop picks one of two roles, and the choice is the package's whole API
// surface (provenance.md, "Three rules, no exceptions"):
//
//   - Edge. It verified a person's token and no upstream stamped. It calls
//     [Stamp], which replaces whatever the three members held. Replacing is
//     safe because the cluster ingress strips any inbound Baggage header
//     before a request reaches a service (provenance.md, Rule 1), so at a
//     real edge there is nothing to replace; and where a header did survive,
//     a verified identity outranks an unauthenticated one.
//   - Verifying hop behind an edge. It verified a person's token and finds an
//     initiator already present. It calls [Assert], which reports disagreement
//     rather than overwriting it (provenance.md, Rule 2). platformd is both,
//     on the same routes, depending on whether origo-web is ahead of it.
//
// A hop that verified a *service* token does neither. A service account
// acting on its own behalf is not an initiator, and the absence of the
// members is the correct record of unattended work (Rule 2, second half).
//
// # Provenance never breaks a call
//
// Baggage is unauthenticated, so nothing here is trusted and nothing here
// fails a request. [Stamp] returns ctx unchanged and logs at warn when a
// value cannot be encoded; [From] reports ok false rather than an error;
// [Assert] is the one function that can return one, and its error is a 400
// for the request that carried the contradiction, not for provenance.
package provenance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"

	"latere.ai/x/pkg/authkit"
	"latere.ai/x/pkg/authz"
)

// The baggage member names, which are also the span and log attribute keys.
// One vocabulary in three places, so a reader who learns it in a log line
// finds it on a span (provenance.md, "The standard").
//
// The prefix is initiator. and never actor.: actor is the family's name for
// the sanctioned one-hop token kind, and reusing it for unauthenticated
// metadata would blur the split this package draws. Entry is a bare member,
// not initiator.entry: it names the front door, not the person.
// Run-scoped tracing takes the run. prefix in the same header, and the two
// do not collide (infrastructure/run-tracing.md, "Shape").
const (
	MemberSubject = "initiator.sub"
	MemberIssuer  = "initiator.iss"
	MemberEntry   = "entry"
)

// Initiator is the person a call is ultimately for, and the front door it
// came through. It is unauthenticated metadata: it grants nothing, and a
// service that reads it must still decide from the token it verified.
type Initiator struct {
	// Subject is the issuer-qualified subject, <iss>|<sub>, as
	// [authz.Subject] renders it. It is the one field that identifies the
	// person; an Initiator without it is not an initiator.
	Subject string
	// Issuer is the issuer that minted the token the edge verified.
	Issuer string
	// Entry is the front door's host, for example platform.latere.ai. It is
	// the edge's own configuration and never a request header, because a
	// header is what an outsider can write.
	Entry string
}

// ErrInitiatorMismatch is the sentinel [Assert] returns, wrapped in a
// [MismatchError], when baggage names an initiator other than the person
// whose token this hop verified. Match it with [errors.Is]; read the two
// subjects with [errors.As].
var ErrInitiatorMismatch = errors.New("provenance: initiator mismatch")

// MismatchError carries both subjects, so the security event a caller logs
// beside its 400 names what disagreed (provenance.md, Rule 2).
type MismatchError struct {
	// Baggage is the subject an upstream edge stamped.
	Baggage string
	// Verified is the subject of the token this hop verified.
	Verified string
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf("%v: baggage carries %q, this hop verified %q", ErrInitiatorMismatch, e.Baggage, e.Verified)
}

// Unwrap reports [ErrInitiatorMismatch], so errors.Is matches the sentinel.
func (e *MismatchError) Unwrap() error { return ErrInitiatorMismatch }

// Stamp returns ctx carrying the initiator of id as baggage, for every
// outbound call the ctx reaches through otel.Transport. Call it at the
// verified edge only, once, immediately after the token is verified.
//
// issuer is the issuer the edge verified the token against; [authkit.Identity]
// does not carry it, because the claim stops at the validator. entry is the
// edge's own host, from its configuration.
//
// Stamp replaces the three members rather than deferring to what arrived:
// see the package doc for why that is Rule 1 rather than against it.
//
// Three inputs stamp nothing and return ctx unchanged, because provenance
// never fails a request: an identity with no Sub, which is no initiator; an
// empty issuer, which would render a subject no core could qualify; and a
// value baggage cannot encode. The last two log at warn, since each is a
// misconfiguration an operator must see.
func Stamp(ctx context.Context, id authkit.Identity, issuer, entry string) context.Context {
	subject, ok := render(ctx, issuer, id.Sub)
	if !ok {
		return ctx
	}
	// Delete first, so an inbound member this identity has no value for
	// cannot survive as half of a spoofed initiator.
	b := baggage.FromContext(ctx)
	for _, key := range []string{MemberSubject, MemberIssuer, MemberEntry} {
		b = b.DeleteMember(key)
	}
	for _, kv := range [][2]string{
		{MemberSubject, subject},
		{MemberIssuer, issuer},
		{MemberEntry, entry},
	} {
		if kv[1] == "" {
			continue
		}
		// The library owns encoding and validation: NewMember refuses a value
		// the W3C grammar has no spelling for, and Member.String escapes what
		// the grammar requires, so the URL and the pipe in <iss>|<sub> reach
		// the wire intact. SetMember refuses a header already at the W3C
		// member ceiling -- far above the family budget of eight members and
		// 1 KiB shared with the run. prefix (run-tracing.md, "Shape"), so
		// three members here can only be refused beside a plane that has
		// already overrun it.
		m, err := baggage.NewMember(kv[0], kv[1])
		if err == nil {
			b, err = b.SetMember(m)
		}
		if err != nil {
			slog.WarnContext(ctx, "provenance: initiator not stamped", "member", kv[0], "error", err)
			return ctx
		}
	}
	return baggage.ContextWithBaggage(ctx, b)
}

// From returns the initiator an upstream edge carried in ctx. ok is false
// when no edge stamped one, which is the normal shape of unattended work.
// The result is unauthenticated metadata and decides nothing.
func From(ctx context.Context) (Initiator, bool) {
	b := baggage.FromContext(ctx)
	i := Initiator{
		Subject: b.Member(MemberSubject).Value(),
		Issuer:  b.Member(MemberIssuer).Value(),
		Entry:   b.Member(MemberEntry).Value(),
	}
	// Subject is what names the person. An entry with no subject is a front
	// door that stamped nothing, not an initiator.
	if i.Subject == "" {
		return Initiator{}, false
	}
	return i, true
}

// Assert is Rule 2 for a hop that verifies a person's token itself: when
// baggage already carries an initiator, it must be the same person.
//
// It returns a [MismatchError] wrapping [ErrInitiatorMismatch] when the
// stamped subject differs from <issuer>|<id.Sub>. The caller answers 400
// invalid_request and logs one security event carrying both values: a
// mismatch is either a bug in an edge or a header that survived the ingress
// strip, and an operator must see both. It is never a silent overwrite and
// never a silent acceptance.
//
// It returns nil, and the initiator stays untouched, when ctx carries no
// initiator (this hop is the edge; call [Stamp]) or when id is not a person.
// A service, agent or dev principal has nothing to compare against: it is
// not the initiator of anything.
func Assert(ctx context.Context, id authkit.Identity, issuer string) error {
	if !isPerson(id) {
		return nil
	}
	got, ok := From(ctx)
	if !ok {
		return nil
	}
	want, ok := render(ctx, issuer, id.Sub)
	if !ok {
		// This hop cannot render its own subject, so it has nothing to
		// compare and every request would 400 on a bug of its own. The warn
		// line render logs is the operator's signal; the initiator stays as
		// it arrived, and it grants nothing either way.
		return nil
	}
	if got.Subject != want {
		return &MismatchError{Baggage: got.Subject, Verified: want}
	}
	return nil
}

// render is the one place <iss>|<sub> is built, so Stamp and Assert cannot
// disagree about what a subject is. ok is false unless both halves are
// present: authz.Subject renders an empty issuer as "|<sub>", a subject no
// core can qualify, and an initiator missing either half is not an
// initiator. A missing sub is ordinary -- an anonymous or unattended
// context -- and passes silently; a missing issuer beside a real sub is a
// misconfigured edge and logs at warn.
func render(ctx context.Context, issuer, sub string) (string, bool) {
	if sub == "" {
		return "", false
	}
	if issuer == "" {
		slog.WarnContext(ctx, "provenance: no issuer, initiator subject not qualified", "sub", sub)
		return "", false
	}
	return authz.Subject(issuer, sub), true
}

// isPerson reports whether id is the kind of principal that can be an
// initiator. Only [authkit.PrincipalUser] is: a service is unattended work
// by definition, and an agent, a dev bypass or an unset principal type is
// not a person this hop can hold an edge's stamp against. Asserting on one
// would fail calls to defend a comparison that means nothing, and
// provenance never breaks a call.
func isPerson(id authkit.Identity) bool {
	return id.PrincipalType == authkit.PrincipalUser
}

// Attrs returns the initiator as slog attributes, for a log line. It is
// empty when no edge stamped one, so a call site adds it unconditionally.
func (i Initiator) Attrs() []slog.Attr {
	out := make([]slog.Attr, 0, 3)
	for _, kv := range i.pairs() {
		out = append(out, slog.String(kv[0], kv[1]))
	}
	return out
}

// SpanAttrs returns the initiator as span attributes, under the same three
// keys [Initiator.Attrs] uses.
func (i Initiator) SpanAttrs() []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, 3)
	for _, kv := range i.pairs() {
		out = append(out, attribute.String(kv[0], kv[1]))
	}
	return out
}

// pairs is the one place the field-to-key mapping lives, so a log line and a
// span cannot drift apart.
func (i Initiator) pairs() [][2]string {
	out := make([][2]string, 0, 3)
	for _, kv := range [][2]string{
		{MemberSubject, i.Subject},
		{MemberIssuer, i.Issuer},
		{MemberEntry, i.Entry},
	} {
		if kv[1] != "" {
			out = append(out, kv)
		}
	}
	return out
}

// Attrs returns the initiator carried in ctx as slog attributes, empty when
// there is none.
func Attrs(ctx context.Context) []slog.Attr {
	i, ok := From(ctx)
	if !ok {
		return nil
	}
	return i.Attrs()
}

// SpanAttrs returns the initiator carried in ctx as span attributes, empty
// when there is none. Pass it to span.SetAttributes so a span and the log
// lines beside it name the same initiator.
func SpanAttrs(ctx context.Context) []attribute.KeyValue {
	i, ok := From(ctx)
	if !ok {
		return nil
	}
	return i.SpanAttrs()
}
