// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"context"
	"log/slog"
)

// AuditKey is the fixed attribute that marks a record as an audit record.
// It is a query predicate on the log pipeline otel.SetupLogs already runs,
// not a store: no new exporter, no new dependency
// (provenance.md, "Where it goes").
const AuditKey = "audit"

// The audit attribute keys that are not already on every record.
// otel.SetupLogs supplies the rest: the record's time is at, the service
// resource is service, and traceContextHandler stamps trace_id and span_id
// (pkg/otel/logs.go).
const (
	AuditActionKey   = "action"
	AuditResourceKey = "resource"
	AuditOutcomeKey  = "outcome"
)

// Outcome is what an audited action came to. The set is closed
// (provenance.md, "The durable record").
type Outcome string

const (
	// OutcomeAllowed: the action was permitted and performed.
	OutcomeAllowed Outcome = "allowed"
	// OutcomeDenied: the action was refused by policy.
	OutcomeDenied Outcome = "denied"
	// OutcomeFailed: the action was permitted and did not complete.
	OutcomeFailed Outcome = "failed"
)

// AuditAttrs returns the audit record's attributes: the fixed audit=true
// marker, the initiator ctx carries, and the action, resource and outcome.
//
// action is <resource kind>.<noun>.<verb> from the closed set the service
// declares in its own spec; resource is <kind>/<id>. extra is appended for
// the fields one service needs and the shape does not name.
//
// The initiator fields are absent for unattended work, which is the correct
// record of a service acting as itself and never a gap to fill.
//
// An action is audited when it changes who may do what, or what exists. A
// read, a list, a clone, a health check or a decision endpoint at request
// rate is counted or traced and never audited: a row per call would cost
// more than the plane it guards (provenance.md, "What is not audited").
func AuditAttrs(ctx context.Context, action, resource string, outcome Outcome, extra ...slog.Attr) []slog.Attr {
	out := make([]slog.Attr, 0, 4+3+len(extra))
	out = append(out, slog.Bool(AuditKey, true))
	out = append(out, Attrs(ctx)...)
	out = append(out,
		slog.String(AuditActionKey, action),
		slog.String(AuditResourceKey, resource),
		slog.String(AuditOutcomeKey, string(outcome)),
	)
	return append(out, extra...)
}

// Audit emits one audit record at info on logger, with action as the message
// so a human reading the stream sees what happened without decoding fields.
// A nil logger writes to [slog.Default].
//
// It is the *Context variant deliberately: the trace ids attach, so the
// record joins the call chain it belongs to.
//
// This is the slog layer of the audit shape, and it is not pkg/audit. The
// two are layers, not two standards: pkg/audit.Event is a Go struct a
// product serializes to its own store, and this is slog attributes on the
// pipeline every service already has (provenance.md, "Relation to
// pkg/audit"). Where the two vocabularies differ, this one is initiator.*
// and pkg/audit keeps its own Actor; re-expressing Actor is a decision for
// whoever next touches that package, and the spec says so rather than
// settling it here.
func Audit(ctx context.Context, logger *slog.Logger, action, resource string, outcome Outcome, extra ...slog.Attr) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.LogAttrs(ctx, slog.LevelInfo, action, AuditAttrs(ctx, action, resource, outcome, extra...)...)
}
