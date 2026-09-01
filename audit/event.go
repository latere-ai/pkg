// Package audit defines the canonical audit-event envelope used across
// Latere services and the abstractions emitters share.
//
// The Event struct is the wire shape: products serialize it to stdout, OTLP
// logs, object storage, Postgres, etc. Storage adapters live in each product
// because retention, schema, and query patterns are product-specific. The
// Emitter interface is the boundary: anything that consumes an Event can be
// composed via MultiEmitter.
//
// Categories form an open set: products may register their own values via
// new untyped constants, and Category is intentionally a string alias so a
// product can name CategoryFoo without coordinating with this package.
package audit

import (
	"encoding/json"
	"time"
)

// Category identifies the audit-event class. The set is open: products may
// register their own values. Common values live as constants below.
type Category string

const (
	// CategoryLifecycle covers create / start / stop / delete events on
	// long-lived resources (sandboxes, virtual keys, sessions).
	CategoryLifecycle Category = "lifecycle"
	// CategoryExec covers command or workload execution within a resource.
	CategoryExec Category = "exec"
	// CategoryIdentity covers principal authentication, authorization,
	// and role/membership changes.
	CategoryIdentity Category = "identity"
	// CategoryNetwork covers gateway/proxy ingress and egress decisions.
	CategoryNetwork Category = "network"
	// CategoryAdmin covers privileged platform-side actions (admin
	// console actions, support overrides, manual cleanups).
	CategoryAdmin Category = "admin"
	// CategoryBilling carries usage events derived from lifecycle or
	// metered activity that downstream pipelines aggregate.
	CategoryBilling Category = "billing"
	// CategorySyscall is reserved for future low-level resource events.
	CategorySyscall Category = "syscall"
)

// Actor describes who initiated an event.
type Actor struct {
	// Type is one of "user", "service", "system". Required when Actor is
	// present. "system" denotes events with no acting principal (e.g. a
	// reaper sweep, a deadline-driven cleanup).
	Type string `json:"type,omitempty"`
	// PrincipalID is the resolved internal identifier (e.g. a user ID, a
	// service account ID).
	PrincipalID string `json:"principal_id,omitempty"`
	// OwnerSub is the OIDC subject claim when the actor authenticated via
	// the platform IdP. Optional and may differ from PrincipalID when the
	// platform maps externals to internal IDs.
	OwnerSub string `json:"owner_sub,omitempty"`
}

// IsZero reports whether a is the zero Actor.
func (a Actor) IsZero() bool {
	return a.Type == "" && a.PrincipalID == "" && a.OwnerSub == ""
}

// Subject identifies the resource the event acted on.
type Subject struct {
	// Kind is a product-defined resource kind ("sandbox", "virtual_key",
	// "role", "org"). Optional.
	Kind string `json:"kind,omitempty"`
	// ID is the canonical resource identifier (e.g. a UUID, a lease ID).
	ID string `json:"id,omitempty"`
	// Name is the user-visible name when distinct from ID.
	Name string `json:"name,omitempty"`
}

// IsZero reports whether s is the zero Subject.
func (s Subject) IsZero() bool {
	return s.Kind == "" && s.ID == "" && s.Name == ""
}

// Event is the canonical audit envelope. Payload is per-category and lives
// in product-specific schema packages.
//
// The omitempty tags allow downstream readers to remain compatible as new
// optional fields are added: any reader that decodes Event will skip
// unrecognized fields, and any reader that encodes one with zero optional
// values will produce a payload identical to a reader that did not know
// those fields existed.
type Event struct {
	EventID   string          `json:"event_id"`
	TS        time.Time       `json:"ts"`
	Category  Category        `json:"category"`
	Actor     Actor           `json:"actor"`
	Replica   string          `json:"replica,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
	OrgID     string          `json:"org_id,omitempty"`
	Subject   *Subject        `json:"subject,omitempty"`
	Policy    string          `json:"policy,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}
