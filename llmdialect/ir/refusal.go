// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package ir

import "errors"

// RefusalScope says how far a frontend's refusal to decode a request
// reaches, so a gateway can tell a refusal that routing makes moot from
// one that no routing changes.
//
// The distinction matters because a gateway does not always need the
// body decoded. When the target speaks the caller's dialect natively the
// body is forwarded byte-identical, and the decode ran only to read
// call-shape fields. A codec that cannot represent something is then
// stating a limit of the translation, not a verdict on the request, and
// the gateway should let the target answer for itself. A codec that
// refuses to serve the request at all is stating something the gateway
// must enforce however it routes.
type RefusalScope string

// Refusal scopes.
const (
	// ScopeNone is the zero value: no refusal. RefusalScopeOf returns it
	// for a nil error and never for a real one.
	ScopeNone RefusalScope = ""
	// ScopeDialect: this codec could not read the body, or could not
	// carry some part of it through the IR. The request may still be
	// valid to the dialect's own server, which owns the vocabulary and
	// may have grown it since this codec was written. A caller that
	// forwards the body to a target speaking this dialect natively may
	// treat the refusal as advisory. This is the default for any decode
	// error that does not say otherwise.
	ScopeDialect RefusalScope = "dialect"
	// ScopeSurface: this surface will not serve the request at all, on
	// any target, translated or not. Forwarding it anyway would be
	// wrong rather than merely lossy. A caller must keep the refusal
	// terminal.
	ScopeSurface RefusalScope = "surface"
)

// Refusal tags a decode error with its scope. It is transparent: Error
// returns the wrapped message unchanged and Unwrap exposes the cause, so
// tagging an existing error changes no message and breaks no errors.Is
// chain.
type Refusal struct {
	Scope RefusalScope
	Err   error
}

func (r *Refusal) Error() string { return r.Err.Error() }
func (r *Refusal) Unwrap() error { return r.Err }

// RefuseSurface tags err as a refusal this surface makes regardless of
// routing. Codecs use it for the few constraints that are theirs to
// enforce rather than the model server's.
func RefuseSurface(err error) error {
	if err == nil {
		return nil
	}
	return &Refusal{Scope: ScopeSurface, Err: err}
}

// RefusalScopeOf classifies err. A nil error is ScopeNone. Any other
// error is ScopeDialect unless it carries a *Refusal saying otherwise,
// so a codec opts in to the stricter reading and never out of it: a new
// error site is advisory by default, which is the safe direction for a
// gateway that would otherwise start rejecting requests its targets
// accept.
//
// It unwraps, so a tagged error keeps its scope through any number of
// fmt.Errorf("%w") layers.
func RefusalScopeOf(err error) RefusalScope {
	if err == nil {
		return ScopeNone
	}
	var r *Refusal
	if errors.As(err, &r) {
		return r.Scope
	}
	return ScopeDialect
}
