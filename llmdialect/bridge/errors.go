// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import "latere.ai/x/pkg/llmdialect"

// Code is one failure of this package's own: which leg of a translation
// could not be completed, or that no codec exists for a dialect. A
// caller maps each onto its own error table; the sentences here are the
// package's, for a program with no table of its own.
type Code string

// The seven codes.
const (
	DecodeRequest  Code = "decode_request"  // the body is not valid for the caller's dialect
	EncodeRequest  Code = "encode_request"  // the request cannot be written in the upstream dialect
	DecodeResponse Code = "decode_response" // the upstream body is not valid for its dialect
	EncodeResponse Code = "encode_response" // the response cannot be written in the caller's dialect
	StreamFailed   Code = "stream_failed"   // the upstream stream ended badly
	WriteFailed    Code = "write_failed"    // writing to the caller failed
	Unsupported    Code = "unsupported"     // no codec for this dialect on this side
)

// messages is the one fixed user sentence per code, never built from
// the codec's error; that travels apart, in Error.Detail.
var messages = map[Code]string{
	DecodeRequest:  "The request is not valid for the API it was sent to.",
	EncodeRequest:  "The request cannot be expressed in the upstream API.",
	DecodeResponse: "The upstream answered with a response this API cannot read.",
	EncodeResponse: "The upstream's response cannot be expressed in this API.",
	StreamFailed:   "The upstream stream ended before the response was complete.",
	WriteFailed:    "The response could not be delivered.",
	Unsupported:    "This API cannot be translated to the requested one.",
}

// Message is the one user sentence of the code, and "" for a string
// that is not one.
func (c Code) Message() string { return messages[c] }

// Error is one failure of this package: the code, the codec's own words
// as the developer detail, the refusal scope when the code is
// DecodeRequest, and the codec's error for errors.Is and errors.As.
type Error struct {
	Code   Code
	Detail string                  // the codec's own words; never shown to a user
	Scope  llmdialect.RefusalScope // ScopeNone unless Code is DecodeRequest
	Err    error                   // the codec's error, for errors.Is and errors.As
}

// Error renders the developer's line: "<code>: <detail>", or the code
// alone when there is no detail.
func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Detail
}

// Message is the fixed user sentence of the code.
func (e *Error) Message() string { return e.Code.Message() }

// Unwrap exposes the codec's error.
func (e *Error) Unwrap() error { return e.Err }

// wrap makes the *Error of a codec failure on one leg.
func wrap(code Code, err error) *Error {
	e := &Error{Code: code, Detail: err.Error(), Err: err}
	if code == DecodeRequest {
		e.Scope = llmdialect.RefusalScopeOf(err)
	}
	return e
}

// Scope classifies any error this package returns: ScopeDialect is a
// limit of the translation, advisory to a caller that could forward the
// body to a native target instead; ScopeSurface is a refusal that holds
// on every target. It is llmdialect.RefusalScopeOf reached through the
// *Error, so a caller classifies without importing the root: a nil
// error is ScopeNone, and any other error is ScopeDialect unless the
// codec tagged it ScopeSurface.
func Scope(err error) llmdialect.RefusalScope { return llmdialect.RefusalScopeOf(err) }
