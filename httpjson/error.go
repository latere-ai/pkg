// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpjson

import (
	"encoding/json/v2"
	"net/http"
)

// Error is the error a Latere API answers with, rendered as
//
//	{"error": {"code": "...", "message": "...", "details": {...}}}
//
// Code is the stable machine identifier chosen when the error is defined.
// Message is the one user sentence for that code, fixed beside the code
// and never built from the underlying error. Details is the developer
// detail, present only when there is one, that a console or a CLI shows
// on request. The rule and the review checklist are docs/writing/registers.md
// at the module root.
type Error struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// ErrorEnvelope is the body WriteError sends, and what a client decodes.
type ErrorEnvelope struct {
	Error Error `json:"error"`
}

// WriteError sends e in the envelope with status, through Write. The
// members of Details are written in sorted order, so two answers with the
// same details are the same bytes: a refusal can then be answered exactly
// as a missing object is, and a client or a test can compare the bodies.
func WriteError(w http.ResponseWriter, status int, e Error) {
	write(w, status, ErrorEnvelope{Error: e}, json.Deterministic(true))
}
