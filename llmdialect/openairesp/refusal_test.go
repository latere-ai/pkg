// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openairesp_test

import (
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
	"latere.ai/x/pkg/llmdialect/openairesp"
)

// The Responses surface serves the stateless subset only. Those two
// refusals are the surface's own, not limits of the translation: a
// gateway that forwards an undecodable body to a native OpenAI target
// (because the body would go byte-identical anyway) must still keep them
// terminal, or the caller's previous_response_id resolves against the
// gateway's upstream account rather than the caller's.
//
// Everything else this decoder rejects is dialect-scoped, so the same
// gateway may forward it and let OpenAI answer for its own vocabulary.
func TestDecodeRequestRefusalScopes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		body  string
		scope ir.RefusalScope
	}{
		{"previous_response_id", `{"model":"gpt-5","input":"x","previous_response_id":"resp_1"}`, ir.ScopeSurface},
		{"store true", `{"model":"gpt-5","input":"x","store":true}`, ir.ScopeSurface},
		{"unknown tool_choice", `{"model":"gpt-5","input":"x","tool_choice":"nonesuch"}`, ir.ScopeDialect},
		{"missing model", `{"input":"x"}`, ir.ScopeDialect},
		{"missing input", `{"model":"gpt-5"}`, ir.ScopeDialect},
		{"invalid json", `{`, ir.ScopeDialect},
		{"negative top_logprobs", `{"model":"gpt-5","input":"x","top_logprobs":-1}`, ir.ScopeDialect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := openairesp.NewFrontend().DecodeRequest([]byte(tc.body))
			if err == nil {
				t.Fatal("want a decode error")
			}
			if got := ir.RefusalScopeOf(err); got != tc.scope {
				t.Fatalf("scope = %q, want %q (err: %v)", got, tc.scope, err)
			}
		})
	}
}

// A stateless request decodes, so nothing above is over-refusing.
func TestStatelessRequestDecodes(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"model":"gpt-5","input":"x"}`,
		`{"model":"gpt-5","input":"x","store":false}`,
		`{"model":"gpt-5","input":"x","previous_response_id":""}`,
	} {
		if _, err := openairesp.NewFrontend().DecodeRequest([]byte(body)); err != nil {
			t.Fatalf("DecodeRequest(%s): %v", body, err)
		}
	}
}

// Tagging must not have changed the message a gateway puts in its 400.
func TestRefusalMessagesUnchanged(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ body, want string }{
		{`{"model":"gpt-5","input":"x","previous_response_id":"r"}`,
			"openairesp: previous_response_id is not supported on this surface (stateless only)"},
		{`{"model":"gpt-5","input":"x","store":true}`,
			"openairesp: store:true is not supported on this surface (stateless only)"},
	} {
		_, err := openairesp.NewFrontend().DecodeRequest([]byte(tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("message = %v, want %q", err, tc.want)
		}
	}
}
