// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package llmdialect

import (
	"encoding/json"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/anthropic"
	"latere.ai/x/pkg/llmdialect/openaichat"
	"latere.ai/x/pkg/llmdialect/openairesp"
)

func newChatFrontend() Frontend { return openaichat.NewFrontend() }

func newAnthropicBackend() Backend {
	return anthropic.NewBackend(anthropic.BackendOptions{DefaultMaxTokens: 1024})
}

// TestLogProbsCrossDialect is the hub-and-spoke property for the
// feature: a Chat Completions caller asking for logprobs reaches a
// Responses upstream with that dialect's own two members, and what
// comes back is re-encoded in the caller's shape. Neither codec knows
// the other exists.
func TestLogProbsCrossDialect(t *testing.T) {
	tr := &Translator{
		Frontend: newChatFrontend(),
		Backend:  openairesp.NewBackend(),
	}
	out, req, err := tr.Request([]byte(
		`{"model":"m","messages":[{"role":"user","content":"hi"}],"logprobs":true,"top_logprobs":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if !req.LogProbs || req.TopLogProbs != 2 {
		t.Fatalf("decoded %v/%d", req.LogProbs, req.TopLogProbs)
	}
	var upstream struct {
		Include     []string `json:"include"`
		TopLogProbs int      `json:"top_logprobs"`
	}
	if err := json.Unmarshal(out, &upstream); err != nil {
		t.Fatal(err)
	}
	if len(upstream.Include) != 1 || upstream.TopLogProbs != 2 {
		t.Fatalf("the ask did not reach the upstream in its own dialect: %s", out)
	}

	body := `{"id":"resp_1","model":"m","status":"completed","output":[
		{"type":"message","role":"assistant","content":[
			{"type":"output_text","text":"hey","logprobs":[
				{"token":"hey","logprob":-0.5,"bytes":[104,101,121],"top_logprobs":[]},
				{"token":"!","logprob":null,"bytes":[33],"top_logprobs":[]}]}]}]}`
	got, err := tr.Response([]byte(body))
	if err != nil {
		t.Fatalf("a masked token must not fail the translation: %v", err)
	}
	if !strings.Contains(string(got), `"bytes":[104,101,121]`) {
		t.Fatalf("the caller's dialect did not get its own byte shape: %s", got)
	}
	if !strings.Contains(string(got), `"logprob":null`) {
		t.Fatalf("the masked token did not survive: %s", got)
	}
}

// TestLogProbsAreReportedLostWhereTheyCannotBeServed: the Messages API
// has no logprobs member, so the ask is a loss on that leg. A caller
// reading the report can tell the difference between a served request
// and one that quietly lost half its ask.
func TestLogProbsAreReportedLostWhereTheyCannotBeServed(t *testing.T) {
	tr := &Translator{Frontend: newChatFrontend(), Backend: newAnthropicBackend()}
	_, req, err := tr.Request([]byte(
		`{"model":"m","messages":[{"role":"user","content":"hi"}],"logprobs":true,"top_logprobs":2}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"logprobs": true, "top_logprobs": true}
	for _, f := range req.Loss.Strings() {
		delete(want, f)
	}
	if len(want) != 0 {
		t.Fatalf("loss = %v, missing %v", req.Loss.Strings(), want)
	}
}
