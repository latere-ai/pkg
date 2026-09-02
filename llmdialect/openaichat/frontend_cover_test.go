// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openaichat

import (
	"errors"
	"slices"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func TestFrontendDecodeStopSingleString(t *testing.T) {
	req := decodeFront(t, `{"model":"m","stop":"END","messages":[{"role":"user","content":"x"}]}`)
	if len(req.StopSequences) != 1 || req.StopSequences[0] != "END" {
		t.Fatalf("stop wrong: %v", req.StopSequences)
	}
}

func TestFrontendDecodeMaxTokensLegacyField(t *testing.T) {
	req := decodeFront(t, `{"model":"m","max_tokens":77,"messages":[{"role":"user","content":"x"}]}`)
	if req.MaxTokens == nil || *req.MaxTokens != 77 {
		t.Fatalf("max_tokens wrong: %v", req.MaxTokens)
	}
}

func TestFrontendDecodeToolVariantsAndParallel(t *testing.T) {
	req := decodeFront(t, `{
		"model": "m",
		"messages": [{"role": "user", "content": "x"}],
		"tools": [
			{"type": "web_search", "web_search": {}},
			{"type": "function", "function": {"name": "f", "strict": true, "parameters": {"type": "object"}}}
		],
		"tool_choice": "required",
		"parallel_tool_calls": false
	}`)
	if len(req.Tools) != 1 || req.Tools[0].Name != "f" {
		t.Fatalf("tools wrong: %+v", req.Tools)
	}
	if req.ToolChoice.Mode != ir.ToolChoiceAny || !req.ToolChoice.DisableParallel {
		t.Fatalf("tool choice wrong: %+v", req.ToolChoice)
	}
	// A non-function type is a tool the provider runs. It keeps its options
	// and passes through instead of being reported as lost.
	if len(req.ServerTools) != 1 || req.ServerTools[0].Type != "web_search" {
		t.Fatalf("server tools wrong: %+v", req.ServerTools)
	}
	if got := string(req.ServerTools[0].Config); got != `{"web_search":{}}` {
		t.Fatalf("server tool config = %s, want the sibling fields kept", got)
	}
	if !slices.Contains(req.Loss.Fields(), ir.LossField("tools.strict")) {
		t.Fatalf("loss %v missing %q", req.Loss.Fields(), "tools.strict")
	}
	if slices.Contains(req.Loss.Fields(), ir.LossField("tools.web_search")) {
		t.Fatalf("loss %v still reports a dropped server tool", req.Loss.Fields())
	}
}

func TestFrontendDecodeAssistantPartsAndReasoning(t *testing.T) {
	req := decodeFront(t, `{
		"model": "m",
		"messages": [
			{"role": "assistant", "reasoning_content": "hm", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]},
			{"role": "user", "content": "x"}
		]
	}`)
	blocks := req.Messages[0].Blocks
	if blocks[0].Type != ir.BlockThinking || blocks[0].Text != "hm" {
		t.Fatalf("thinking wrong: %+v", blocks[0])
	}
	if blocks[1].Text != "a\n\nb" {
		t.Fatalf("parts join wrong: %q", blocks[1].Text)
	}
}

func TestFrontendDecodeContentErrors(t *testing.T) {
	cases := map[string]string{
		"bad system":       `{"model":"m","messages":[{"role":"system","content":42}]}`,
		"bad assistant":    `{"model":"m","messages":[{"role":"assistant","content":42}]}`,
		"bad tool content": `{"model":"m","messages":[{"role":"tool","tool_call_id":"t","content":42}]}`,
		"image no url":     `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url"}]}]}`,
		"named choice bad": `{"model":"m","tool_choice":{"type":"function"},"messages":[{"role":"user","content":"x"}]}`,
	}
	for name, body := range cases {
		if _, err := NewFrontend().DecodeRequest([]byte(body)); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}

type errWriter struct{ after int }

func (w *errWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errors.New("sink closed")
	}
	w.after--
	return len(p), nil
}

func TestFrontendEventEncoderWriteErrors(t *testing.T) {
	enc := NewFrontend().NewEventEncoder(&errWriter{})
	if err := enc.Encode(ir.Event{Type: ir.EventMessageStart, ID: "m"}); err == nil {
		t.Fatal("want write error on role chunk")
	}
	enc = NewFrontend().NewEventEncoder(&errWriter{after: 1})
	if err := enc.Encode(ir.Event{Type: ir.EventMessageDelta, Usage: &ir.Usage{}}); err == nil {
		t.Fatal("want write error on usage chunk")
	}
}
