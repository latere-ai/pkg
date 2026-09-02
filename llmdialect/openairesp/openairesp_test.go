// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openairesp

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/internal/sse"
	"latere.ai/x/pkg/llmdialect/ir"
)

func decode(t *testing.T, body string) *ir.Request {
	t.Helper()
	req, err := NewFrontend().DecodeRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestName(t *testing.T) {
	if NewFrontend().Name() != DialectName {
		t.Fatal("name mismatch")
	}
}

// TestDecodeRequestCodexShape covers the wire shape Codex sends when
// driving a custom provider: instructions, an item-list input with a
// prior function_call/function_call_output round trip, flattened
// tools, reasoning effort, store:false.
func TestDecodeRequestCodexShape(t *testing.T) {
	body := `{
		"model": "qwen3-32b",
		"instructions": "You are Codex",
		"store": false,
		"stream": true,
		"max_output_tokens": 4096,
		"temperature": 0.4,
		"reasoning": {"effort": "medium", "summary": "auto"},
		"parallel_tool_calls": false,
		"input": [
			{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "list files"}]},
			{"type": "reasoning", "summary": [], "encrypted_content": "opaque"},
			{"type": "function_call", "call_id": "call_1", "name": "shell", "arguments": "{\"cmd\":\"ls\"}"},
			{"type": "function_call", "call_id": "call_2", "name": "shell", "arguments": "{\"cmd\":\"pwd\"}"},
			{"type": "function_call_output", "call_id": "call_1", "output": "a.txt"},
			{"type": "function_call_output", "call_id": "call_2", "output": "/repo"},
			{"type": "message", "role": "user", "content": "now what?"}
		],
		"tools": [
			{"type": "function", "name": "shell", "description": "run", "parameters": {"type": "object"}, "strict": true},
			{"type": "web_search"}
		],
		"tool_choice": "auto"
	}`
	req := decode(t, body)

	if req.Model != "qwen3-32b" || !req.Stream || *req.MaxTokens != 4096 {
		t.Fatalf("basics wrong: %+v", req)
	}
	if len(req.System) != 1 || req.System[0].Text != "You are Codex" {
		t.Fatalf("instructions wrong: %+v", req.System)
	}
	// user, assistant(2 tool calls), user(2 tool results + trailing
	// text — consecutive same-role items coalesce into one turn).
	if len(req.Messages) != 3 {
		t.Fatalf("want 3 messages, got %d: %+v", len(req.Messages), req.Messages)
	}
	asst := req.Messages[1]
	if asst.Role != ir.RoleAssistant || len(asst.Blocks) != 2 ||
		asst.Blocks[0].ToolUse.ID != "call_1" || asst.Blocks[1].ToolUse.ID != "call_2" {
		t.Fatalf("folded tool calls wrong: %+v", asst)
	}
	results := req.Messages[2]
	if results.Role != ir.RoleUser || len(results.Blocks) != 3 ||
		results.Blocks[0].ToolResult.ToolUseID != "call_1" ||
		results.Blocks[0].ToolResult.Blocks[0].Text != "a.txt" ||
		results.Blocks[2].Text != "now what?" {
		t.Fatalf("folded tool results wrong: %+v", results)
	}
	if req.Reasoning == nil || req.Reasoning.Effort != "medium" {
		t.Fatalf("reasoning wrong: %+v", req.Reasoning)
	}
	if len(req.Tools) != 1 || req.Tools[0].Name != "shell" {
		t.Fatalf("tools wrong: %+v", req.Tools)
	}
	if req.ToolChoice == nil || !req.ToolChoice.DisableParallel {
		t.Fatalf("tool choice wrong: %+v", req.ToolChoice)
	}
	loss := req.Loss.Fields()
	for _, want := range []ir.LossField{"reasoning", "reasoning.summary", "tools.strict", "tools.web_search"} {
		if !slices.Contains(loss, want) {
			t.Fatalf("loss %v missing %q", loss, want)
		}
	}
}

func TestDecodeRequestStringInputAndSchema(t *testing.T) {
	req := decode(t, `{
		"model": "m", "input": "hello",
		"text": {"format": {"type": "json_schema", "name": "out", "schema": {"type": "object"}, "strict": true}, "verbosity": "low"}
	}`)
	if len(req.Messages) != 1 || req.Messages[0].Blocks[0].Text != "hello" {
		t.Fatalf("string input wrong: %+v", req.Messages)
	}
	if req.Schema == nil || req.Schema.Name != "out" || !req.Schema.Strict {
		t.Fatalf("schema wrong: %+v", req.Schema)
	}
	if !slices.Contains(req.Loss.Fields(), "text.verbosity") {
		t.Fatalf("verbosity loss missing: %v", req.Loss.Fields())
	}
}

func TestDecodeRequestImagesAndSystemItems(t *testing.T) {
	req := decode(t, `{
		"model": "m",
		"input": [
			{"type": "message", "role": "system", "content": "sys"},
			{"type": "message", "role": "user", "content": [
				{"type": "input_text", "text": "look"},
				{"type": "input_image", "image_url": "data:image/png;base64,AAAA"},
				{"type": "input_image", "image_url": "https://x/y.png"}
			]}
		]
	}`)
	if len(req.System) != 1 || req.System[0].Text != "sys" {
		t.Fatalf("system item wrong: %+v", req.System)
	}
	blocks := req.Messages[0].Blocks
	if blocks[1].Image.Data != "AAAA" || blocks[2].Image.URL != "https://x/y.png" {
		t.Fatalf("images wrong: %+v", blocks)
	}
}

func TestDecodeRequestStatelessGuards(t *testing.T) {
	if _, err := NewFrontend().DecodeRequest([]byte(
		`{"model":"m","input":"x","previous_response_id":"resp_1"}`)); err == nil {
		t.Fatal("previous_response_id must be rejected")
	}
	if _, err := NewFrontend().DecodeRequest([]byte(
		`{"model":"m","input":"x","store":true}`)); err == nil {
		t.Fatal("store:true must be rejected")
	}
	// store:false and omitted store are fine.
	decode(t, `{"model":"m","input":"x","store":false}`)
	decode(t, `{"model":"m","input":"x"}`)
}

func TestDecodeRequestErrors(t *testing.T) {
	cases := map[string]string{
		"invalid json":  `{`,
		"missing model": `{"input":"x"}`,
		"empty input":   `{"model":"m"}`,
		"bad input":     `{"model":"m","input":42}`,
		"bad role":      `{"model":"m","input":[{"type":"message","role":"critic","content":"x"}]}`,
		"bad choice":    `{"model":"m","input":"x","tool_choice":"sometimes"}`,
		"bad data uri":  `{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_image","image_url":"data:image/png,raw"}]}]}`,
		"bad content":   `{"model":"m","input":[{"type":"message","role":"user","content":42}]}`,
	}
	for name, body := range cases {
		if _, err := NewFrontend().DecodeRequest([]byte(body)); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}

func TestEncodeResponse(t *testing.T) {
	resp := &ir.Response{
		ID:    "abc",
		Model: "qwen3",
		Blocks: []ir.Block{
			{Type: ir.BlockThinking, Text: "hm"},
			{Type: ir.BlockText, Text: "hi"},
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "call_1", Name: "shell", Args: json.RawMessage(`{"cmd":"ls"}`)}},
		},
		StopReason: ir.StopToolUse,
		Usage:      ir.Usage{InputTokens: 40, OutputTokens: 6, CacheReadInputTokens: 60, ReasoningTokens: 2},
	}
	raw, err := NewFrontend().EncodeResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if got["object"] != "response" || got["status"] != "completed" || got["id"] != "resp_abc" {
		t.Fatalf("envelope wrong: %v", got)
	}
	output := got["output"].([]any)
	if len(output) != 3 {
		t.Fatalf("want 3 output items, got %v", output)
	}
	if output[0].(map[string]any)["type"] != "reasoning" {
		t.Fatalf("reasoning item wrong: %v", output[0])
	}
	msg := output[1].(map[string]any)
	if msg["type"] != "message" ||
		msg["content"].([]any)[0].(map[string]any)["text"] != "hi" {
		t.Fatalf("message item wrong: %v", msg)
	}
	fc := output[2].(map[string]any)
	if fc["type"] != "function_call" || fc["call_id"] != "call_1" || fc["arguments"] != `{"cmd":"ls"}` {
		t.Fatalf("function_call item wrong: %v", fc)
	}
	usage := got["usage"].(map[string]any)
	if usage["input_tokens"].(float64) != 100 ||
		usage["input_tokens_details"].(map[string]any)["cached_tokens"].(float64) != 60 {
		t.Fatalf("usage wrong: %v", usage)
	}
}

func TestEncodeResponseIncomplete(t *testing.T) {
	raw, err := NewFrontend().EncodeResponse(&ir.Response{
		ID: "x", Blocks: []ir.Block{{Type: ir.BlockText, Text: "cut"}}, StopReason: ir.StopMaxTokens,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if got["status"] != "incomplete" ||
		got["incomplete_details"].(map[string]any)["reason"] != "max_output_tokens" {
		t.Fatalf("incomplete mapping wrong: %v", got)
	}
}

func readFrames(t *testing.T, raw string) []sse.Event {
	t.Helper()
	r := sse.NewReader(strings.NewReader(raw))
	var out []sse.Event
	for {
		ev, err := r.Next()
		if err != nil {
			return out
		}
		out = append(out, ev)
	}
}

func TestEventEncoderSequence(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	events := []ir.Event{
		{Type: ir.EventMessageStart, ID: "abc", Model: "qwen3"},
		{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockText}},
		{Type: ir.EventTextDelta, Index: 0, Delta: "he"},
		{Type: ir.EventTextDelta, Index: 0, Delta: "y"},
		{Type: ir.EventBlockStop, Index: 0},
		{Type: ir.EventBlockStart, Index: 1, Block: &ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "call_1", Name: "shell"}}},
		{Type: ir.EventArgsDelta, Index: 1, Delta: `{"cmd":"ls"}`},
		{Type: ir.EventBlockStop, Index: 1},
		{Type: ir.EventMessageDelta, StopReason: ir.StopToolUse, Usage: &ir.Usage{InputTokens: 7, OutputTokens: 3}},
		{Type: ir.EventMessageStop},
	}
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}

	frames := readFrames(t, buf.String())
	var names []string
	for _, f := range frames {
		names = append(names, f.Name)
	}
	want := []string{
		"response.created", "response.in_progress",
		"response.output_item.added", "response.content_part.added",
		"response.output_text.delta", "response.output_text.delta",
		"response.output_text.done", "response.output_item.done",
		"response.output_item.added",
		"response.function_call_arguments.delta",
		"response.function_call_arguments.done", "response.output_item.done",
		"response.completed",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("events = %v\nwant %v", names, want)
	}

	var completed map[string]any
	_ = json.Unmarshal(frames[len(frames)-1].Data, &completed)
	response := completed["response"].(map[string]any)
	if response["status"] != "completed" || response["id"] != "resp_abc" {
		t.Fatalf("completed envelope wrong: %v", response)
	}
	output := response["output"].([]any)
	if len(output) != 2 {
		t.Fatalf("completed output wrong: %v", output)
	}
	if output[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"] != "hey" {
		t.Fatalf("accumulated text wrong: %v", output[0])
	}
	fc := output[1].(map[string]any)
	if fc["call_id"] != "call_1" || fc["arguments"] != `{"cmd":"ls"}` {
		t.Fatalf("accumulated tool call wrong: %v", fc)
	}
	if response["usage"].(map[string]any)["input_tokens"].(float64) != 7 {
		t.Fatalf("usage wrong: %v", response["usage"])
	}

	// Sequence numbers are strictly increasing from 0.
	for i, f := range frames {
		var payload map[string]any
		_ = json.Unmarshal(f.Data, &payload)
		if int(payload["sequence_number"].(float64)) != i {
			t.Fatalf("sequence_number[%d] = %v", i, payload["sequence_number"])
		}
		if payload["type"] != f.Name {
			t.Fatalf("payload type %v != event name %s", payload["type"], f.Name)
		}
	}
}

func TestEventEncoderThinkingAndIncomplete(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	events := []ir.Event{
		{Type: ir.EventMessageStart, ID: "x", Model: "m"},
		{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockThinking}},
		{Type: ir.EventThinkingDelta, Index: 0, Delta: "hm"},
		{Type: ir.EventBlockStop, Index: 0},
		{Type: ir.EventMessageDelta, StopReason: ir.StopMaxTokens},
		{Type: ir.EventMessageStop},
	}
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	out := buf.String()
	for _, want := range []string{
		"event: response.reasoning_summary_text.delta",
		"event: response.incomplete", `"reason":"max_output_tokens"`,
		`"summary_text"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stream missing %q:\n%s", want, out)
		}
	}
}

func TestEventEncoderErrors(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	if err := enc.Encode(ir.Event{Type: "weird"}); err == nil {
		t.Fatal("want unknown event error")
	}
	if err := enc.Encode(ir.Event{Type: ir.EventBlockStart}); err == nil {
		t.Fatal("want missing block error")
	}
	if err := enc.Encode(ir.Event{Type: ir.EventBlockStart, Block: &ir.Block{Type: ir.BlockImage}}); err == nil {
		t.Fatal("want unstreamable block error")
	}
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"model":"m","input":"hi"}`))
	f.Add([]byte(`{"model":"m","input":[{"type":"function_call","call_id":"c","name":"f","arguments":"{}"}]}`))
	f.Add([]byte(`{"model":"m","input":"hi","top_logprobs":2,"include":["message.output_text.logprobs"]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = NewFrontend().DecodeRequest(body) // must not panic
	})
}
