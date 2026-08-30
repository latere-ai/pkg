package openairesp

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// mustJSON unmarshals into a generic map for shape assertions.
func mustJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, b)
	}
	return m
}

func TestBackendName(t *testing.T) {
	if NewBackend().Name() != DialectName {
		t.Fatalf("name = %q", NewBackend().Name())
	}
}

// EncodeRequest must produce a Responses body: instructions from system,
// input items for the turns, flat tools, reasoning.effort, max_output_tokens.
func TestBackendEncodeRequest(t *testing.T) {
	maxTok := int64(4096)
	temp := 0.5
	req := &ir.Request{
		Model:       "gpt-5.6-sol",
		MaxTokens:   &maxTok,
		Temperature: &temp,
		Stream:      true,
		System:      []ir.Block{{Type: ir.BlockText, Text: "be terse"}},
		Reasoning:   &ir.Reasoning{Effort: ir.EffortHigh},
		Tools: []ir.Tool{{
			Name: "shell", Description: "run a command",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"cmd":{"type":"string"}}}`),
		}},
		ToolChoice: &ir.ToolChoice{Mode: ir.ToolChoiceAuto},
		Messages: []ir.Message{
			{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "make hello.py"}}},
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockText, Text: "on it"},
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "call_1", Name: "shell", Args: json.RawMessage(`{"cmd":"touch hello.py"}`)}},
			}},
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: "call_1", Blocks: []ir.Block{{Type: ir.BlockText, Text: "done"}}}},
			}},
		},
	}
	raw, err := NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON(t, raw)

	if body["model"] != "gpt-5.6-sol" {
		t.Errorf("model = %v", body["model"])
	}
	if body["instructions"] != "be terse" {
		t.Errorf("instructions = %v", body["instructions"])
	}
	if body["max_output_tokens"].(float64) != 4096 {
		t.Errorf("max_output_tokens = %v", body["max_output_tokens"])
	}
	if body["stream"] != true {
		t.Errorf("stream = %v", body["stream"])
	}
	// reasoning.effort must survive (the whole point vs chat/completions).
	rz, ok := body["reasoning"].(map[string]any)
	if !ok || rz["effort"] != "high" {
		t.Errorf("reasoning = %v", body["reasoning"])
	}
	// tools must be flat function objects (name/description/parameters at top).
	tools, ok := body["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools = %v", body["tools"])
	}
	tool := tools[0].(map[string]any)
	if tool["type"] != "function" || tool["name"] != "shell" {
		t.Errorf("tool = %v", tool)
	}
	if tool["parameters"] == nil {
		t.Errorf("tool.parameters missing: %v", tool)
	}
	// input items: user text, assistant text, function_call, function_call_output.
	input, ok := body["input"].([]any)
	if !ok {
		t.Fatalf("input not a list: %v", body["input"])
	}
	var kinds []string
	for _, it := range input {
		m := it.(map[string]any)
		if m["type"] == "function_call" && m["call_id"] == "call_1" && m["name"] == "shell" {
			kinds = append(kinds, "function_call")
			continue
		}
		if m["type"] == "function_call_output" && m["call_id"] == "call_1" {
			kinds = append(kinds, "function_call_output")
			continue
		}
		kinds = append(kinds, "message:"+m["role"].(string))
	}
	want := []string{"message:user", "message:assistant", "function_call", "function_call_output"}
	if !reflect.DeepEqual(kinds, want) {
		t.Errorf("input kinds = %v, want %v", kinds, want)
	}
}

// A round-trip through the existing frontend must be ~identity on the
// representable subset.
func TestBackendFrontendRoundTrip(t *testing.T) {
	orig := &ir.Request{
		Model:    "gpt-5.6-sol",
		System:   []ir.Block{{Type: ir.BlockText, Text: "sys"}},
		Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}}}},
		Tools:    []ir.Tool{{Name: "t", InputSchema: json.RawMessage(`{"type":"object"}`)}},
	}
	raw, err := NewBackend().EncodeRequest(orig)
	if err != nil {
		t.Fatal(err)
	}
	back, err := NewFrontend().DecodeRequest(raw)
	if err != nil {
		t.Fatalf("frontend cannot read backend output: %v\n%s", err, raw)
	}
	if back.Model != "gpt-5.6-sol" || len(back.Messages) != 1 || len(back.Tools) != 1 {
		t.Fatalf("round-trip lost data: %+v", back)
	}
	if len(back.System) != 1 || back.System[0].Text != "sys" {
		t.Fatalf("system lost: %+v", back.System)
	}
}

// DecodeResponse: a Responses body with a function_call → BlockToolUse + StopToolUse.
func TestBackendDecodeResponseToolCall(t *testing.T) {
	body := `{
		"id":"resp_x","model":"gpt-5.6-sol","status":"completed",
		"output":[
			{"type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"I'll run it"}]},
			{"type":"function_call","call_id":"call_9","name":"shell","arguments":"{\"cmd\":\"ls\"}"}
		],
		"usage":{"input_tokens":100,"output_tokens":20,
			"input_tokens_details":{"cached_tokens":10},
			"output_tokens_details":{"reasoning_tokens":8}}
	}`
	resp, err := NewBackend().DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	// The backend strips the Responses-specific "resp_" prefix so the IR
	// id is bare (the frontend re-adds it on encode).
	if resp.ID != "x" || resp.Model != "gpt-5.6-sol" {
		t.Errorf("ids: %+v", resp)
	}
	kinds := blockKinds(resp.Blocks)
	if !reflect.DeepEqual(kinds, []string{"thinking", "text", "tool_use"}) {
		t.Fatalf("blocks = %v", kinds)
	}
	if resp.StopReason != ir.StopToolUse {
		t.Errorf("stop = %v", resp.StopReason)
	}
	tu := resp.Blocks[2].ToolUse
	if tu.ID != "call_9" || tu.Name != "shell" || string(tu.Args) != `{"cmd":"ls"}` {
		t.Errorf("tool use = %+v", tu)
	}
	// IR input excludes cache reads; reasoning tokens preserved.
	if resp.Usage.InputTokens != 90 || resp.Usage.CacheReadInputTokens != 10 || resp.Usage.ReasoningTokens != 8 {
		t.Errorf("usage = %+v", resp.Usage)
	}
}

func TestBackendDecodeResponseIncomplete(t *testing.T) {
	body := `{"id":"r","model":"m","status":"incomplete",
		"incomplete_details":{"reason":"max_output_tokens"},
		"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"partial"}]}]}`
	resp, err := NewBackend().DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StopReason != ir.StopMaxTokens {
		t.Errorf("stop = %v", resp.StopReason)
	}
}

func TestBackendDecodeResponseError(t *testing.T) {
	if _, err := NewBackend().DecodeResponse([]byte(`{"error":{"message":"boom","type":"invalid_request_error"}}`)); err == nil {
		t.Fatal("want error")
	}
	if _, err := NewBackend().DecodeResponse([]byte(`{`)); err == nil {
		t.Fatal("want json error")
	}
}

// Streaming: a Responses SSE stream decodes to the canonical IR event sequence.
func TestBackendEventDecoder(t *testing.T) {
	stream := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"resp_s","model":"gpt-5.6-sol"}}`, ``,
		`event: response.output_item.added`,
		`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_0","role":"assistant"}}`, ``,
		`event: response.output_text.delta`,
		`data: {"type":"response.output_text.delta","item_id":"msg_0","output_index":0,"delta":"hel"}`, ``,
		`event: response.output_text.delta`,
		`data: {"type":"response.output_text.delta","item_id":"msg_0","output_index":0,"delta":"lo"}`, ``,
		`event: response.output_item.done`,
		`data: {"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"msg_0","role":"assistant","content":[{"type":"output_text","text":"hello"}]}}`, ``,
		`event: response.output_item.added`,
		`data: {"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_2","name":"shell","arguments":""}}`, ``,
		`event: response.function_call_arguments.delta`,
		`data: {"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":"{\"cmd\":\"ls\"}"}`, ``,
		`event: response.output_item.done`,
		`data: {"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_2","name":"shell","arguments":"{\"cmd\":\"ls\"}"}}`, ``,
		`event: response.completed`,
		`data: {"type":"response.completed","response":{"id":"resp_s","status":"completed","usage":{"input_tokens":5,"output_tokens":7}}}`, ``,
	}, "\n")

	dec := NewBackend().NewEventDecoder(strings.NewReader(stream))
	var got []ir.EventType
	var text, args strings.Builder
	var stop ir.StopReason
	var usage *ir.Usage
	for {
		ev, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ev.Type)
		switch ev.Type {
		case ir.EventTextDelta:
			text.WriteString(ev.Delta)
		case ir.EventArgsDelta:
			args.WriteString(ev.Delta)
		case ir.EventMessageDelta:
			stop = ev.StopReason
			usage = ev.Usage
		}
	}
	if text.String() != "hello" {
		t.Errorf("text = %q", text.String())
	}
	if args.String() != `{"cmd":"ls"}` {
		t.Errorf("args = %q", args.String())
	}
	if stop != ir.StopToolUse {
		t.Errorf("stop = %v", stop)
	}
	if usage == nil || usage.OutputTokens != 7 {
		t.Errorf("usage = %+v", usage)
	}
	// must start with MessageStart and end with MessageStop
	if got[0] != ir.EventMessageStart || got[len(got)-1] != ir.EventMessageStop {
		t.Errorf("event envelope = %v", got)
	}
}

func blockKinds(blocks []ir.Block) []string {
	var out []string
	for _, b := range blocks {
		switch b.Type {
		case ir.BlockText:
			out = append(out, "text")
		case ir.BlockThinking:
			out = append(out, "thinking")
		case ir.BlockToolUse:
			out = append(out, "tool_use")
		}
	}
	return out
}
