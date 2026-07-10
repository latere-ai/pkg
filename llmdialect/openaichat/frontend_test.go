package openaichat

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func decodeFront(t *testing.T, body string) *ir.Request {
	t.Helper()
	req, err := NewFrontend().DecodeRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestFrontendName(t *testing.T) {
	if NewFrontend().Name() != DialectName {
		t.Fatal("name mismatch")
	}
}

func TestFrontendDecodeRequestFull(t *testing.T) {
	body := `{
		"model": "claude-sonnet-5",
		"max_completion_tokens": 2048,
		"temperature": 0.7,
		"top_p": 0.95,
		"stop": ["END", "FIN"],
		"stream": true,
		"user": "u-9",
		"reasoning_effort": "high",
		"messages": [
			{"role": "system", "content": "be brief"},
			{"role": "developer", "content": [{"type": "text", "text": "and precise"}]},
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "checking", "tool_calls": [
				{"id": "t1", "type": "function", "function": {"name": "get_time", "arguments": "{\"tz\":\"UTC\"}"}}
			]},
			{"role": "tool", "tool_call_id": "t1", "content": "14:02"},
			{"role": "tool", "tool_call_id": "t2", "content": "sunny"},
			{"role": "user", "content": "thanks"}
		],
		"tools": [{"type": "function", "function": {"name": "get_time", "description": "clock", "parameters": {"type": "object"}}}],
		"tool_choice": "auto",
		"parallel_tool_calls": false
	}`
	req := decodeFront(t, body)

	if req.Model != "claude-sonnet-5" || *req.MaxTokens != 2048 || !req.Stream || req.UserID != "u-9" {
		t.Fatalf("basics wrong: %+v", req)
	}
	if len(req.System) != 2 || req.System[0].Text != "be brief" || req.System[1].Text != "and precise" {
		t.Fatalf("system wrong: %+v", req.System)
	}
	if !reflect.DeepEqual(req.StopSequences, []string{"END", "FIN"}) {
		t.Fatalf("stop wrong: %v", req.StopSequences)
	}
	if len(req.Messages) != 4 {
		t.Fatalf("want 4 IR messages, got %d: %+v", len(req.Messages), req.Messages)
	}
	asst := req.Messages[1]
	if asst.Role != ir.RoleAssistant || asst.Blocks[0].Text != "checking" ||
		asst.Blocks[1].ToolUse.Name != "get_time" || string(asst.Blocks[1].ToolUse.Args) != `{"tz":"UTC"}` {
		t.Fatalf("assistant wrong: %+v", asst)
	}
	// Two consecutive tool messages coalesce into one user turn.
	toolTurn := req.Messages[2]
	if toolTurn.Role != ir.RoleUser || len(toolTurn.Blocks) != 2 ||
		toolTurn.Blocks[0].ToolResult.ToolUseID != "t1" ||
		toolTurn.Blocks[1].ToolResult.ToolUseID != "t2" {
		t.Fatalf("tool turn wrong: %+v", toolTurn)
	}
	if req.Messages[3].Blocks[0].Text != "thanks" {
		t.Fatalf("trailing user wrong: %+v", req.Messages[3])
	}
	if req.ToolChoice.Mode != ir.ToolChoiceAuto || !req.ToolChoice.DisableParallel {
		t.Fatalf("tool choice wrong: %+v", req.ToolChoice)
	}
	if req.Reasoning == nil || req.Reasoning.Effort != "high" {
		t.Fatalf("reasoning wrong: %+v", req.Reasoning)
	}
}

func TestFrontendDecodeRequestImagesAndSchema(t *testing.T) {
	body := `{
		"model": "m",
		"messages": [{"role": "user", "content": [
			{"type": "text", "text": "what is this"},
			{"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
			{"type": "image_url", "image_url": {"url": "https://x/y.png"}},
			{"type": "input_audio", "input_audio": {}}
		]}],
		"response_format": {"type": "json_schema", "json_schema": {"name": "out", "schema": {"type": "object"}, "strict": true}},
		"seed": 42
	}`
	req := decodeFront(t, body)
	blocks := req.Messages[0].Blocks
	if blocks[1].Image.MediaType != "image/png" || blocks[1].Image.Data != "AAAA" {
		t.Fatalf("data uri wrong: %+v", blocks[1].Image)
	}
	if blocks[2].Image.URL != "https://x/y.png" {
		t.Fatalf("url image wrong: %+v", blocks[2].Image)
	}
	if req.Schema == nil || req.Schema.Name != "out" || !req.Schema.Strict {
		t.Fatalf("schema wrong: %+v", req.Schema)
	}
	loss := req.Loss.Fields()
	for _, want := range []ir.LossField{"seed", "content.input_audio"} {
		if !contains(loss, want) {
			t.Fatalf("loss %v missing %q", loss, want)
		}
	}
}

func TestFrontendDecodeToolChoiceForms(t *testing.T) {
	base := `{"model":"m","messages":[{"role":"user","content":"x"}],"tool_choice":`
	for wire, mode := range map[string]ir.ToolChoiceMode{
		`"auto"`: ir.ToolChoiceAuto, `"required"`: ir.ToolChoiceAny, `"none"`: ir.ToolChoiceNone,
	} {
		req := decodeFront(t, base+wire+`}`)
		if req.ToolChoice.Mode != mode {
			t.Fatalf("%s → %v", wire, req.ToolChoice.Mode)
		}
	}
	req := decodeFront(t, base+`{"type":"function","function":{"name":"f"}}}`)
	if req.ToolChoice.Mode != ir.ToolChoiceTool || req.ToolChoice.Name != "f" {
		t.Fatalf("named choice wrong: %+v", req.ToolChoice)
	}
}

func TestFrontendDecodeRequestErrors(t *testing.T) {
	cases := map[string]string{
		"invalid json":    `{`,
		"missing model":   `{"messages":[{"role":"user","content":"x"}]}`,
		"no messages":     `{"model":"m"}`,
		"n>1":             `{"model":"m","n":2,"messages":[{"role":"user","content":"x"}]}`,
		"bad role":        `{"model":"m","messages":[{"role":"critic","content":"x"}]}`,
		"bad stop":        `{"model":"m","stop":42,"messages":[{"role":"user","content":"x"}]}`,
		"bad tool choice": `{"model":"m","tool_choice":"sometimes","messages":[{"role":"user","content":"x"}]}`,
		"bad data uri":    `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png,raw"}}]}]}`,
		"schema missing":  `{"model":"m","response_format":{"type":"json_schema"},"messages":[{"role":"user","content":"x"}]}`,
		"bad content":     `{"model":"m","messages":[{"role":"user","content":42}]}`,
	}
	for name, body := range cases {
		if _, err := NewFrontend().DecodeRequest([]byte(body)); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}

func TestFrontendEncodeResponse(t *testing.T) {
	resp := &ir.Response{
		ID:    "msg_1",
		Model: "claude-sonnet-5",
		Blocks: []ir.Block{
			{Type: ir.BlockThinking, Text: "hm"},
			{Type: ir.BlockText, Text: "hi"},
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t1", Name: "f"}},
			{Type: ir.BlockRedactedThinking, Redacted: "xx"},
		},
		StopReason: ir.StopToolUse,
		Usage:      ir.Usage{InputTokens: 40, OutputTokens: 5, CacheReadInputTokens: 60, ReasoningTokens: 2},
	}
	raw, err := NewFrontend().EncodeResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if got["object"] != "chat.completion" || got["id"] != "msg_1" {
		t.Fatalf("envelope wrong: %v", got)
	}
	choice := got["choices"].([]any)[0].(map[string]any)
	msg := choice["message"].(map[string]any)
	if choice["finish_reason"] != "tool_calls" || msg["content"] != "hi" || msg["reasoning_content"] != "hm" {
		t.Fatalf("message wrong: %v", choice)
	}
	tc := msg["tool_calls"].([]any)[0].(map[string]any)
	if tc["function"].(map[string]any)["arguments"] != "{}" {
		t.Fatalf("empty args wrong: %v", tc)
	}
	usage := got["usage"].(map[string]any)
	// prompt_tokens includes cache reads (40 + 60).
	if usage["prompt_tokens"].(float64) != 100 || usage["total_tokens"].(float64) != 105 ||
		usage["prompt_tokens_details"].(map[string]any)["cached_tokens"].(float64) != 60 {
		t.Fatalf("usage wrong: %v", usage)
	}
}

func TestFrontendEncodeResponseStopMapping(t *testing.T) {
	for stop, want := range map[ir.StopReason]string{
		ir.StopEndTurn: "stop", ir.StopStopSequence: "stop",
		ir.StopMaxTokens: "length", ir.StopRefusal: "content_filter", "": "stop",
	} {
		raw, err := NewFrontend().EncodeResponse(&ir.Response{StopReason: stop, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}})
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if fr := got["choices"].([]any)[0].(map[string]any)["finish_reason"]; fr != want {
			t.Fatalf("%s → %v want %s", stop, fr, want)
		}
	}
	if _, err := NewFrontend().EncodeResponse(&ir.Response{Blocks: []ir.Block{{Type: ir.BlockImage}}}); err == nil {
		t.Fatal("want error for unrepresentable block")
	}
}

func TestFrontendEventEncoderSequence(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	events := []ir.Event{
		{Type: ir.EventMessageStart, ID: "msg_1", Model: "claude"},
		{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockThinking}},
		{Type: ir.EventThinkingDelta, Index: 0, Delta: "hm"},
		{Type: ir.EventSignatureDelta, Index: 0, Delta: "sig"},
		{Type: ir.EventBlockStop, Index: 0},
		{Type: ir.EventBlockStart, Index: 1, Block: &ir.Block{Type: ir.BlockText}},
		{Type: ir.EventTextDelta, Index: 1, Delta: "he"},
		{Type: ir.EventTextDelta, Index: 1, Delta: "y"},
		{Type: ir.EventBlockStop, Index: 1},
		{Type: ir.EventBlockStart, Index: 2, Block: &ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t1", Name: "f"}}},
		{Type: ir.EventArgsDelta, Index: 2, Delta: `{"a":1}`},
		{Type: ir.EventBlockStop, Index: 2},
		{Type: ir.EventMessageDelta, StopReason: ir.StopToolUse, Usage: &ir.Usage{InputTokens: 7, OutputTokens: 3}},
		{Type: ir.EventMessageStop},
	}
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}

	frames := strings.Split(strings.TrimSpace(buf.String()), "\n\n")
	last := strings.TrimPrefix(frames[len(frames)-1], "data: ")
	if last != "[DONE]" {
		t.Fatalf("stream must end with [DONE], got %q", last)
	}

	var chunks []map[string]any
	for _, f := range frames[:len(frames)-1] {
		var c map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(f, "data: ")), &c); err != nil {
			t.Fatalf("bad chunk %q: %v", f, err)
		}
		chunks = append(chunks, c)
	}

	delta := func(i int) map[string]any {
		return chunks[i]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
	}
	if delta(0)["role"] != "assistant" {
		t.Fatalf("first chunk must carry the role: %v", chunks[0])
	}
	if delta(1)["reasoning_content"] != "hm" {
		t.Fatalf("thinking delta wrong: %v", chunks[1])
	}
	if delta(2)["content"] != "he" || delta(3)["content"] != "y" {
		t.Fatalf("text deltas wrong: %v %v", chunks[2], chunks[3])
	}
	toolStart := delta(4)["tool_calls"].([]any)[0].(map[string]any)
	if toolStart["id"] != "t1" || toolStart["index"].(float64) != 0 ||
		toolStart["function"].(map[string]any)["name"] != "f" {
		t.Fatalf("tool start wrong: %v", toolStart)
	}
	argsDelta := delta(5)["tool_calls"].([]any)[0].(map[string]any)
	if argsDelta["function"].(map[string]any)["arguments"] != `{"a":1}` {
		t.Fatalf("args delta wrong: %v", argsDelta)
	}
	finishChunk := chunks[6]["choices"].([]any)[0].(map[string]any)
	if finishChunk["finish_reason"] != "tool_calls" {
		t.Fatalf("finish chunk wrong: %v", finishChunk)
	}
	usageChunk := chunks[7]
	if len(usageChunk["choices"].([]any)) != 0 ||
		usageChunk["usage"].(map[string]any)["prompt_tokens"].(float64) != 7 {
		t.Fatalf("usage chunk wrong: %v", usageChunk)
	}
	if chunks[0]["id"] != "msg_1" || chunks[0]["model"] != "claude" || chunks[0]["object"] != "chat.completion.chunk" {
		t.Fatalf("chunk envelope wrong: %v", chunks[0])
	}
}

func TestFrontendEventEncoderErrors(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	if err := enc.Encode(ir.Event{Type: "weird"}); err == nil {
		t.Fatal("want unknown event error")
	}
	if err := enc.Encode(ir.Event{Type: ir.EventBlockStart}); err == nil {
		t.Fatal("want missing block error")
	}
	if err := enc.Encode(ir.Event{Type: ir.EventArgsDelta, Delta: "x"}); err == nil {
		t.Fatal("want args-outside-tool error")
	}
}

func FuzzFrontendDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"tool","tool_call_id":"t","content":"x"},{"role":"tool","tool_call_id":"u","content":"y"}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = NewFrontend().DecodeRequest(body) // must not panic
	})
}
