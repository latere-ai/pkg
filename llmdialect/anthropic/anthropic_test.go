package anthropic

import (
	"bytes"
	"encoding/json"
	"reflect"
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

func TestDecodeRequestFull(t *testing.T) {
	body := `{
		"model": "claude-sonnet-5",
		"max_tokens": 4096,
		"system": "be brief",
		"messages": [
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": [
				{"type": "text", "text": "let me check"},
				{"type": "tool_use", "id": "tu_1", "name": "get_time", "input": {"tz": "UTC"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "tu_1", "content": "14:02", "is_error": false},
				{"type": "text", "text": "and now?"}
			]}
		],
		"tools": [{"name": "get_time", "description": "clock", "input_schema": {"type": "object"}}],
		"tool_choice": {"type": "tool", "name": "get_time", "disable_parallel_tool_use": true},
		"temperature": 0.5,
		"top_p": 0.9,
		"top_k": 40,
		"stop_sequences": ["END"],
		"stream": true,
		"metadata": {"user_id": "u-1"},
		"thinking": {"type": "enabled", "budget_tokens": 1024}
	}`
	req := decode(t, body)

	if req.Model != "claude-sonnet-5" || *req.MaxTokens != 4096 || !req.Stream {
		t.Fatalf("basics wrong: %+v", req)
	}
	if len(req.System) != 1 || req.System[0].Text != "be brief" {
		t.Fatalf("system wrong: %+v", req.System)
	}
	if len(req.Messages) != 3 {
		t.Fatalf("want 3 messages, got %d", len(req.Messages))
	}
	asst := req.Messages[1]
	if asst.Role != ir.RoleAssistant || asst.Blocks[1].ToolUse.Name != "get_time" {
		t.Fatalf("assistant turn wrong: %+v", asst)
	}
	if string(asst.Blocks[1].ToolUse.Args) != `{"tz": "UTC"}` {
		t.Fatalf("tool args wrong: %s", asst.Blocks[1].ToolUse.Args)
	}
	tr := req.Messages[2].Blocks[0]
	if tr.Type != ir.BlockToolResult || tr.ToolResult.ToolUseID != "tu_1" ||
		len(tr.ToolResult.Blocks) != 1 || tr.ToolResult.Blocks[0].Text != "14:02" {
		t.Fatalf("tool result wrong: %+v", tr)
	}
	if len(req.Tools) != 1 || req.Tools[0].Name != "get_time" {
		t.Fatalf("tools wrong: %+v", req.Tools)
	}
	if req.ToolChoice.Mode != ir.ToolChoiceTool || req.ToolChoice.Name != "get_time" || !req.ToolChoice.DisableParallel {
		t.Fatalf("tool choice wrong: %+v", req.ToolChoice)
	}
	if *req.Temperature != 0.5 || *req.TopP != 0.9 || *req.TopK != 40 {
		t.Fatal("sampling params wrong")
	}
	if req.UserID != "u-1" || req.Reasoning == nil || req.Reasoning.BudgetTokens != 1024 {
		t.Fatalf("metadata/thinking wrong: %+v", req)
	}
	if got := req.Loss.Fields(); got != nil {
		t.Fatalf("unexpected loss: %v", got)
	}
}

func TestDecodeRequestSystemBlocksAndCacheControl(t *testing.T) {
	body := `{
		"model": "m", "max_tokens": 10,
		"system": [
			{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}},
			{"type": "search_result", "text": "x"}
		],
		"messages": [{"role": "user", "content": [
			{"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}
		]}]
	}`
	req := decode(t, body)
	if len(req.System) != 1 || !req.System[0].CacheHint {
		t.Fatalf("system cache hint missing: %+v", req.System)
	}
	if !req.Messages[0].Blocks[0].CacheHint {
		t.Fatal("message cache hint missing")
	}
	if want := []string{"system.search_result"}; !reflect.DeepEqual(req.Loss.Strings(), want) {
		t.Fatalf("loss = %v want %v", req.Loss.Strings(), want)
	}
}

func TestDecodeRequestImages(t *testing.T) {
	body := `{
		"model": "m", "messages": [{"role": "user", "content": [
			{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
			{"type": "image", "source": {"type": "url", "url": "https://x/y.png"}}
		]}]
	}`
	req := decode(t, body)
	b := req.Messages[0].Blocks
	if b[0].Image.MediaType != "image/png" || b[0].Image.Data != "AAAA" {
		t.Fatalf("base64 image wrong: %+v", b[0].Image)
	}
	if b[1].Image.URL != "https://x/y.png" {
		t.Fatalf("url image wrong: %+v", b[1].Image)
	}
}

func TestDecodeRequestThinkingBlocksAndUnknowns(t *testing.T) {
	body := `{
		"model": "m", "messages": [
			{"role": "assistant", "content": [
				{"type": "thinking", "thinking": "hmm", "signature": "sig1"},
				{"type": "redacted_thinking", "data": "opaque"},
				{"type": "server_tool_use", "id": "x"},
				{"type": "text", "text": "ok", "citations": [{"a":1}]}
			]}
		],
		"service_tier": "auto"
	}`
	req := decode(t, body)
	blocks := req.Messages[0].Blocks
	if blocks[0].Type != ir.BlockThinking || blocks[0].Text != "hmm" || blocks[0].Signature != "sig1" {
		t.Fatalf("thinking wrong: %+v", blocks[0])
	}
	if blocks[1].Type != ir.BlockRedactedThinking || blocks[1].Redacted != "opaque" {
		t.Fatalf("redacted wrong: %+v", blocks[1])
	}
	if len(blocks) != 3 {
		t.Fatalf("unknown block should be skipped, got %d blocks", len(blocks))
	}
	loss := req.Loss.Fields()
	for _, want := range []ir.LossField{"service_tier", "content.server_tool_use", "citations"} {
		if !contains(loss, want) {
			t.Fatalf("loss %v missing %q", loss, want)
		}
	}
}

func TestDecodeRequestToolVariants(t *testing.T) {
	body := `{
		"model": "m", "messages": [{"role": "user", "content": "x"}],
		"tools": [
			{"name": "a", "input_schema": {"type": "object"}, "cache_control": {"type": "ephemeral"}},
			{"type": "bash_20250124", "name": "bash"},
			{"type": "custom", "name": "b", "input_schema": {"type": "object"}}
		]
	}`
	req := decode(t, body)
	if len(req.Tools) != 2 || req.Tools[0].Name != "a" || req.Tools[1].Name != "b" {
		t.Fatalf("tools wrong: %+v", req.Tools)
	}
	loss := req.Loss.Fields()
	for _, want := range []ir.LossField{"tools.cache_control", "tools.bash_20250124"} {
		if !contains(loss, want) {
			t.Fatalf("loss %v missing %q", loss, want)
		}
	}
}

func TestDecodeRequestToolChoiceModes(t *testing.T) {
	for wire, mode := range map[string]ir.ToolChoiceMode{
		"auto": ir.ToolChoiceAuto, "any": ir.ToolChoiceAny, "none": ir.ToolChoiceNone,
	} {
		req := decode(t, `{"model":"m","messages":[{"role":"user","content":"x"}],"tool_choice":{"type":"`+wire+`"}}`)
		if req.ToolChoice.Mode != mode {
			t.Fatalf("tool_choice %s → %v", wire, req.ToolChoice.Mode)
		}
	}
}

func TestDecodeRequestOutputFormat(t *testing.T) {
	req := decode(t, `{"model":"m","messages":[{"role":"user","content":"x"}],
		"output_format":{"type":"json_schema","schema":{"type":"object"}}}`)
	if req.Schema == nil || string(req.Schema.Schema) != `{"type":"object"}` {
		t.Fatalf("schema wrong: %+v", req.Schema)
	}
}

func TestDecodeRequestToolResultBlockContent(t *testing.T) {
	req := decode(t, `{"model":"m","messages":[{"role":"user","content":[
		{"type":"tool_result","tool_use_id":"t1","is_error":true,"content":[
			{"type":"text","text":"fail"},
			{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA"}}
		]}
	]}]}`)
	tr := req.Messages[0].Blocks[0].ToolResult
	if !tr.IsError || len(tr.Blocks) != 2 || tr.Blocks[1].Type != ir.BlockImage {
		t.Fatalf("tool result wrong: %+v", tr)
	}
}

func TestDecodeRequestErrors(t *testing.T) {
	cases := map[string]string{
		"invalid json":       `{`,
		"missing model":      `{"messages":[{"role":"user","content":"x"}]}`,
		"missing messages":   `{"model":"m"}`,
		"bad role":           `{"model":"m","messages":[{"role":"tool","content":"x"}]}`,
		"bad content":        `{"model":"m","messages":[{"role":"user","content":42}]}`,
		"image no source":    `{"model":"m","messages":[{"role":"user","content":[{"type":"image"}]}]}`,
		"bad image source":   `{"model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"type":"file"}}]}]}`,
		"bad tool choice":    `{"model":"m","messages":[{"role":"user","content":"x"}],"tool_choice":{"type":"weird"}}`,
		"bad system":         `{"model":"m","messages":[{"role":"user","content":"x"}],"system":42}`,
		"bad output format":  `{"model":"m","messages":[{"role":"user","content":"x"}],"output_format":{"type":"text"}}`,
		"bad tool result":    `{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":42}]}]}`,
		"malformed messages": `{"model":"m","messages":[{"role":"user","content":"x"}],"temperature":"hot"}`,
	}
	for name, body := range cases {
		if _, err := NewFrontend().DecodeRequest([]byte(body)); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}

func TestEncodeResponse(t *testing.T) {
	resp := &ir.Response{
		ID:    "chatcmpl-1",
		Model: "qwen3",
		Blocks: []ir.Block{
			{Type: ir.BlockThinking, Text: "let me think"},
			{Type: ir.BlockText, Text: "hi"},
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t1", Name: "f"}},
			{Type: ir.BlockRedactedThinking, Redacted: "xx"},
		},
		StopReason: ir.StopToolUse,
		Usage:      ir.Usage{InputTokens: 10, OutputTokens: 5, CacheReadInputTokens: 3},
	}
	raw, err := NewFrontend().EncodeResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != "chatcmpl-1" || got["type"] != "message" || got["role"] != "assistant" ||
		got["model"] != "qwen3" || got["stop_reason"] != "tool_use" || got["stop_sequence"] != nil {
		t.Fatalf("envelope wrong: %v", got)
	}
	content := got["content"].([]any)
	if len(content) != 4 {
		t.Fatalf("want 4 blocks, got %d", len(content))
	}
	tu := content[2].(map[string]any)
	if tu["type"] != "tool_use" || !reflect.DeepEqual(tu["input"], map[string]any{}) {
		t.Fatalf("tool_use wrong: %v", tu)
	}
	usage := got["usage"].(map[string]any)
	if usage["input_tokens"].(float64) != 10 || usage["cache_read_input_tokens"].(float64) != 3 {
		t.Fatalf("usage wrong: %v", usage)
	}
}

func TestEncodeResponseDefaultsAndErrors(t *testing.T) {
	raw, err := NewFrontend().EncodeResponse(&ir.Response{StopSequence: "END"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if got["stop_reason"] != "end_turn" || got["stop_sequence"] != "END" {
		t.Fatalf("defaults wrong: %v", got)
	}

	_, err = NewFrontend().EncodeResponse(&ir.Response{Blocks: []ir.Block{{Type: ir.BlockImage}}})
	if err == nil {
		t.Fatal("want error for unrepresentable block")
	}
}

// readEvents parses SSE output into (name, decoded-json) pairs.
func readEvents(t *testing.T, raw string) []sse.Event {
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
		{Type: ir.EventMessageStart, ID: "m1", Model: "qwen3"},
		{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockThinking}},
		{Type: ir.EventThinkingDelta, Index: 0, Delta: "hm"},
		{Type: ir.EventSignatureDelta, Index: 0, Delta: "s"},
		{Type: ir.EventBlockStop, Index: 0},
		{Type: ir.EventBlockStart, Index: 1, Block: &ir.Block{Type: ir.BlockText}},
		{Type: ir.EventTextDelta, Index: 1, Delta: "he"},
		{Type: ir.EventTextDelta, Index: 1, Delta: "y"},
		{Type: ir.EventBlockStop, Index: 1},
		{Type: ir.EventBlockStart, Index: 2, Block: &ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t1", Name: "f"}}},
		{Type: ir.EventArgsDelta, Index: 2, Delta: `{"a":`},
		{Type: ir.EventArgsDelta, Index: 2, Delta: `1}`},
		{Type: ir.EventBlockStop, Index: 2},
		{Type: ir.EventMessageDelta, StopReason: ir.StopToolUse, Usage: &ir.Usage{InputTokens: 7, OutputTokens: 3}},
		{Type: ir.EventMessageStop},
	}
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}

	frames := readEvents(t, buf.String())
	wantNames := []string{
		"message_start", "ping",
		"content_block_start", "content_block_delta", "content_block_delta", "content_block_stop",
		"content_block_start", "content_block_delta", "content_block_delta", "content_block_stop",
		"content_block_start", "content_block_delta", "content_block_delta", "content_block_stop",
		"message_delta", "message_stop",
	}
	var names []string
	for _, f := range frames {
		names = append(names, f.Name)
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("event names = %v\nwant %v", names, wantNames)
	}

	var start map[string]any
	_ = json.Unmarshal(frames[0].Data, &start)
	msg := start["message"].(map[string]any)
	if msg["id"] != "m1" || msg["model"] != "qwen3" || msg["stop_reason"] != nil {
		t.Fatalf("message_start wrong: %v", msg)
	}

	var tool map[string]any
	_ = json.Unmarshal(frames[10].Data, &tool)
	cb := tool["content_block"].(map[string]any)
	if cb["type"] != "tool_use" || cb["id"] != "t1" || cb["name"] != "f" {
		t.Fatalf("tool block start wrong: %v", cb)
	}

	var argsDelta map[string]any
	_ = json.Unmarshal(frames[11].Data, &argsDelta)
	if argsDelta["delta"].(map[string]any)["partial_json"] != `{"a":` {
		t.Fatalf("args delta wrong: %v", argsDelta)
	}

	var md map[string]any
	_ = json.Unmarshal(frames[14].Data, &md)
	if md["delta"].(map[string]any)["stop_reason"] != "tool_use" ||
		md["usage"].(map[string]any)["input_tokens"].(float64) != 7 {
		t.Fatalf("message_delta wrong: %v", md)
	}
}

func TestEventEncoderMessageDeltaDefaults(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	if err := enc.Encode(ir.Event{Type: ir.EventMessageDelta}); err != nil {
		t.Fatal(err)
	}
	frames := readEvents(t, buf.String())
	var md map[string]any
	_ = json.Unmarshal(frames[0].Data, &md)
	if md["delta"].(map[string]any)["stop_reason"] != "end_turn" {
		t.Fatalf("default stop reason wrong: %v", md)
	}
	if _, hasUsage := md["usage"]; hasUsage {
		t.Fatal("usage should be omitted when absent")
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

func contains(ss []ir.LossField, want ir.LossField) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"x"}]}]}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = NewFrontend().DecodeRequest(body) // must not panic
	})
}
