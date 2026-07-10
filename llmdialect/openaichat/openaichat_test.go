package openaichat

import (
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func i64(v int64) *int64     { return &v }
func f64(v float64) *float64 { return &v }

func encode(t *testing.T, req *ir.Request, opts BackendOptions) map[string]any {
	t.Helper()
	raw, err := NewBackend(opts).EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestName(t *testing.T) {
	if NewBackend(BackendOptions{}).Name() != DialectName {
		t.Fatal("name mismatch")
	}
}

func TestEncodeRequestFull(t *testing.T) {
	req := &ir.Request{
		Model:  "qwen3-32b",
		System: []ir.Block{{Type: ir.BlockText, Text: "sys a"}, {Type: ir.BlockText, Text: "sys b", CacheHint: true}},
		Messages: []ir.Message{
			{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hello"}}},
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockText, Text: "checking"},
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t1", Name: "get_time", Args: json.RawMessage(`{"tz":"UTC"}`)}},
			}},
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: "t1", Blocks: []ir.Block{{Type: ir.BlockText, Text: "14:02"}}}},
				{Type: ir.BlockText, Text: "thanks"},
			}},
		},
		Tools:         []ir.Tool{{Name: "get_time", Description: "clock", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		ToolChoice:    &ir.ToolChoice{Mode: ir.ToolChoiceAuto, DisableParallel: true},
		MaxTokens:     i64(4096),
		Temperature:   f64(0.5),
		TopP:          f64(0.9),
		StopSequences: []string{"END"},
		Stream:        true,
		UserID:        "u-1",
	}
	got := encode(t, req, BackendOptions{})

	if got["model"] != "qwen3-32b" || got["max_tokens"].(float64) != 4096 ||
		got["temperature"].(float64) != 0.5 || got["top_p"].(float64) != 0.9 ||
		got["user"] != "u-1" || got["stream"] != true {
		t.Fatalf("scalars wrong: %v", got)
	}
	if !reflect.DeepEqual(got["stream_options"], map[string]any{"include_usage": true}) {
		t.Fatalf("stream_options wrong: %v", got["stream_options"])
	}
	if !reflect.DeepEqual(got["stop"], []any{"END"}) {
		t.Fatalf("stop wrong: %v", got["stop"])
	}
	if got["tool_choice"] != "auto" || got["parallel_tool_calls"] != false {
		t.Fatalf("tool choice wrong: %v", got)
	}

	msgs := got["messages"].([]any)
	if len(msgs) != 5 { // system, user, assistant, tool, user
		t.Fatalf("want 5 messages, got %d: %v", len(msgs), msgs)
	}
	sys := msgs[0].(map[string]any)
	if sys["role"] != "system" || sys["content"] != "sys a\n\nsys b" {
		t.Fatalf("system wrong: %v", sys)
	}
	if m := msgs[1].(map[string]any); m["content"] != "hello" {
		t.Fatalf("user message should be a plain string: %v", m)
	}
	asst := msgs[2].(map[string]any)
	tc := asst["tool_calls"].([]any)[0].(map[string]any)
	if asst["content"] != "checking" || tc["id"] != "t1" ||
		tc["function"].(map[string]any)["arguments"] != `{"tz":"UTC"}` {
		t.Fatalf("assistant wrong: %v", asst)
	}
	tool := msgs[3].(map[string]any)
	if tool["role"] != "tool" || tool["tool_call_id"] != "t1" || tool["content"] != "14:02" {
		t.Fatalf("tool message wrong: %v", tool)
	}
	if m := msgs[4].(map[string]any); m["content"] != "thanks" {
		t.Fatalf("trailing user wrong: %v", m)
	}
	if !contains(req.Loss.Fields(), "cache_control") {
		t.Fatalf("cache_control loss missing: %v", req.Loss.Fields())
	}
}

func TestEncodeRequestImagesAndParts(t *testing.T) {
	req := &ir.Request{
		Model: "m",
		Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{
			{Type: ir.BlockText, Text: "what is this"},
			{Type: ir.BlockImage, Image: &ir.Image{MediaType: "image/png", Data: "AAAA"}},
			{Type: ir.BlockImage, Image: &ir.Image{URL: "https://x/y.png"}},
		}}},
	}
	got := encode(t, req, BackendOptions{})
	content := got["messages"].([]any)[0].(map[string]any)["content"].([]any)
	if len(content) != 3 {
		t.Fatalf("want 3 parts, got %v", content)
	}
	p1 := content[1].(map[string]any)["image_url"].(map[string]any)
	if p1["url"] != "data:image/png;base64,AAAA" {
		t.Fatalf("data uri wrong: %v", p1)
	}
	p2 := content[2].(map[string]any)["image_url"].(map[string]any)
	if p2["url"] != "https://x/y.png" {
		t.Fatalf("url wrong: %v", p2)
	}
}

func TestEncodeRequestToolChoiceModes(t *testing.T) {
	base := func() *ir.Request {
		return &ir.Request{Model: "m", Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}}}
	}
	req := base()
	req.ToolChoice = &ir.ToolChoice{Mode: ir.ToolChoiceAny}
	if got := encode(t, req, BackendOptions{}); got["tool_choice"] != "required" {
		t.Fatalf("any → %v", got["tool_choice"])
	}
	req = base()
	req.ToolChoice = &ir.ToolChoice{Mode: ir.ToolChoiceNone}
	if got := encode(t, req, BackendOptions{}); got["tool_choice"] != "none" {
		t.Fatalf("none → %v", got["tool_choice"])
	}
	req = base()
	req.ToolChoice = &ir.ToolChoice{Mode: ir.ToolChoiceTool, Name: "f"}
	got := encode(t, req, BackendOptions{})
	want := map[string]any{"type": "function", "function": map[string]any{"name": "f"}}
	if !reflect.DeepEqual(got["tool_choice"], want) {
		t.Fatalf("tool → %v", got["tool_choice"])
	}
	req = base()
	req.ToolChoice = &ir.ToolChoice{Mode: "weird"}
	if _, err := NewBackend(BackendOptions{}).EncodeRequest(req); err == nil {
		t.Fatal("want unknown mode error")
	}
}

func TestEncodeRequestLossyParams(t *testing.T) {
	req := &ir.Request{
		Model:         "m",
		Messages:      []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}},
		TopK:          i64(40),
		StopSequences: []string{"a", "b", "c", "d", "e"},
	}
	got := encode(t, req, BackendOptions{})
	if _, ok := got["top_k"]; ok {
		t.Fatal("top_k must not be emitted")
	}
	if stop := got["stop"].([]any); len(stop) != 4 {
		t.Fatalf("stop should truncate to 4, got %v", stop)
	}
	for _, want := range []ir.LossField{"top_k", "stop_sequences"} {
		if !contains(req.Loss.Fields(), want) {
			t.Fatalf("loss %v missing %q", req.Loss.Fields(), want)
		}
	}
}

func TestEncodeRequestReasoning(t *testing.T) {
	base := func(r *ir.Reasoning) *ir.Request {
		return &ir.Request{Model: "m", Reasoning: r,
			Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}}}
	}
	req := base(&ir.Reasoning{Effort: "high"})
	if got := encode(t, req, BackendOptions{}); got["reasoning_effort"] != "high" {
		t.Fatalf("effort passthrough wrong: %v", got["reasoning_effort"])
	}
	for budget, want := range map[int64]string{1024: "low", 4096: "medium", 30000: "high"} {
		req := base(&ir.Reasoning{BudgetTokens: budget})
		if got := encode(t, req, BackendOptions{}); got["reasoning_effort"] != want {
			t.Fatalf("budget %d → %v want %s", budget, got["reasoning_effort"], want)
		}
		if !contains(req.Loss.Fields(), "thinking.budget_tokens") {
			t.Fatal("budget approximation must be recorded as loss")
		}
	}
}

func TestEncodeRequestSchemaAndMaxCompletionTokens(t *testing.T) {
	req := &ir.Request{
		Model:     "m",
		MaxTokens: i64(100),
		Schema:    &ir.ResponseSchema{Name: "out", Description: "d", Schema: json.RawMessage(`{"type":"object"}`), Strict: true},
		Messages:  []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}},
	}
	got := encode(t, req, BackendOptions{UseMaxCompletionTokens: true})
	if _, ok := got["max_tokens"]; ok {
		t.Fatal("max_tokens must not be emitted with UseMaxCompletionTokens")
	}
	if got["max_completion_tokens"].(float64) != 100 {
		t.Fatalf("max_completion_tokens wrong: %v", got)
	}
	rf := got["response_format"].(map[string]any)
	js := rf["json_schema"].(map[string]any)
	if rf["type"] != "json_schema" || js["name"] != "out" || js["strict"] != true || js["description"] != "d" {
		t.Fatalf("response_format wrong: %v", rf)
	}
}

func TestEncodeRequestThinkingDroppedAndEmptySchema(t *testing.T) {
	req := &ir.Request{
		Model: "m",
		Messages: []ir.Message{{Role: ir.RoleAssistant, Blocks: []ir.Block{
			{Type: ir.BlockThinking, Text: "hm", Signature: "s"},
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t1", Name: "f"}},
		}}},
		Tools: []ir.Tool{{Name: "f"}},
	}
	got := encode(t, req, BackendOptions{})
	asst := got["messages"].([]any)[0].(map[string]any)
	if asst["content"] != nil {
		t.Fatalf("empty assistant content should be null: %v", asst)
	}
	tc := asst["tool_calls"].([]any)[0].(map[string]any)
	if tc["function"].(map[string]any)["arguments"] != "{}" {
		t.Fatalf("empty args should encode as {}: %v", tc)
	}
	fn := got["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)
	if !reflect.DeepEqual(fn["parameters"], map[string]any{"type": "object"}) {
		t.Fatalf("empty schema should default: %v", fn)
	}
	if !contains(req.Loss.Fields(), "thinking") {
		t.Fatalf("thinking loss missing: %v", req.Loss.Fields())
	}
}

func TestEncodeRequestToolResultLosses(t *testing.T) {
	req := &ir.Request{
		Model: "m",
		Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{
			{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: "t1", IsError: true, Blocks: []ir.Block{
				{Type: ir.BlockText, Text: "boom"},
				{Type: ir.BlockImage, Image: &ir.Image{URL: "https://x"}},
			}}},
		}}},
	}
	got := encode(t, req, BackendOptions{})
	tool := got["messages"].([]any)[0].(map[string]any)
	if tool["content"] != "boom" {
		t.Fatalf("tool content wrong: %v", tool)
	}
	for _, want := range []ir.LossField{"tool_result.image", "tool_result.is_error"} {
		if !contains(req.Loss.Fields(), want) {
			t.Fatalf("loss %v missing %q", req.Loss.Fields(), want)
		}
	}
}

func TestEncodeRequestRoleErrors(t *testing.T) {
	cases := []ir.Message{
		{Role: "system", Blocks: []ir.Block{{Type: ir.BlockText}}},
		{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{}}}},
		{Role: ir.RoleAssistant, Blocks: []ir.Block{{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{}}}},
	}
	for i, m := range cases {
		req := &ir.Request{Model: "m", Messages: []ir.Message{m}}
		if _, err := NewBackend(BackendOptions{}).EncodeRequest(req); err == nil {
			t.Fatalf("case %d: want error", i)
		}
	}
}

func TestDecodeResponse(t *testing.T) {
	body := `{
		"id": "chatcmpl-1", "model": "qwen3",
		"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
			"content": "on it",
			"reasoning_content": "think",
			"tool_calls": [{"id": "t1", "type": "function", "function": {"name": "f", "arguments": "{\"a\":1}"}}]
		}}],
		"usage": {"prompt_tokens": 100, "completion_tokens": 20,
			"prompt_tokens_details": {"cached_tokens": 60},
			"completion_tokens_details": {"reasoning_tokens": 5}}
	}`
	resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != "chatcmpl-1" || resp.Model != "qwen3" || resp.StopReason != ir.StopToolUse {
		t.Fatalf("envelope wrong: %+v", resp)
	}
	if len(resp.Blocks) != 3 ||
		resp.Blocks[0].Type != ir.BlockThinking || resp.Blocks[0].Text != "think" ||
		resp.Blocks[1].Text != "on it" ||
		resp.Blocks[2].ToolUse.Name != "f" || string(resp.Blocks[2].ToolUse.Args) != `{"a":1}` {
		t.Fatalf("blocks wrong: %+v", resp.Blocks)
	}
	// IR input tokens exclude cache reads: 100 prompt - 60 cached = 40.
	want := ir.Usage{InputTokens: 40, OutputTokens: 20, CacheReadInputTokens: 60, ReasoningTokens: 5}
	if resp.Usage != want {
		t.Fatalf("usage = %+v want %+v", resp.Usage, want)
	}
}

func TestDecodeResponseStopReasons(t *testing.T) {
	for finish, want := range map[string]ir.StopReason{
		"stop": ir.StopEndTurn, "length": ir.StopMaxTokens,
		"content_filter": ir.StopRefusal, "function_call": ir.StopToolUse,
	} {
		body := `{"id":"x","choices":[{"finish_reason":"` + finish + `","message":{"content":"y"}}]}`
		resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StopReason != want {
			t.Fatalf("%s → %v want %v", finish, resp.StopReason, want)
		}
	}
	// Runtimes that report "stop" despite emitting tool calls.
	body := `{"id":"x","choices":[{"finish_reason":"stop","message":{
		"tool_calls":[{"id":"t","function":{"name":"f","arguments":"{}"}}]}}]}`
	resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StopReason != ir.StopToolUse {
		t.Fatalf("tool presence must win: %v", resp.StopReason)
	}
}

func TestDecodeResponseRefusalAndCappedUsage(t *testing.T) {
	body := `{"id":"x","choices":[{"finish_reason":"stop","message":{"refusal":"no"}}],
		"usage":{"prompt_tokens":5,"prompt_tokens_details":{"cached_tokens":9}}}`
	resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StopReason != ir.StopRefusal || resp.Blocks[0].Text != "no" {
		t.Fatalf("refusal wrong: %+v", resp)
	}
	if resp.Usage.InputTokens != 0 {
		t.Fatalf("input tokens must not go negative: %+v", resp.Usage)
	}
}

func TestDecodeResponseErrors(t *testing.T) {
	if _, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(`{`)); err == nil {
		t.Fatal("want JSON error")
	}
	if _, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(`{"id":"x","choices":[]}`)); err == nil {
		t.Fatal("want no-choices error")
	}
	_, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(`{"error":{"message":"nope","type":"invalid_request_error"}}`))
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("want upstream error, got %v", err)
	}
}

func drain(t *testing.T, stream string) []ir.Event {
	t.Helper()
	dec := NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader(stream))
	var out []ir.Event
	for {
		ev, err := dec.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
}

func chunk(s string) string { return "data: " + s + "\n\n" }

func TestEventDecoderTextAndTools(t *testing.T) {
	stream := chunk(`{"id":"c1","model":"qwen3","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`) +
		chunk(`{"id":"c1","choices":[{"index":0,"delta":{"content":"he"}}]}`) +
		chunk(`{"id":"c1","choices":[{"index":0,"delta":{"content":"y"}}]}`) +
		chunk(`{"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"t1","function":{"name":"f","arguments":""}}]}}]}`) +
		chunk(`{"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"a\":1}"}}]}}]}`) +
		chunk(`{"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"t2","function":{"name":"g","arguments":"{}"}}]}}]}`) +
		chunk(`{"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`) +
		chunk(`{"id":"c1","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":4}}`) +
		chunk(`[DONE]`)

	events := drain(t, stream)
	var types []ir.EventType
	for _, ev := range events {
		types = append(types, ev.Type)
	}
	want := []ir.EventType{
		ir.EventMessageStart,
		ir.EventBlockStart, ir.EventTextDelta, ir.EventTextDelta, ir.EventBlockStop,
		ir.EventBlockStart, ir.EventArgsDelta, ir.EventBlockStop,
		ir.EventBlockStart, ir.EventArgsDelta, ir.EventBlockStop,
		ir.EventMessageDelta, ir.EventMessageStop,
	}
	if !reflect.DeepEqual(types, want) {
		t.Fatalf("event types = %v\nwant %v", types, want)
	}
	if events[0].ID != "c1" || events[0].Model != "qwen3" {
		t.Fatalf("message start wrong: %+v", events[0])
	}
	if events[5].Block.ToolUse.ID != "t1" || events[5].Block.ToolUse.Name != "f" || events[5].Index != 1 {
		t.Fatalf("first tool start wrong: %+v", events[5])
	}
	if events[8].Block.ToolUse.ID != "t2" || events[8].Index != 2 {
		t.Fatalf("second tool start wrong: %+v", events[8])
	}
	md := events[11]
	if md.StopReason != ir.StopToolUse || md.Usage == nil || md.Usage.InputTokens != 10 || md.Usage.OutputTokens != 4 {
		t.Fatalf("message delta wrong: %+v", md)
	}
}

func TestEventDecoderReasoningTransition(t *testing.T) {
	stream := chunk(`{"id":"c1","model":"m","choices":[{"index":0,"delta":{"reasoning_content":"hm"}}]}`) +
		chunk(`{"id":"c1","choices":[{"index":0,"delta":{"reasoning_content":"m2"}}]}`) +
		chunk(`{"id":"c1","choices":[{"index":0,"delta":{"content":"answer"}}]}`) +
		chunk(`{"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`) +
		chunk(`[DONE]`)
	events := drain(t, stream)
	var types []ir.EventType
	for _, ev := range events {
		types = append(types, ev.Type)
	}
	want := []ir.EventType{
		ir.EventMessageStart,
		ir.EventBlockStart, ir.EventThinkingDelta, ir.EventThinkingDelta, ir.EventBlockStop,
		ir.EventBlockStart, ir.EventTextDelta, ir.EventBlockStop,
		ir.EventMessageDelta, ir.EventMessageStop,
	}
	if !reflect.DeepEqual(types, want) {
		t.Fatalf("event types = %v\nwant %v", types, want)
	}
	if events[1].Block.Type != ir.BlockThinking || events[5].Block.Type != ir.BlockText {
		t.Fatal("block kinds wrong")
	}
	if events[8].StopReason != ir.StopEndTurn {
		t.Fatalf("stop reason wrong: %v", events[8].StopReason)
	}
}

func TestEventDecoderNoDoneMarker(t *testing.T) {
	// Some runtimes close the stream without data: [DONE].
	stream := chunk(`{"id":"c1","model":"m","choices":[{"index":0,"delta":{"content":"x"}}]}`)
	events := drain(t, stream)
	last := events[len(events)-1]
	if last.Type != ir.EventMessageStop {
		t.Fatalf("stream must still end with message_stop, got %v", last.Type)
	}
}

func TestEventDecoderSkipsOtherChoices(t *testing.T) {
	stream := chunk(`{"id":"c1","model":"m","choices":[{"index":1,"delta":{"content":"IGNORED"}}]}`) +
		chunk(`[DONE]`)
	for _, ev := range drain(t, stream) {
		if ev.Type == ir.EventTextDelta {
			t.Fatal("choice index 1 must be skipped")
		}
	}
}

func TestEventDecoderErrors(t *testing.T) {
	dec := NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader(chunk(`{nope`)))
	if _, err := dec.Next(); err == nil {
		t.Fatal("want chunk parse error")
	}
	dec = NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader(chunk(`{"error":{"message":"overloaded","type":"server_error"}}`)))
	if _, err := dec.Next(); err == nil || !strings.Contains(err.Error(), "overloaded") {
		t.Fatal("want upstream stream error")
	}
}

func TestEventDecoderUsageOnlyStream(t *testing.T) {
	// Degenerate: usage chunk then DONE, no content at all.
	stream := chunk(`{"id":"c1","model":"m","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":0}}`) +
		chunk(`[DONE]`)
	events := drain(t, stream)
	var types []ir.EventType
	for _, ev := range events {
		types = append(types, ev.Type)
	}
	want := []ir.EventType{ir.EventMessageStart, ir.EventMessageDelta, ir.EventMessageStop}
	if !reflect.DeepEqual(types, want) {
		t.Fatalf("event types = %v want %v", types, want)
	}
	if events[1].Usage == nil || events[1].Usage.InputTokens != 3 {
		t.Fatalf("usage missing: %+v", events[1])
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

func FuzzDecodeResponse(f *testing.F) {
	f.Add([]byte(`{"id":"x","choices":[{"message":{"content":"y"}}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = NewBackend(BackendOptions{}).DecodeResponse(body) // must not panic
	})
}

func FuzzEventDecoder(f *testing.F) {
	f.Add([]byte("data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\ndata: [DONE]\n\n"))
	f.Add([]byte("data: {\n\n"))
	f.Fuzz(func(t *testing.T, stream []byte) {
		dec := NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader(string(stream)))
		for i := 0; i < 10000; i++ {
			if _, err := dec.Next(); err != nil {
				return
			}
		}
	})
}
