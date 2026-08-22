package openairesp

import (
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// reasoningEffort banding over Anthropic-style token budgets, plus the
// explicit-effort short-circuit.
func TestBackendReasoningEffortBanding(t *testing.T) {
	cases := []struct {
		r    ir.Reasoning
		want string
	}{
		{ir.Reasoning{Effort: ir.EffortMedium}, "medium"},
		{ir.Reasoning{BudgetTokens: 1000}, "low"},
		{ir.Reasoning{BudgetTokens: 5000}, "medium"},
		{ir.Reasoning{BudgetTokens: 20000}, "high"},
	}
	for _, c := range cases {
		req := &ir.Request{Model: "m", Reasoning: &c.r,
			Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}}}
		raw, err := NewBackend().EncodeRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		body := mustJSON(t, raw)
		got := body["reasoning"].(map[string]any)["effort"]
		if got != c.want {
			t.Errorf("budget %+v: effort = %v, want %v", c.r, got, c.want)
		}
	}
}

// EncodeRequest secondary fields: tool_choice variants, schema, top_p,
// user, image, and the loss-recorded fields.
func TestBackendEncodeRequestExtras(t *testing.T) {
	topP := 0.9
	cases := []struct {
		name   string
		mut    func(*ir.Request)
		assert func(*testing.T, map[string]any, *ir.Request)
	}{
		{"tool_choice required", func(r *ir.Request) { r.ToolChoice = &ir.ToolChoice{Mode: ir.ToolChoiceAny} },
			func(t *testing.T, b map[string]any, _ *ir.Request) {
				if b["tool_choice"] != "required" {
					t.Errorf("tool_choice = %v", b["tool_choice"])
				}
			}},
		{"tool_choice none", func(r *ir.Request) { r.ToolChoice = &ir.ToolChoice{Mode: ir.ToolChoiceNone} },
			func(t *testing.T, b map[string]any, _ *ir.Request) {
				if b["tool_choice"] != "none" {
					t.Errorf("tool_choice = %v", b["tool_choice"])
				}
			}},
		{"tool_choice named + no-parallel", func(r *ir.Request) {
			r.ToolChoice = &ir.ToolChoice{Mode: ir.ToolChoiceTool, Name: "shell", DisableParallel: true}
		}, func(t *testing.T, b map[string]any, _ *ir.Request) {
			tc := b["tool_choice"].(map[string]any)
			if tc["type"] != "function" || tc["name"] != "shell" {
				t.Errorf("tool_choice = %v", tc)
			}
			if b["parallel_tool_calls"] != false {
				t.Errorf("parallel_tool_calls = %v", b["parallel_tool_calls"])
			}
		}},
		{"schema + top_p + user", func(r *ir.Request) {
			r.TopP = &topP
			r.UserID = "u1"
			r.Schema = &ir.ResponseSchema{Name: "out", Description: "d", Schema: json.RawMessage(`{"type":"object"}`), Strict: true}
		}, func(t *testing.T, b map[string]any, _ *ir.Request) {
			if b["top_p"].(float64) != 0.9 || b["user"] != "u1" {
				t.Errorf("top_p/user = %v %v", b["top_p"], b["user"])
			}
			fmt := b["text"].(map[string]any)["format"].(map[string]any)
			if fmt["type"] != "json_schema" || fmt["name"] != "out" || fmt["strict"] != true {
				t.Errorf("format = %v", fmt)
			}
		}},
		{"topk + stop loss", func(r *ir.Request) {
			k := int64(40)
			r.TopK = &k
			r.StopSequences = []string{"END"}
		}, func(t *testing.T, _ map[string]any, r *ir.Request) {
			ls := r.Loss.Strings()
			if !slices.Contains(ls, "top_k") || !slices.Contains(ls, "stop_sequences") {
				t.Errorf("loss = %v", ls)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := &ir.Request{Model: "m",
				Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}}}
			c.mut(req)
			raw, err := NewBackend().EncodeRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			c.assert(t, mustJSON(t, raw), req)
		})
	}
}

func TestBackendEncodeImagesAndLoss(t *testing.T) {
	req := &ir.Request{
		Model:  "m",
		System: []ir.Block{{Type: ir.BlockText, Text: "sys", CacheHint: true}},
		Messages: []ir.Message{
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockImage, Image: &ir.Image{URL: "https://x/y.png"}},
				{Type: ir.BlockImage, Image: &ir.Image{MediaType: "image/png", Data: "AAAA"}},
			}},
			{Role: ir.RoleAssistant, Blocks: []ir.Block{{Type: ir.BlockThinking, Text: "hmm"}}},
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: "c1", IsError: true, Blocks: []ir.Block{
					{Type: ir.BlockText, Text: "boom"}, {Type: ir.BlockImage, Image: &ir.Image{URL: "u"}},
				}}},
			}},
		},
	}
	raw, err := NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON(t, raw)
	input := body["input"].([]any)
	// first item: user message with two images (url + data URI)
	content := input[0].(map[string]any)["content"].([]any)
	if content[0].(map[string]any)["image_url"] != "https://x/y.png" {
		t.Errorf("image url = %v", content[0])
	}
	if !strings.HasPrefix(content[1].(map[string]any)["image_url"].(string), "data:image/png;base64,") {
		t.Errorf("image data uri = %v", content[1])
	}
	ls := req.Loss.Strings()
	for _, want := range []string{"cache_control", "thinking", "tool_result.image", "tool_result.is_error"} {
		if !slices.Contains(ls, want) {
			t.Errorf("missing loss %q in %v", want, ls)
		}
	}
}

func TestBackendEncodeRequestErrors(t *testing.T) {
	// unknown role
	if _, err := NewBackend().EncodeRequest(&ir.Request{Model: "m",
		Messages: []ir.Message{{Role: ir.Role("weird"), Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}}}); err == nil {
		t.Error("want unknown-role error")
	}
	// image in assistant message
	if _, err := NewBackend().EncodeRequest(&ir.Request{Model: "m",
		Messages: []ir.Message{{Role: ir.RoleAssistant, Blocks: []ir.Block{{Type: ir.BlockImage, Image: &ir.Image{URL: "u"}}}}}}); err == nil {
		t.Error("want assistant-image error")
	}
	// unknown tool choice mode
	if _, err := NewBackend().EncodeRequest(&ir.Request{Model: "m",
		ToolChoice: &ir.ToolChoice{Mode: ir.ToolChoiceMode("bogus")},
		Messages:   []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}}}); err == nil {
		t.Error("want tool-choice error")
	}
}

func TestBackendDecodeResponseEdge(t *testing.T) {
	// string content form, empty function args default, end_turn, usage clamp
	body := `{"id":"resp_e","model":"m","status":"completed","output":[
		{"type":"message","role":"assistant","content":"plain string"},
		{"type":"reasoning","summary":[]}
	],"usage":{"input_tokens":3,"output_tokens":1,"input_tokens_details":{"cached_tokens":9}}}`
	resp, err := NewBackend().DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Blocks) != 1 || resp.Blocks[0].Text != "plain string" {
		t.Fatalf("blocks = %+v", resp.Blocks)
	}
	if resp.StopReason != ir.StopEndTurn {
		t.Errorf("stop = %v", resp.StopReason)
	}
	if resp.Usage.InputTokens != 0 { // 3 - 9 clamped to 0
		t.Errorf("input tokens clamp = %d", resp.Usage.InputTokens)
	}
	// function_call with empty arguments defaults to {}
	body2 := `{"id":"r","model":"m","status":"completed","output":[
		{"type":"function_call","call_id":"c","name":"f","arguments":""}]}`
	resp2, _ := NewBackend().DecodeResponse([]byte(body2))
	if string(resp2.Blocks[0].ToolUse.Args) != "{}" {
		t.Errorf("empty args = %s", resp2.Blocks[0].ToolUse.Args)
	}
}

func TestBackendDecodeOutputTextInvalid(t *testing.T) {
	// content that is neither string nor part array yields no text (not an error)
	body := `{"id":"r","model":"m","status":"completed","output":[
		{"type":"message","role":"assistant","content":42}]}`
	resp, err := NewBackend().DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Blocks) != 0 {
		t.Errorf("blocks = %+v", resp.Blocks)
	}
}

// Streaming edge cases: reasoning deltas and EOF without a terminal event.
func TestBackendEventDecoderReasoningAndEOF(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_a","model":"m"}}`, ``,
		`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"reasoning","id":"rs_0"}}`, ``,
		`data: {"type":"response.reasoning_summary_text.delta","item_id":"rs_0","output_index":0,"delta":"think"}`, ``,
		`data: {"type":"response.output_item.done","output_index":0,"item":{"type":"reasoning"}}`, ``,
	}, "\n") // no response.completed → EOF path
	dec := NewBackend().NewEventDecoder(strings.NewReader(stream))
	var thinking strings.Builder
	var sawStart, sawStop bool
	for {
		ev, err := dec.Next()
		if errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch ev.Type {
		case ir.EventMessageStart:
			sawStart = true
		case ir.EventThinkingDelta:
			thinking.WriteString(ev.Delta)
		case ir.EventMessageStop:
			sawStop = true
		}
	}
	if !sawStart || sawStop || thinking.String() != "think" {
		t.Errorf("start=%v stop=%v thinking=%q", sawStart, sawStop, thinking.String())
	}
}

func TestBackendEventDecoderIncomplete(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_i","model":"m"}}`, ``,
		`data: {"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}}`, ``,
	}, "\n")
	dec := NewBackend().NewEventDecoder(strings.NewReader(stream))
	var stop ir.StopReason
	for {
		ev, err := dec.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if ev.Type == ir.EventMessageDelta {
			stop = ev.StopReason
		}
	}
	if stop != ir.StopMaxTokens {
		t.Errorf("stop = %v", stop)
	}
}

func TestBackendEventDecoderErrors(t *testing.T) {
	// The legacy nested error shape remains accepted.
	dec := NewBackend().NewEventDecoder(strings.NewReader("data: {\"type\":\"error\",\"error\":{\"message\":\"x\",\"type\":\"e\"}}\n\n"))
	if _, err := dec.Next(); err == nil {
		t.Error("want error frame")
	}
	// The official error event carries code and message at top level.
	dec = NewBackend().NewEventDecoder(strings.NewReader("data: {\"type\":\"error\",\"code\":\"server_error\",\"message\":\"boom\"}\n\n"))
	if _, err := dec.Next(); err == nil || !strings.Contains(err.Error(), "server_error") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("official error frame = %v", err)
	}
	// response.failed carries its error inside the response object.
	failed := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_f","model":"m"}}`, ``,
		`data: {"type":"response.failed","response":{"status":"failed","error":{"code":"model_error","message":"failed generation"}}}`, ``,
	}, "\n")
	dec = NewBackend().NewEventDecoder(strings.NewReader(failed))
	if ev, err := dec.Next(); err != nil || ev.Type != ir.EventMessageStart {
		t.Fatalf("start event = %+v, %v", ev, err)
	}
	if _, err := dec.Next(); err == nil || !strings.Contains(err.Error(), "model_error") {
		t.Fatalf("response.failed error = %v", err)
	}
	// A cancelled response is also terminal and cannot become end_turn.
	dec = NewBackend().NewEventDecoder(strings.NewReader("data: {\"type\":\"response.cancelled\",\"response\":{\"status\":\"cancelled\"}}\n\n"))
	if _, err := dec.Next(); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("response.cancelled error = %v", err)
	}
	// invalid JSON frame surfaces as an error
	dec2 := NewBackend().NewEventDecoder(strings.NewReader("data: {not json\n\n"))
	if _, err := dec2.Next(); err == nil {
		t.Error("want invalid-frame error")
	}
}

func TestBackendUpstreamError(t *testing.T) {
	err := (&respError{Message: "m", Type: "t"}).Error()
	if !strings.Contains(err, "m") || !strings.Contains(err, "t") {
		t.Errorf("error string = %q", err)
	}
}

// errReader fails after handing back its payload, exercising the
// non-EOF read-error path in the stream decoder.
type errReader struct {
	data []byte
	done bool
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.done {
		return 0, io.ErrUnexpectedEOF
	}
	e.done = true
	n := copy(p, e.data)
	return n, nil
}

// Covers the default-value branches: a tool with no schema, a tool_use
// with empty args, and a cache-hinted block inside a message.
func TestBackendEncodeDefaults(t *testing.T) {
	req := &ir.Request{
		Model: "m",
		Tools: []ir.Tool{{Name: "noschema"}}, // empty InputSchema → {"type":"object"}
		Messages: []ir.Message{
			{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi", CacheHint: true}}},
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "c", Name: "noschema"}}, // empty Args → {}
			}},
		},
	}
	raw, err := NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON(t, raw)
	tool := body["tools"].([]any)[0].(map[string]any)
	if string(mustMarshal(t, tool["parameters"])) != `{"type":"object"}` {
		t.Errorf("default schema = %v", tool["parameters"])
	}
	var fc map[string]any
	for _, it := range body["input"].([]any) {
		if m := it.(map[string]any); m["type"] == "function_call" {
			fc = m
		}
	}
	if fc["arguments"] != "{}" {
		t.Errorf("default args = %v", fc["arguments"])
	}
	if !slices.Contains(req.Loss.Strings(), "cache_control") {
		t.Errorf("cache loss missing: %v", req.Loss.Strings())
	}
}

// A message item with no content field decodes to no text (len-0 raw path).
func TestBackendDecodeMessageNoContent(t *testing.T) {
	resp, err := NewBackend().DecodeResponse([]byte(
		`{"id":"r","model":"m","status":"completed","output":[{"type":"message","role":"assistant"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Blocks) != 0 {
		t.Errorf("blocks = %+v", resp.Blocks)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The Responses API caps `user` at 64 chars; harnesses (Claude Code)
// send longer session ids, so the backend must cap it rather than emit
// an over-long value that upstream 400s on.
func TestBackendEncodeUserCapped(t *testing.T) {
	long := strings.Repeat("a", 150)
	req := &ir.Request{Model: "m", UserID: long,
		Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}}}
	raw, err := NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON(t, raw)
	u, _ := body["user"].(string)
	if len(u) > 64 {
		t.Errorf("user len = %d, want <= 64", len(u))
	}
	if !slices.Contains(req.Loss.Strings(), "user.truncated") {
		t.Errorf("truncation loss missing: %v", req.Loss.Strings())
	}
	// A short user id passes through untouched with no loss.
	req2 := &ir.Request{Model: "m", UserID: "u1",
		Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}}}
	raw2, _ := NewBackend().EncodeRequest(req2)
	if mustJSON(t, raw2)["user"] != "u1" {
		t.Errorf("short user changed")
	}
	if slices.Contains(req2.Loss.Strings(), "user.truncated") {
		t.Errorf("unexpected truncation loss for short user")
	}
}

func TestBackendEncodeMessageBadBlock(t *testing.T) {
	// an unrepresentable block type in a message errors out
	_, err := NewBackend().EncodeRequest(&ir.Request{Model: "m",
		Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockType("bogus")}}}}})
	if err == nil {
		t.Error("want bad-block error")
	}
}

func TestBackendDecodeEmptyStringContent(t *testing.T) {
	// message with an empty string content contributes no text block
	resp, err := NewBackend().DecodeResponse([]byte(
		`{"id":"r","model":"m","status":"completed","output":[{"type":"message","role":"assistant","content":""}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Blocks) != 0 {
		t.Errorf("blocks = %+v", resp.Blocks)
	}
}

func TestBackendEventDecoderOpenBlockAtEOF(t *testing.T) {
	// A message item opened but never completed is a truncated upstream stream,
	// not a successful response with a synthetic terminal tail.
	stream := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_o","model":"m"}}`, ``,
		`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_0","role":"assistant"}}`, ``,
		`data: {"type":"response.output_text.delta","item_id":"msg_0","output_index":0,"delta":"hi"}`, ``,
	}, "\n")
	dec := NewBackend().NewEventDecoder(strings.NewReader(stream))
	var seq []ir.EventType
	for {
		ev, err := dec.Next()
		if errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seq = append(seq, ev.Type)
	}
	var sawSyntheticTerminal bool
	for _, e := range seq {
		if e == ir.EventBlockStop || e == ir.EventMessageDelta || e == ir.EventMessageStop {
			sawSyntheticTerminal = true
		}
	}
	if sawSyntheticTerminal {
		t.Errorf("truncated stream synthesized terminal events: %v", seq)
	}
}

func TestBackendEventDecoderReadError(t *testing.T) {
	r := &errReader{data: []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\"}}\n\n")}
	dec := NewBackend().NewEventDecoder(r)
	// first event is MessageStart; a later Next hits the read error
	for range 10 {
		_, err := dec.Next()
		if err == io.EOF {
			t.Fatal("expected a read error, got clean EOF")
		}
		if err != nil {
			return // the injected read error surfaced
		}
	}
	t.Fatal("read error never surfaced")
}

func FuzzBackendDecodeResponse(f *testing.F) {
	f.Add(`{"id":"resp_x","model":"m","status":"completed","output":[]}`)
	f.Add(`{"error":{"message":"e","type":"t"}}`)
	f.Add(`{"output":[{"type":"function_call","call_id":"c","name":"n","arguments":"{}"}]}`)
	f.Fuzz(func(t *testing.T, body string) {
		_, _ = NewBackend().DecodeResponse([]byte(body)) // must not panic
	})
}

func FuzzBackendEventDecoder(f *testing.F) {
	f.Add("data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\"}}\n\n")
	f.Add("data: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n")
	f.Fuzz(func(t *testing.T, stream string) {
		dec := NewBackend().NewEventDecoder(strings.NewReader(stream))
		for range 1000 {
			if _, err := dec.Next(); err != nil {
				return // io.EOF or a decode error — both fine, just no panic
			}
		}
	})
}
