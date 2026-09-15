// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func i64(v int64) *int64     { return &v }
func f64(v float64) *float64 { return &v }

func encodeBack(t *testing.T, req *ir.Request, opts BackendOptions) map[string]any {
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

func userMsg(text string) ir.Message {
	return ir.Message{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: text}}}
}

func TestBackendName(t *testing.T) {
	if NewBackend(BackendOptions{}).Name() != DialectName {
		t.Fatal("name mismatch")
	}
}

func TestBackendEncodeRequestFull(t *testing.T) {
	req := &ir.Request{
		Model:  "claude-sonnet-5",
		System: []ir.Block{{Type: ir.BlockText, Text: "sys", CacheHint: true}},
		Messages: []ir.Message{
			userMsg("hi"),
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockText, Text: "checking"},
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t1", Name: "f", Args: json.RawMessage(`{"a":1}`)}},
			}},
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{
					ToolUseID: "t1", IsError: true,
					Blocks: []ir.Block{
						{Type: ir.BlockText, Text: "boom"},
						{Type: ir.BlockImage, Image: &ir.Image{URL: "https://x/y.png"}},
					},
				}},
			}},
		},
		Tools:         []ir.Tool{{Name: "f", Description: "d", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		ToolChoice:    &ir.ToolChoice{Mode: ir.ToolChoiceTool, Name: "f", DisableParallel: true},
		MaxTokens:     i64(2048),
		Temperature:   f64(1.4),
		TopP:          f64(0.9),
		TopK:          i64(40),
		StopSequences: []string{"END"},
		Stream:        true,
		UserID:        "u-1",
	}
	got := encodeBack(t, req, BackendOptions{})

	if got["model"] != "claude-sonnet-5" || got["max_tokens"].(float64) != 2048 || got["stream"] != true {
		t.Fatalf("scalars wrong: %v", got)
	}
	// OpenAI temperature 1.4 clamps to the Anthropic max of 1.
	if got["temperature"].(float64) != 1 || !slices.Contains(req.Loss.Fields(), "temperature") {
		t.Fatalf("temperature clamp wrong: %v loss=%v", got["temperature"], req.Loss.Fields())
	}
	if got["top_p"].(float64) != 0.9 || got["top_k"].(float64) != 40 {
		t.Fatal("top_p/top_k wrong")
	}
	sys := got["system"].([]any)[0].(map[string]any)
	if sys["text"] != "sys" || sys["cache_control"] == nil {
		t.Fatalf("system wrong: %v", sys)
	}
	msgs := got["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("want 3 messages, got %d", len(msgs))
	}
	asst := msgs[1].(map[string]any)
	tu := asst["content"].([]any)[1].(map[string]any)
	if asst["role"] != "assistant" || tu["type"] != "tool_use" ||
		!reflect.DeepEqual(tu["input"], map[string]any{"a": float64(1)}) {
		t.Fatalf("assistant wrong: %v", asst)
	}
	tr := msgs[2].(map[string]any)["content"].([]any)[0].(map[string]any)
	if tr["type"] != "tool_result" || tr["is_error"] != true ||
		len(tr["content"].([]any)) != 2 {
		t.Fatalf("tool result wrong: %v", tr)
	}
	tc := got["tool_choice"].(map[string]any)
	if tc["type"] != "tool" || tc["name"] != "f" || tc["disable_parallel_tool_use"] != true {
		t.Fatalf("tool choice wrong: %v", tc)
	}
	if got["metadata"].(map[string]any)["user_id"] != "u-1" {
		t.Fatalf("metadata wrong: %v", got["metadata"])
	}
	if !reflect.DeepEqual(got["stop_sequences"], []any{"END"}) {
		t.Fatalf("stop wrong: %v", got["stop_sequences"])
	}
}

func TestBackendEncodeDefaultMaxTokensAndSchema(t *testing.T) {
	req := &ir.Request{
		Model:    "m",
		Messages: []ir.Message{userMsg("x")},
		Schema:   &ir.ResponseSchema{Name: "out", Schema: json.RawMessage(`{"type":"object"}`)},
	}
	got := encodeBack(t, req, BackendOptions{})
	if got["max_tokens"].(float64) != 4096 {
		t.Fatalf("default max_tokens wrong: %v", got["max_tokens"])
	}
	if _, retired := got["output_format"]; retired {
		t.Fatalf("retired top-level output_format emitted: %v", got["output_format"])
	}
	of := got["output_config"].(map[string]any)["format"].(map[string]any)
	if of["type"] != "json_schema" || of["schema"] == nil {
		t.Fatalf("output_config.format wrong: %v", of)
	}

	got = encodeBack(t, &ir.Request{Model: "m", Messages: []ir.Message{userMsg("x")}},
		BackendOptions{DefaultMaxTokens: 999})
	if got["max_tokens"].(float64) != 999 {
		t.Fatalf("custom default wrong: %v", got["max_tokens"])
	}
}

// Models from Claude Opus 4.7 on reject temperature, top_p, and top_k with a
// 400. With DropSampling the body omits them and the loss report names each
// one the caller set, so a caller can still tell its sampling did not apply.
func TestBackendEncodeDropSampling(t *testing.T) {
	req := &ir.Request{
		Model:       "claude-opus-5",
		Messages:    []ir.Message{userMsg("x")},
		Temperature: f64(0.2),
		TopP:        f64(0.9),
		TopK:        i64(40),
	}
	got := encodeBack(t, req, BackendOptions{DropSampling: true})
	for _, key := range []string{"temperature", "top_p", "top_k"} {
		if _, present := got[key]; present {
			t.Fatalf("%s forwarded under DropSampling: %v", key, got[key])
		}
	}
	want := []ir.LossField{ir.LossTemperature, ir.LossTopP, ir.LossTopK}
	if fields := req.Loss.Fields(); !slices.Equal(fields, want) {
		t.Fatalf("loss = %v, want %v", fields, want)
	}

	// A caller that set nothing loses nothing.
	req = &ir.Request{Model: "claude-opus-5", Messages: []ir.Message{userMsg("x")}}
	encodeBack(t, req, BackendOptions{DropSampling: true})
	if fields := req.Loss.Fields(); len(fields) != 0 {
		t.Fatalf("unexpected loss without sampling params: %v", fields)
	}
}

func TestBackendEncodeThinkingAdaptive(t *testing.T) {
	base := func(r *ir.Reasoning) *ir.Request {
		return &ir.Request{Model: "m", MaxTokens: i64(32000), Reasoning: r,
			Messages: []ir.Message{userMsg("x")}}
	}
	// Reasoning encodes as thinking:{adaptive} + output_config.effort, never
	// the deprecated thinking:{enabled, budget_tokens} that newer Claude
	// models (opus-4.7/4.8, sonnet-5, fable-5) reject.
	assertShape := func(t *testing.T, got map[string]any, wantEffort string) {
		th, ok := got["thinking"].(map[string]any)
		if !ok || th["type"] != "adaptive" {
			t.Fatalf("thinking = %v, want {type:adaptive}", got["thinking"])
		}
		if _, has := th["budget_tokens"]; has {
			t.Fatalf("must not emit budget_tokens: %v", th)
		}
		oc, ok := got["output_config"].(map[string]any)
		if !ok || oc["effort"] != wantEffort {
			t.Fatalf("output_config = %v, want effort %q", got["output_config"], wantEffort)
		}
	}
	// Effort passes straight through (lossless — no banding).
	for effort, want := range map[ir.Effort]string{ir.EffortLow: "low", ir.EffortMedium: "medium", ir.EffortHigh: "high"} {
		req := base(&ir.Reasoning{Effort: effort})
		got := encodeBack(t, req, BackendOptions{})
		assertShape(t, got, want)
		if slices.Contains(req.Loss.Fields(), "reasoning_effort") {
			t.Fatalf("effort %s passthrough must not record a loss", effort)
		}
	}
	// minimal has no API equivalent → low, recorded as a loss.
	req := base(&ir.Reasoning{Effort: ir.EffortMinimal})
	got := encodeBack(t, req, BackendOptions{})
	assertShape(t, got, "low")
	if !slices.Contains(req.Loss.Fields(), "reasoning_effort") {
		t.Fatal("minimal→low must be a recorded loss")
	}
	// Anthropic-style budget bands to an effort and records the approximation.
	for budget, want := range map[int64]string{1500: "low", 5000: "medium", 20000: "high"} {
		req := base(&ir.Reasoning{BudgetTokens: budget})
		got := encodeBack(t, req, BackendOptions{})
		assertShape(t, got, want)
		if !slices.Contains(req.Loss.Fields(), "thinking.budget_tokens") {
			t.Fatalf("budget %d banding must record a loss", budget)
		}
	}
	// Reasoning enabled with neither effort nor budget defaults to high.
	assertShape(t, encodeBack(t, base(&ir.Reasoning{}), BackendOptions{}), "high")
}

func TestBackendEncodeThinkingReplayPolicy(t *testing.T) {
	req := &ir.Request{
		Model: "m",
		Messages: []ir.Message{{Role: ir.RoleAssistant, Blocks: []ir.Block{
			{Type: ir.BlockThinking, Text: "signed", Signature: "sig1"},
			{Type: ir.BlockThinking, Text: "synth"}, // no signature: dropped
			{Type: ir.BlockRedactedThinking, Redacted: "xx"},
			{Type: ir.BlockText, Text: "ok"},
		}}},
	}
	got := encodeBack(t, req, BackendOptions{})
	content := got["messages"].([]any)[0].(map[string]any)["content"].([]any)
	if len(content) != 3 {
		t.Fatalf("want signed thinking + redacted + text, got %v", content)
	}
	first := content[0].(map[string]any)
	if first["type"] != "thinking" || first["signature"] != "sig1" {
		t.Fatalf("signed thinking wrong: %v", first)
	}
	if !slices.Contains(req.Loss.Fields(), "thinking") {
		t.Fatalf("unsigned thinking drop must be a loss: %v", req.Loss.Fields())
	}
}

func TestBackendEncodeErrors(t *testing.T) {
	bad := []ir.Request{
		{Model: "m", Messages: []ir.Message{{Role: ir.RoleAssistant, Blocks: []ir.Block{
			{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{}}}}}},
		{Model: "m", ToolChoice: &ir.ToolChoice{Mode: "weird"}, Messages: []ir.Message{userMsg("x")}},
	}
	for i := range bad {
		if _, err := NewBackend(BackendOptions{}).EncodeRequest(&bad[i]); err == nil {
			t.Fatalf("case %d: want error", i)
		}
	}
}

func TestBackendDecodeResponse(t *testing.T) {
	body := `{
		"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5",
		"content": [
			{"type": "thinking", "thinking": "hm", "signature": "s1"},
			{"type": "text", "text": "hi"},
			{"type": "tool_use", "id": "t1", "name": "f", "input": {"a": 1}}
		],
		"stop_reason": "tool_use", "stop_sequence": null,
		"usage": {"input_tokens": 10, "output_tokens": 4, "cache_read_input_tokens": 6, "cache_creation_input_tokens": 2}
	}`
	resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != "msg_1" || resp.StopReason != ir.StopToolUse {
		t.Fatalf("envelope wrong: %+v", resp)
	}
	if resp.Blocks[0].Type != ir.BlockThinking || resp.Blocks[0].Signature != "s1" {
		t.Fatalf("thinking wrong: %+v", resp.Blocks[0])
	}
	want := ir.Usage{InputTokens: 10, OutputTokens: 4, CacheReadInputTokens: i64(6), CacheWriteInputTokens: i64(2)}
	if !reflect.DeepEqual(resp.Usage, want) {
		t.Fatalf("usage = %+v want %+v", resp.Usage, want)
	}
}

// TestBackendDecodeUsageCacheReporting pins the nil/zero distinction on
// both cache counts: a usage that omits a member, or writes it null,
// decodes to nil for it; one that carries it decodes to the count, zero
// included. On the stream, a count message_delta carries fills one
// message_start did not, a zero there never erases a count already
// reported, and a nonzero one replaces it.
func TestBackendDecodeUsageCacheReporting(t *testing.T) {
	cases := []struct {
		name, usage string
		want        ir.Usage
	}{
		{"neither", `{"input_tokens":10,"output_tokens":1}`, ir.Usage{InputTokens: 10, OutputTokens: 1}},
		{"null", `{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":null,"cache_creation_input_tokens":null}`, ir.Usage{InputTokens: 10, OutputTokens: 1}},
		{"zeros", `{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}`,
			ir.Usage{InputTokens: 10, OutputTokens: 1, CacheReadInputTokens: i64(0), CacheWriteInputTokens: i64(0)}},
		{"read only", `{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":4}`,
			ir.Usage{InputTokens: 10, OutputTokens: 1, CacheReadInputTokens: i64(4)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(
				`{"id":"m","type":"message","content":[{"type":"text","text":"x"}],"usage":` + tc.usage + `}`))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(resp.Usage, tc.want) {
				t.Fatalf("usage = %+v want %+v", resp.Usage, tc.want)
			}
		})
	}

	streamCases := []struct {
		name, start, delta string
		want               ir.Usage
	}{
		{"start without, delta without", `{"input_tokens":9}`, `{"output_tokens":5}`,
			ir.Usage{InputTokens: 9, OutputTokens: 5}},
		{"start without, delta reports zero", `{"input_tokens":9}`, `{"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}`,
			ir.Usage{InputTokens: 9, OutputTokens: 5, CacheReadInputTokens: i64(0), CacheWriteInputTokens: i64(0)}},
		{"start reports, delta zero keeps it", `{"input_tokens":9,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}`, `{"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}`,
			ir.Usage{InputTokens: 9, OutputTokens: 5, CacheReadInputTokens: i64(3), CacheWriteInputTokens: i64(2)}},
		{"delta replaces with a count", `{"input_tokens":9,"cache_read_input_tokens":3}`, `{"output_tokens":5,"cache_read_input_tokens":7,"cache_creation_input_tokens":4}`,
			ir.Usage{InputTokens: 9, OutputTokens: 5, CacheReadInputTokens: i64(7), CacheWriteInputTokens: i64(4)}},
	}
	for _, tc := range streamCases {
		t.Run(tc.name, func(t *testing.T) {
			events := drainBackend(t, anthropicSSE(
				[2]string{"message_start", `{"type":"message_start","message":{"id":"m","model":"c","usage":` + tc.start + `}}`},
				[2]string{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":` + tc.delta + `}`},
				[2]string{"message_stop", `{"type":"message_stop"}`},
			))
			md := events[len(events)-2]
			if md.Type != ir.EventMessageDelta || md.Usage == nil || !reflect.DeepEqual(*md.Usage, tc.want) {
				t.Fatalf("message_delta usage = %+v want %+v", md.Usage, tc.want)
			}
		})
	}
}

// jsonHasKey reports whether any object in raw has a member whose name
// folds to key, which is how encoding/json matches a member, so the
// fuzz invariant asks the question the decoder answers.
func jsonHasKey(raw []byte, key string) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	for k, v := range obj {
		if strings.EqualFold(k, key) || jsonHasKey(v, key) {
			return true
		}
	}
	return false
}

// FuzzBackendUsageDecode holds each cache count to its own wire member
// under any usage object: set only when the member appeared, and the
// buffered decode agrees with a stream whose message_start carried the
// same object.
func FuzzBackendUsageDecode(f *testing.F) {
	f.Add([]byte(`{"input_tokens":10,"output_tokens":1}`))
	f.Add([]byte(`{"input_tokens":10,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}`))
	f.Add([]byte(`{"input_tokens":10,"cache_read_input_tokens":null}`))
	f.Add([]byte(`{"cache_creation_input_tokens":5,"output_tokens_details":{"thinking_tokens":2}}`))
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, usage []byte) {
		resp, err := NewBackend(BackendOptions{}).DecodeResponse(
			append(append([]byte(`{"id":"m","type":"message","content":[],"usage":`), usage...), '}'))
		if err != nil {
			return
		}
		u := resp.Usage
		if u.CacheReadInputTokens != nil && !jsonHasKey(usage, "cache_read_input_tokens") {
			t.Fatalf("cache read %d reported by %s", *u.CacheReadInputTokens, usage)
		}
		if u.CacheWriteInputTokens != nil && !jsonHasKey(usage, "cache_creation_input_tokens") {
			t.Fatalf("cache write %d reported by %s", *u.CacheWriteInputTokens, usage)
		}
		if bytes.ContainsAny(usage, "\r\n") {
			return // a line break splits the SSE data line; not a usage question
		}
		dec := NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader(anthropicSSE(
			[2]string{"message_start", `{"type":"message_start","message":{"id":"m","model":"c","usage":` + string(usage) + `}}`},
			[2]string{"message_stop", `{"type":"message_stop"}`},
		)))
		start, err := dec.Next()
		if err != nil {
			t.Fatal(err)
		}
		if start.Usage == nil || !reflect.DeepEqual(*start.Usage, u) {
			t.Fatalf("message_start usage %+v, buffered %+v", start.Usage, u)
		}
	})
}

func TestBackendDecodeResponseErrors(t *testing.T) {
	if _, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(`{`)); err == nil {
		t.Fatal("want JSON error")
	}
	_, err := NewBackend(BackendOptions{}).DecodeResponse(
		[]byte(`{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`))
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("want upstream error, got %v", err)
	}
}

func anthropicSSE(events ...[2]string) string {
	var b strings.Builder
	for _, ev := range events {
		b.WriteString("event: " + ev[0] + "\ndata: " + ev[1] + "\n\n")
	}
	return b.String()
}

func drainBackend(t *testing.T, stream string) []ir.Event {
	t.Helper()
	dec := NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader(stream))
	var out []ir.Event
	for {
		ev, err := dec.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
}

func TestBackendEventDecoderSequence(t *testing.T) {
	stream := anthropicSSE(
		[2]string{"message_start", `{"type":"message_start","message":{"id":"msg_1","model":"claude","usage":{"input_tokens":9,"output_tokens":0,"cache_read_input_tokens":3}}}`},
		[2]string{"ping", `{"type":"ping"}`},
		[2]string{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hm"}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"s1"}}`},
		[2]string{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		[2]string{"content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"f","input":{}}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":1}"}}`},
		[2]string{"content_block_stop", `{"type":"content_block_stop","index":1}`},
		[2]string{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":5}}`},
		[2]string{"message_stop", `{"type":"message_stop"}`},
	)
	events := drainBackend(t, stream)
	var types []ir.EventType
	for _, ev := range events {
		types = append(types, ev.Type)
	}
	want := []ir.EventType{
		ir.EventMessageStart,
		ir.EventBlockStart, ir.EventThinkingDelta, ir.EventSignatureDelta, ir.EventBlockStop,
		ir.EventBlockStart, ir.EventArgsDelta, ir.EventBlockStop,
		ir.EventMessageDelta, ir.EventMessageStop,
	}
	if !reflect.DeepEqual(types, want) {
		t.Fatalf("event types = %v\nwant %v", types, want)
	}
	start := events[0]
	if start.ID != "msg_1" || start.Usage.InputTokens != 9 || start.Usage.CacheReadInputTokens == nil || *start.Usage.CacheReadInputTokens != 3 {
		t.Fatalf("message start wrong: %+v", start)
	}
	if events[5].Block.ToolUse.ID != "t1" || events[5].Block.ToolUse.Name != "f" {
		t.Fatalf("tool block wrong: %+v", events[5].Block)
	}
	md := events[8]
	// Input tokens from message_start merge with output from message_delta.
	if md.StopReason != ir.StopToolUse || md.Usage.InputTokens != 9 || md.Usage.OutputTokens != 5 {
		t.Fatalf("message delta wrong: %+v", md)
	}
}

func TestBackendEventDecoderEarlyCloseAndErrors(t *testing.T) {
	// Early close still yields a well-formed tail.
	events := drainBackend(t, anthropicSSE(
		[2]string{"message_start", `{"type":"message_start","message":{"id":"m","model":"c","usage":{"input_tokens":1}}}`},
	))
	if events[len(events)-1].Type != ir.EventMessageStop {
		t.Fatalf("tail missing: %+v", events)
	}

	dec := NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader(
		anthropicSSE([2]string{"error", `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`})))
	if _, err := dec.Next(); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("want stream error, got %v", err)
	}

	dec = NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader("event: message_start\ndata: {nope\n\n"))
	if _, err := dec.Next(); err == nil {
		t.Fatal("want parse error")
	}
}

func FuzzBackendDecodeResponse(f *testing.F) {
	f.Add([]byte(`{"id":"m","content":[{"type":"text","text":"x"}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = NewBackend(BackendOptions{}).DecodeResponse(body) // must not panic
	})
}

// Anthropic reports thinking under output_tokens_details.thinking_tokens.
// Without carrying it into ir.Usage.ReasoningTokens, a Responses-dialect
// caller (codex) sees reasoning_tokens: 0 for every Anthropic model even
// when the model thought, and cannot tell "effort ignored" from "effort
// applied".
func TestDecodeResponseCarriesThinkingTokensAsReasoning(t *testing.T) {
	t.Parallel()
	body := []byte(`{"type":"message","id":"msg_1","model":"claude-fable-5-1","role":"assistant",
		"content":[{"type":"thinking","thinking":"...","signature":"sig"},{"type":"text","text":"390"}],
		"stop_reason":"end_turn",
		"usage":{"input_tokens":31,"output_tokens":180,"cache_read_input_tokens":0,
		         "cache_creation_input_tokens":0,"output_tokens_details":{"thinking_tokens":51}}}`)
	resp, err := (&Backend{}).DecodeResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Usage.ReasoningTokens != 51 {
		t.Fatalf("ReasoningTokens = %d, want 51", resp.Usage.ReasoningTokens)
	}
	if resp.Usage.OutputTokens != 180 {
		t.Fatalf("OutputTokens = %d, want 180 (thinking is included, not added)", resp.Usage.OutputTokens)
	}
	// A response with no details block, the pre-thinking shape, still parses.
	resp, err = (&Backend{}).DecodeResponse([]byte(`{"type":"message","id":"m","model":"x","role":"assistant",
		"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn",
		"usage":{"input_tokens":1,"output_tokens":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Usage.ReasoningTokens != 0 {
		t.Fatalf("ReasoningTokens = %d, want 0 without details", resp.Usage.ReasoningTokens)
	}
}
