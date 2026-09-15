// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package lux

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func i64(v int64) *int64           { return &v }
func f64(v float64) *float64       { return &v }
func raw(s string) json.RawMessage { return json.RawMessage(s) }

// richIRRequest exercises every representable request field.
func richIRRequest() *ir.Request {
	return &ir.Request{
		Model: "claude-sonnet-5",
		System: []ir.Block{
			{Type: ir.BlockText, Text: "You are helpful", CacheHint: true},
		},
		Messages: []ir.Message{
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockText, Text: "look at this"},
				{Type: ir.BlockImage, Image: &ir.Image{MediaType: "image/png", Data: "aGk="}},
			}},
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockThinking, Text: "hmm", Signature: "sig1"},
				{Type: ir.BlockRedactedThinking, Redacted: "opaque"},
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "tu_1", Name: "bash", Args: raw(`{"cmd":"ls"}`)}},
			}},
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{
					ToolUseID: "tu_1",
					Blocks: []ir.Block{
						{Type: ir.BlockText, Text: "a.txt"},
						{Type: ir.BlockImage, Image: &ir.Image{URL: "https://x/y.png"}},
					},
					IsError: true,
				}},
			}},
		},
		Tools: []ir.Tool{
			{Name: "bash", Description: "run", InputSchema: raw(`{"type":"object"}`)},
		},
		ToolChoice:    &ir.ToolChoice{Mode: ir.ToolChoiceTool, Name: "bash", DisableParallel: true},
		MaxTokens:     i64(4096),
		Temperature:   f64(0.7),
		TopP:          f64(0.9),
		TopK:          i64(40),
		StopSequences: []string{"STOP"},
		Stream:        true,
		Reasoning:     &ir.Reasoning{BudgetTokens: 2048},
		Schema:        &ir.ResponseSchema{Name: "out", Description: "d", Schema: raw(`{"type":"object"}`), Strict: true},
		UserID:        "u-1",
		CacheKey:      "prefix-7",
	}
}

// TestRequestRoundTrip: IR → lux wire → IR is the identity, with an
// empty loss report — the frontend leg is lossless by construction.
func TestRequestRoundTrip(t *testing.T) {
	want := richIRRequest()
	body, err := NewBackend().EncodeRequest(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewFrontend().DecodeRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if losses := got.Loss.Strings(); losses != nil {
		t.Fatalf("frontend leg lost fields: %v", losses)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\ngot  %#v\nwant %#v", got, want)
	}
}

func TestDecodeRequestGolden(t *testing.T) {
	in := `{
		"model": "claude-sonnet-5",
		"system": [{"type": "text", "text": "sys", "cache_hint": true}],
		"messages": [{"role": "user", "blocks": [{"type": "text", "text": "hi"}]}],
		"reasoning": {"effort": "high"},
		"max_tokens": 128,
		"stream": true,
		"cache_key": "prefix-7"
	}`
	req, err := NewFrontend().DecodeRequest([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if req.Model != "claude-sonnet-5" || !req.Stream || *req.MaxTokens != 128 {
		t.Fatalf("bad decode: %#v", req)
	}
	// The key is carried verbatim and never derived from cache_hint, so a
	// lux caller's own key survives and a caller that set none has none.
	if req.CacheKey != "prefix-7" {
		t.Fatalf("bad cache_key: %q", req.CacheKey)
	}
	if got := req.Loss.Strings(); got != nil {
		t.Fatalf("cache_key reported as loss: %v", got)
	}
	if len(req.System) != 1 || req.System[0].Text != "sys" || !req.System[0].CacheHint {
		t.Fatalf("bad system: %#v", req.System)
	}
	if req.Reasoning == nil || req.Reasoning.Effort != ir.EffortHigh {
		t.Fatalf("bad reasoning: %#v", req.Reasoning)
	}
	if req.Messages[0].Role != ir.RoleUser || req.Messages[0].Blocks[0].Text != "hi" {
		t.Fatalf("bad message: %#v", req.Messages)
	}
}

func TestDecodeRequestLoss(t *testing.T) {
	in := `{
		"model": "m",
		"mystery_knob": 1,
		"system": [{"type": "text", "text": "a"}, {"type": "widget", "text": "b"}],
		"messages": [{"role": "user", "blocks": [
			{"type": "text", "text": "hi"},
			{"type": "hologram"}
		]}]
	}`
	req, err := NewFrontend().DecodeRequest([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	got := req.Loss.Strings()
	want := map[string]bool{"mystery_knob": true, "system.widget": true, "content.hologram": true}
	if len(got) != len(want) {
		t.Fatalf("loss = %v, want keys %v", got, want)
	}
	for _, f := range got {
		if !want[f] {
			t.Fatalf("unexpected loss field %q in %v", f, got)
		}
	}
	if len(req.System) != 1 || len(req.Messages[0].Blocks) != 1 {
		t.Fatalf("lossy blocks should be skipped: %#v", req)
	}
}

// TestDecodeRequestServerToolsAndWebSearchAreNotLoss: both fields are
// decoded, so a request carrying them reports no loss.
func TestDecodeRequestServerToolsAndWebSearchAreNotLoss(t *testing.T) {
	in := `{
		"model": "m",
		"messages": [{"role": "user", "blocks": [{"type": "text", "text": "hi"}]}],
		"server_tools": [{"type": "web_search_20250305", "name": "web_search", "config": {"max_uses": 3}}],
		"web_search": {"context_size": "medium", "user_location": {"type": "approximate", "city": "Munich"}}
	}`
	req, err := NewFrontend().DecodeRequest([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if losses := req.Loss.Strings(); losses != nil {
		t.Fatalf("a request with server_tools and web_search reported loss %v", losses)
	}
	if len(req.ServerTools) != 1 || req.ServerTools[0].Type != "web_search_20250305" || req.ServerTools[0].Name != "web_search" || string(req.ServerTools[0].Config) != `{"max_uses": 3}` {
		t.Fatalf("server_tools = %+v", req.ServerTools)
	}
	if req.WebSearch == nil || req.WebSearch.ContextSize != "medium" || string(req.WebSearch.UserLocation) != `{"type": "approximate", "city": "Munich"}` {
		t.Fatalf("web_search = %+v", req.WebSearch)
	}
	// Every field Request declares is a key the decoder names, so the two
	// cannot drift apart again.
	var wire map[string]json.RawMessage
	raw, _ := json.Marshal(Request{})
	_ = json.Unmarshal(raw, &wire)
	for k := range wire {
		if !requestKeys[k] {
			t.Errorf("Request declares %q and requestKeys does not name it", k)
		}
	}
}

func TestDecodeRequestErrors(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"invalid json", `{`},
		{"malformed shape", `{"model": "m", "messages": "nope"}`},
		{"missing model", `{"messages": [{"role": "user", "blocks": [{"type": "text"}]}]}`},
		{"missing messages", `{"model": "m"}`},
		{"bad role", `{"model": "m", "messages": [{"role": "wizard", "blocks": [{"type": "text"}]}]}`},
		{"empty blocks", `{"model": "m", "messages": [{"role": "user", "blocks": []}]}`},
		{"bad tool_choice", `{"model": "m", "tool_choice": {"mode": "maybe"}, "messages": [{"role": "user", "blocks": [{"type": "text"}]}]}`},
		{"tool mode without name", `{"model": "m", "tool_choice": {"mode": "tool"}, "messages": [{"role": "user", "blocks": [{"type": "text"}]}]}`},
		{"reasoning both", `{"model": "m", "reasoning": {"effort": "low", "budget_tokens": 1}, "messages": [{"role": "user", "blocks": [{"type": "text"}]}]}`},
		{"image missing payload", `{"model": "m", "messages": [{"role": "user", "blocks": [{"type": "image"}]}]}`},
		{"image empty source", `{"model": "m", "messages": [{"role": "user", "blocks": [{"type": "image", "image": {}}]}]}`},
		{"tool_use missing payload", `{"model": "m", "messages": [{"role": "assistant", "blocks": [{"type": "tool_use"}]}]}`},
		{"tool_result missing payload", `{"model": "m", "messages": [{"role": "user", "blocks": [{"type": "tool_result"}]}]}`},
		{"tool_result bad inner", `{"model": "m", "messages": [{"role": "user", "blocks": [{"type": "tool_result", "tool_result": {"tool_use_id": "t", "blocks": [{"type": "image"}]}}]}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewFrontend().DecodeRequest([]byte(tc.in)); err == nil {
				t.Fatalf("want error for %s", tc.name)
			}
		})
	}
}

func TestToolChoiceModes(t *testing.T) {
	for _, mode := range []ir.ToolChoiceMode{ir.ToolChoiceAuto, ir.ToolChoiceAny, ir.ToolChoiceNone} {
		in := `{"model": "m", "tool_choice": {"mode": "` + string(mode) + `"}, "messages": [{"role": "user", "blocks": [{"type": "text", "text": "x"}]}]}`
		req, err := NewFrontend().DecodeRequest([]byte(in))
		if err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
		if req.ToolChoice.Mode != mode {
			t.Fatalf("mode %s: got %s", mode, req.ToolChoice.Mode)
		}
	}
}

func TestEncodeResponse(t *testing.T) {
	body, err := NewFrontend().EncodeResponse(&ir.Response{
		ID:    "msg_1",
		Model: "m",
		Blocks: []ir.Block{
			{Type: ir.BlockText, Text: "hello"},
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "tu_1", Name: "bash", Args: raw(`{}`)}},
		},
		StopReason:   ir.StopToolUse,
		StopSequence: "S",
		Usage:        ir.Usage{InputTokens: 10, OutputTokens: 5, CacheReadInputTokens: i64(3), CacheWriteInputTokens: i64(2), ReasoningTokens: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire Response
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.ID != "msg_1" || wire.StopReason != ir.StopToolUse || wire.StopSequence != "S" {
		t.Fatalf("bad response: %s", body)
	}
	if wire.Usage.InputTokens != 10 || wire.Usage.ReasoningTokens != 1 {
		t.Fatalf("bad usage: %+v", wire.Usage)
	}
	if len(wire.Blocks) != 2 || wire.Blocks[1].ToolUse.Name != "bash" {
		t.Fatalf("bad blocks: %s", body)
	}
}

func TestEncodeResponseDefaultsStopReason(t *testing.T) {
	body, err := NewFrontend().EncodeResponse(&ir.Response{ID: "m1", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"stop_reason":"end_turn"`) {
		t.Fatalf("missing default stop_reason: %s", body)
	}
}

func TestEncodeResponseBadBlock(t *testing.T) {
	cases := []ir.Block{
		{Type: ir.BlockType("weird")},
		{Type: ir.BlockImage},
		{Type: ir.BlockToolUse},
		{Type: ir.BlockToolResult},
		{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{Blocks: []ir.Block{{Type: ir.BlockImage}}}},
	}
	for _, b := range cases {
		if _, err := NewFrontend().EncodeResponse(&ir.Response{Blocks: []ir.Block{b}}); err == nil {
			t.Fatalf("want error for block %#v", b)
		}
	}
}

func TestResponseRoundTrip(t *testing.T) {
	want := &ir.Response{
		ID:    "msg_2",
		Model: "m",
		Blocks: []ir.Block{
			{Type: ir.BlockText, Text: "t"},
			{Type: ir.BlockThinking, Text: "th", Signature: "sig"},
			{Type: ir.BlockRedactedThinking, Redacted: "r"},
			{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: "tu", Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}},
		},
		StopReason: ir.StopEndTurn,
		Usage:      ir.Usage{InputTokens: 1, OutputTokens: 2},
	}
	body, err := NewFrontend().EncodeResponse(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewBackend().DecodeResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\ngot  %#v\nwant %#v", got, want)
	}
}

func TestDecodeResponseErrors(t *testing.T) {
	if _, err := NewBackend().DecodeResponse([]byte(`{`)); err == nil {
		t.Fatal("want error for invalid JSON")
	}
	if _, err := NewBackend().DecodeResponse([]byte(`{"blocks": [{"type": "image"}]}`)); err == nil {
		t.Fatal("want error for bad block")
	}
}

func TestDecodeResponseSkipsUnknownBlocks(t *testing.T) {
	got, err := NewBackend().DecodeResponse([]byte(`{"id":"x","blocks":[{"type":"widget"},{"type":"text","text":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Blocks) != 1 || got.Blocks[0].Text != "hi" {
		t.Fatalf("bad blocks: %#v", got.Blocks)
	}
}

func streamEvents() []ir.Event {
	inTok := &ir.Usage{InputTokens: 12}
	full := &ir.Usage{InputTokens: 12, OutputTokens: 34, CacheReadInputTokens: i64(5), CacheWriteInputTokens: i64(0), ReasoningTokens: 6}
	return []ir.Event{
		{Type: ir.EventMessageStart, ID: "msg_1", Model: "m", Usage: inTok},
		{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockText}},
		{Type: ir.EventTextDelta, Index: 0, Delta: "Hel"},
		{Type: ir.EventTextDelta, Index: 0, Delta: "lo"},
		{Type: ir.EventBlockStop, Index: 0},
		{Type: ir.EventBlockStart, Index: 1, Block: &ir.Block{Type: ir.BlockThinking}},
		{Type: ir.EventThinkingDelta, Index: 1, Delta: "hmm"},
		{Type: ir.EventSignatureDelta, Index: 1, Delta: "sig"},
		{Type: ir.EventBlockStop, Index: 1},
		{Type: ir.EventBlockStart, Index: 2, Block: &ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "tu_1", Name: "bash"}}},
		{Type: ir.EventArgsDelta, Index: 2, Delta: `{"cmd":`},
		{Type: ir.EventArgsDelta, Index: 2, Delta: `"ls"}`},
		{Type: ir.EventBlockStop, Index: 2},
		{Type: ir.EventMessageDelta, StopReason: ir.StopToolUse, StopSequence: "S", Usage: full},
		{Type: ir.EventMessageStop},
	}
}

// TestStreamRoundTrip: IR events → lux SSE → IR events is the
// identity, so the lux stream carries the full canonical grammar.
func TestStreamRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	want := streamEvents()
	for _, ev := range want {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	dec := NewBackend().NewEventDecoder(&buf)
	var got []ir.Event
	for {
		ev, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ev)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stream round trip mismatch:\ngot  %#v\nwant %#v", got, want)
	}
}

func TestStreamWireFraming(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	if err := enc.Encode(ir.Event{Type: ir.EventTextDelta, Index: 0, Delta: "hi"}); err != nil {
		t.Fatal(err)
	}
	want := "event: text_delta\ndata: {\"type\":\"text_delta\",\"index\":0,\"delta\":\"hi\"}\n\n"
	if buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}
}

func TestStreamReaderErrorFrame(t *testing.T) {
	in := "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}\n\n"
	_, err := NewStreamReader(strings.NewReader(in)).Next()
	var se *StreamError
	if !errors.As(err, &se) {
		t.Fatalf("want StreamError, got %v", err)
	}
	if se.Code != "overloaded_error" || se.Message != "busy" {
		t.Fatalf("bad stream error: %+v", se)
	}
	if !strings.Contains(se.Error(), "overloaded_error") || !strings.Contains(se.Error(), "busy") {
		t.Fatalf("bad error string: %s", se.Error())
	}
}

func TestStreamReaderOpaqueErrorFrame(t *testing.T) {
	in := "event: error\ndata: upstream exploded\n\n"
	_, err := NewStreamReader(strings.NewReader(in)).Next()
	var se *StreamError
	if !errors.As(err, &se) {
		t.Fatalf("want StreamError, got %v", err)
	}
	if se.Code != "" || se.Message != "upstream exploded" {
		t.Fatalf("bad stream error: %+v", se)
	}
	if !strings.Contains(se.Error(), "upstream exploded") {
		t.Fatalf("bad error string: %s", se.Error())
	}
}

// TestEventDecoderTruncatedStream pins that a stream cut off before
// message_stop is reported as io.ErrUnexpectedEOF, not the clean io.EOF that
// signals a complete message. A caller cannot otherwise tell a finished
// response from a dropped connection.
func TestEventDecoderTruncatedStream(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	truncated := []ir.Event{
		{Type: ir.EventMessageStart, ID: "msg_1", Model: "m"},
		{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockText}},
		{Type: ir.EventTextDelta, Index: 0, Delta: "Hel"},
	}
	for _, ev := range truncated {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	dec := NewBackend().NewEventDecoder(&buf)
	var last []string
	for {
		ev, err := dec.Next()
		if err != nil {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated stream (last event %v) reported as %v; want io.ErrUnexpectedEOF", last, err)
			}
			break
		}
		last = append(last, string(ev.Type))
	}
}

// TestEventDecoderCompleteStreamEOF pins the other half: once message_stop
// has been delivered, end of stream is the clean io.EOF.
func TestEventDecoderCompleteStreamEOF(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	if err := enc.Encode(ir.Event{Type: ir.EventMessageStop}); err != nil {
		t.Fatal(err)
	}
	dec := NewBackend().NewEventDecoder(&buf)
	if _, err := dec.Next(); err != nil {
		t.Fatalf("message_stop: %v", err)
	}
	if _, err := dec.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("after message_stop: got %v, want io.EOF", err)
	}
}

func TestStreamReaderSkipsUnknownFrames(t *testing.T) {
	in := "event: ping\ndata: {}\n\n" +
		"data: [DONE]\n\n" +
		"event: text_delta\ndata: {\"index\":0,\"delta\":\"hi\"}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	r := NewStreamReader(strings.NewReader(in))
	ev, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	// The type field is filled from the frame name when absent.
	if ev.Type != ir.EventTextDelta || ev.Delta != "hi" {
		t.Fatalf("bad event: %#v", ev)
	}
	stop, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if stop.Type != ir.EventMessageStop {
		t.Fatalf("bad event: %#v", stop)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestStreamReaderMalformedEvent(t *testing.T) {
	in := "event: text_delta\ndata: not-json\n\n"
	if _, err := NewStreamReader(strings.NewReader(in)).Next(); err == nil {
		t.Fatal("want error for malformed event JSON")
	}
}

func TestEventDecoderRejectsMismatchedType(t *testing.T) {
	// Frame name is valid but the body claims an unknown type.
	in := "event: text_delta\ndata: {\"type\":\"bogus\"}\n\n"
	if _, err := NewBackend().NewEventDecoder(strings.NewReader(in)).Next(); err == nil {
		t.Fatal("want error for mismatched event type")
	}
}

func TestEventDecoderBadBlock(t *testing.T) {
	in := "event: block_start\ndata: {\"type\":\"block_start\",\"index\":0,\"block\":{\"type\":\"image\"}}\n\n"
	if _, err := NewBackend().NewEventDecoder(strings.NewReader(in)).Next(); err == nil {
		t.Fatal("want error for bad block payload")
	}
}

func TestEventDecoderSkipsUnknownBlockType(t *testing.T) {
	in := "event: block_start\ndata: {\"type\":\"block_start\",\"index\":0,\"block\":{\"type\":\"widget\"}}\n\n"
	ev, err := NewBackend().NewEventDecoder(strings.NewReader(in)).Next()
	if err != nil {
		t.Fatal(err)
	}
	if ev.Block != nil {
		t.Fatalf("unknown block type should be dropped, got %#v", ev.Block)
	}
}

func TestEncoderRejectsUnknownEventType(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	if err := enc.Encode(ir.Event{Type: ir.EventType("bogus")}); err == nil {
		t.Fatal("want error for unknown event type")
	}
}

func TestEncoderRejectsBadBlock(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	ev := ir.Event{Type: ir.EventBlockStart, Block: &ir.Block{Type: ir.BlockToolUse}}
	if err := enc.Encode(ev); err == nil {
		t.Fatal("want error for bad block payload")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("sink closed") }

func TestEncoderPropagatesWriteError(t *testing.T) {
	enc := NewFrontend().NewEventEncoder(failWriter{})
	if err := enc.Encode(ir.Event{Type: ir.EventMessageStop}); err == nil {
		t.Fatal("want write error")
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("pipe broke") }

func TestStreamReaderPropagatesReadError(t *testing.T) {
	if _, err := NewStreamReader(failReader{}).Next(); err == nil {
		t.Fatal("want read error")
	}
}

func TestBackendEncodeRequestBadBlocks(t *testing.T) {
	bad := []*ir.Request{
		{Model: "m", System: []ir.Block{{Type: ir.BlockImage}}},
		{Model: "m", Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockToolUse}}}}},
	}
	for _, req := range bad {
		if _, err := NewBackend().EncodeRequest(req); err == nil {
			t.Fatalf("want error for %#v", req)
		}
	}
}

func TestNames(t *testing.T) {
	if NewFrontend().Name() != ir.DialectLux || NewBackend().Name() != ir.DialectLux {
		t.Fatal("dialect name mismatch")
	}
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","blocks":[{"type":"text","text":"hi"}]}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","blocks":[{"type":"tool_result","tool_result":{"tool_use_id":"t"}}]}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","blocks":[{"type":"text","text":"hi"}]}],` +
		`"logprobs":true,"top_logprobs":2}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := NewFrontend().DecodeRequest(body)
		if err == nil && req.Model == "" {
			t.Fatal("nil error must imply a model")
		}
	})
}

// TestDecodeResponseCostUSDMicro pins the gateway-reported cost on the
// decode path against literal wire bytes, so the JSON name is part of
// the contract and not merely symmetric with the encoder. The nil vs
// zero distinction is the point: a consumer that fails closed on an
// unknown cost must not read an unreported cost as free.
func TestDecodeResponseCostUSDMicro(t *testing.T) {
	cases := []struct {
		name string
		body string
		want *int64
	}{
		{"absent", `{"id":"x","usage":{"input_tokens":1,"output_tokens":2}}`, nil},
		{"reported", `{"id":"x","usage":{"input_tokens":1,"output_tokens":2,"cost_usd_micro":1200}}`, i64(1200)},
		{"explicit zero", `{"id":"x","usage":{"input_tokens":1,"cost_usd_micro":0}}`, i64(0)},
		{"unpriced sentinel", `{"id":"x","usage":{"input_tokens":1,"cost_usd_micro":-1}}`, i64(-1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewBackend().DecodeResponse([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.want == nil && got.Usage.CostUSDMicro != nil:
				t.Fatalf("CostUSDMicro = %d, want nil (unreported cost is unknown, not zero)", *got.Usage.CostUSDMicro)
			case tc.want != nil && got.Usage.CostUSDMicro == nil:
				t.Fatalf("CostUSDMicro = nil, want %d", *tc.want)
			case tc.want != nil && *got.Usage.CostUSDMicro != *tc.want:
				t.Fatalf("CostUSDMicro = %d, want %d", *got.Usage.CostUSDMicro, *tc.want)
			}
		})
	}
}

// TestEncodeResponseCostUSDMicro pins the encoded wire name and the
// omission rule: nil writes no key at all, an explicit zero writes the
// key with 0.
func TestEncodeResponseCostUSDMicro(t *testing.T) {
	body, err := NewFrontend().EncodeResponse(&ir.Response{
		ID:    "msg_1",
		Model: "m",
		Usage: ir.Usage{InputTokens: 1, CostUSDMicro: i64(0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"cost_usd_micro":0`) {
		t.Fatalf("zero cost must be encoded: %s", body)
	}
	body, err = NewFrontend().EncodeResponse(&ir.Response{ID: "msg_1", Model: "m", Usage: ir.Usage{InputTokens: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "cost_usd_micro") {
		t.Fatalf("unreported cost must be omitted: %s", body)
	}
}

// TestStreamUsageCostUSDMicro pins the same carriage on the streaming
// path, where usage rides on message_delta.
func TestStreamUsageCostUSDMicro(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	ev := ir.Event{Type: ir.EventMessageDelta, StopReason: ir.StopEndTurn, Usage: &ir.Usage{OutputTokens: 7, CostUSDMicro: i64(4343)}}
	if err := enc.Encode(ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"cost_usd_micro":4343`) {
		t.Fatalf("frame missing cost: %s", buf.String())
	}
	in := "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7,\"cost_usd_micro\":4343}}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n"
	r := NewStreamReader(strings.NewReader(in))
	withCost, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if withCost.Usage == nil || withCost.Usage.CostUSDMicro == nil || *withCost.Usage.CostUSDMicro != 4343 {
		t.Fatalf("bad usage: %#v", withCost.Usage)
	}
	without, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if without.Usage == nil || without.Usage.CostUSDMicro != nil {
		t.Fatalf("absent cost must decode to nil, got %#v", without.Usage)
	}
}

// TestUsageCostUSDMicroNotAliased pins that the pointer does not alias
// across the wire/IR boundary, so a caller mutating one usage value
// cannot change the other.
func TestUsageCostUSDMicroNotAliased(t *testing.T) {
	wire := Usage{CostUSDMicro: i64(50)}
	got := usageToIR(wire)
	*got.CostUSDMicro = 99
	if *wire.CostUSDMicro != 50 {
		t.Fatalf("usageToIR aliases the cost pointer: wire = %d", *wire.CostUSDMicro)
	}
	back := usageFromIR(got)
	*back.CostUSDMicro = 7
	if *got.CostUSDMicro != 99 {
		t.Fatalf("usageFromIR aliases the cost pointer: ir = %d", *got.CostUSDMicro)
	}
}

// TestUsageCacheCountsNilVsZero pins the two cache counts against literal
// wire bytes on both legs, as the cost is pinned: an absent or null
// member decodes to nil, a present one to its value, zero included; nil
// encodes to no key and a zero to the key with 0; and neither pointer
// aliases across the wire/IR boundary.
func TestUsageCacheCountsNilVsZero(t *testing.T) {
	cases := []struct {
		name, body      string
		wantRead, wantW *int64
	}{
		{"absent", `{"id":"x","usage":{"input_tokens":1,"output_tokens":2}}`, nil, nil},
		{"null", `{"id":"x","usage":{"input_tokens":1,"cache_read_input_tokens":null,"cache_write_input_tokens":null}}`, nil, nil},
		{"zeros", `{"id":"x","usage":{"input_tokens":1,"cache_read_input_tokens":0,"cache_write_input_tokens":0}}`, i64(0), i64(0)},
		{"counts", `{"id":"x","usage":{"input_tokens":1,"cache_read_input_tokens":3,"cache_write_input_tokens":4}}`, i64(3), i64(4)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewBackend().DecodeResponse([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Usage.CacheReadInputTokens, tc.wantRead) || !reflect.DeepEqual(got.Usage.CacheWriteInputTokens, tc.wantW) {
				t.Fatalf("usage = %+v, want read %v write %v", got.Usage, tc.wantRead, tc.wantW)
			}
		})
	}
	body, err := NewFrontend().EncodeResponse(&ir.Response{ID: "m", Model: "m",
		Usage: ir.Usage{InputTokens: 1, CacheReadInputTokens: i64(0), CacheWriteInputTokens: i64(0)}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"cache_read_input_tokens":0`) || !strings.Contains(string(body), `"cache_write_input_tokens":0`) {
		t.Fatalf("reported zeros must be encoded: %s", body)
	}
	body, err = NewFrontend().EncodeResponse(&ir.Response{ID: "m", Model: "m", Usage: ir.Usage{InputTokens: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "cache_read_input_tokens") || strings.Contains(string(body), "cache_write_input_tokens") {
		t.Fatalf("unreported counts must be omitted: %s", body)
	}

	wire := Usage{CacheReadInputTokens: i64(5), CacheWriteInputTokens: i64(6)}
	toIR := usageToIR(wire)
	*toIR.CacheReadInputTokens, *toIR.CacheWriteInputTokens = 50, 60
	if *wire.CacheReadInputTokens != 5 || *wire.CacheWriteInputTokens != 6 {
		t.Fatalf("usageToIR aliases a cache pointer: wire = %+v", wire)
	}
	back := usageFromIR(toIR)
	*back.CacheReadInputTokens, *back.CacheWriteInputTokens = 7, 8
	if *toIR.CacheReadInputTokens != 50 || *toIR.CacheWriteInputTokens != 60 {
		t.Fatalf("usageFromIR aliases a cache pointer: ir = %+v", toIR)
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

// FuzzDecodeResponseUsage holds each optional usage member to its own
// wire key under any usage object: a member is set only when its key
// appeared, and a decoded usage re-encodes to bytes that decode to the
// same usage.
func FuzzDecodeResponseUsage(f *testing.F) {
	f.Add([]byte(`{"input_tokens":1,"output_tokens":2}`))
	f.Add([]byte(`{"input_tokens":1,"cache_read_input_tokens":0,"cache_write_input_tokens":0,"cost_usd_micro":0}`))
	f.Add([]byte(`{"cache_read_input_tokens":null,"cache_write_input_tokens":3}`))
	f.Fuzz(func(t *testing.T, usage []byte) {
		got, err := NewBackend().DecodeResponse(append(append([]byte(`{"id":"x","usage":`), usage...), '}'))
		if err != nil {
			return
		}
		for key, member := range map[string]*int64{
			"cache_read_input_tokens":  got.Usage.CacheReadInputTokens,
			"cache_write_input_tokens": got.Usage.CacheWriteInputTokens,
			"cost_usd_micro":           got.Usage.CostUSDMicro,
		} {
			if member != nil && !jsonHasKey(usage, key) {
				t.Fatalf("%s = %d reported by %s", key, *member, usage)
			}
		}
		body, err := NewFrontend().EncodeResponse(&ir.Response{ID: "x", Usage: got.Usage})
		if err != nil {
			t.Fatal(err)
		}
		again, err := NewBackend().DecodeResponse(body)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(again.Usage, got.Usage) {
			t.Fatalf("usage changed across a round trip: %+v then %+v", got.Usage, again.Usage)
		}
	})
}
