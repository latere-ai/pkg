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
		"stream": true
	}`
	req, err := NewFrontend().DecodeRequest([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if req.Model != "claude-sonnet-5" || !req.Stream || *req.MaxTokens != 128 {
		t.Fatalf("bad decode: %#v", req)
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
		Usage:        ir.Usage{InputTokens: 10, OutputTokens: 5, CacheReadInputTokens: 3, CacheWriteInputTokens: 2, ReasoningTokens: 1},
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
	full := &ir.Usage{InputTokens: 12, OutputTokens: 34, CacheReadInputTokens: 5, ReasoningTokens: 6}
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
		if err == io.EOF {
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

func TestStreamReaderSkipsUnknownFrames(t *testing.T) {
	in := "event: ping\ndata: {}\n\n" +
		"data: [DONE]\n\n" +
		"event: text_delta\ndata: {\"index\":0,\"delta\":\"hi\"}\n\n"
	r := NewStreamReader(strings.NewReader(in))
	ev, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	// The type field is filled from the frame name when absent.
	if ev.Type != ir.EventTextDelta || ev.Delta != "hi" {
		t.Fatalf("bad event: %#v", ev)
	}
	if _, err := r.Next(); err != io.EOF {
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
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := NewFrontend().DecodeRequest(body)
		if err == nil && req.Model == "" {
			t.Fatal("nil error must imply a model")
		}
	})
}
