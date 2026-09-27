// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openairesp

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// ownItem is a reasoning item of this dialect, in the form ir.Opaque
// documents.
const ownItem = `{"id":"rs_1","type":"reasoning","summary":[],"encrypted_content":"gAAAAABo"}`

func ownOpaque(raw string) ir.Block {
	return ir.Block{Type: ir.BlockOpaque, Opaque: &ir.Opaque{
		Dialect: DialectName, Kind: "reasoning", Raw: json.RawMessage(raw),
	}}
}

// inputItems returns the encoded request's input items as raw JSON, in
// order, so a test can compare an item byte for byte.
func inputItems(t *testing.T, body []byte) []json.RawMessage {
	t.Helper()
	var wire struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	return wire.Input
}

// An opaque block of this dialect is its input item: written byte for
// byte where the block stands, between the items of the blocks around
// it, with no loss.
func TestBackendReplaysOwnOpaqueInPlace(t *testing.T) {
	req := &ir.Request{Model: "gpt-5.6-sol", Messages: []ir.Message{
		{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}}},
		{Role: ir.RoleAssistant, Blocks: []ir.Block{
			{Type: ir.BlockText, Text: "before"},
			ownOpaque(ownItem),
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "call_1", Name: "shell", Args: json.RawMessage(`{}`)}},
		}},
	}}
	body, err := NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if losses := req.Loss.Strings(); losses != nil {
		t.Fatalf("loss = %v", losses)
	}
	items := inputItems(t, body)
	if len(items) != 4 {
		t.Fatalf("input = %s", body)
	}
	if string(items[2]) != ownItem {
		t.Fatalf("item not replayed verbatim:\ngot  %s\nwant %s", items[2], ownItem)
	}
	var kinds []string
	for _, it := range items {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(it, &head); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, head.Type)
	}
	if want := []string{"message", "message", "reasoning", "function_call"}; !reflect.DeepEqual(kinds, want) {
		t.Fatalf("item order = %v, want %v", kinds, want)
	}
}

// Another dialect's opaque block is dropped with the loss recorded.
func TestBackendDropsForeignOpaque(t *testing.T) {
	foreign := ir.Block{Type: ir.BlockOpaque, Opaque: &ir.Opaque{
		Dialect: ir.DialectAnthropicMessages, Kind: "widget", Raw: json.RawMessage(`{"id":"w_1"}`),
	}}
	req := &ir.Request{Model: "m", Messages: []ir.Message{
		{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}, foreign}},
	}}
	body, err := NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{string(ir.LossOpaque)}; !reflect.DeepEqual(req.Loss.Strings(), want) {
		t.Fatalf("loss = %v, want %v", req.Loss.Strings(), want)
	}
	if strings.Contains(string(body), "w_1") {
		t.Fatalf("body carries the foreign item:\n%s", body)
	}
}

// An opaque block with no payload, or one of this dialect with no item,
// cannot be written; the request fails rather than sending null.
func TestBackendRejectsMalformedOpaque(t *testing.T) {
	for name, blk := range map[string]ir.Block{
		"no payload": {Type: ir.BlockOpaque},
		"no item":    ownOpaque(""),
	} {
		req := &ir.Request{Model: "m", Messages: []ir.Message{{Role: ir.RoleAssistant, Blocks: []ir.Block{blk}}}}
		if _, err := NewBackend().EncodeRequest(req); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// The frontend's callers never asked for opaque items, so a response
// and a stream carry none, and the stream's output indices stay dense.
func TestFrontendSkipsOpaque(t *testing.T) {
	raw, err := NewFrontend().EncodeResponse(&ir.Response{ID: "r1", Blocks: []ir.Block{
		ownOpaque(ownItem), {Type: ir.BlockText, Text: "yes"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "rs_1") {
		t.Fatalf("response carries the opaque item:\n%s", raw)
	}

	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	blk := ownOpaque(ownItem)
	for _, ev := range []ir.Event{
		{Type: ir.EventMessageStart, ID: "r1", Model: "m"},
		{Type: ir.EventBlockStart, Index: 0, Block: &blk},
		{Type: ir.EventBlockStop, Index: 0},
		{Type: ir.EventBlockStart, Index: 1, Block: &ir.Block{Type: ir.BlockText}},
		{Type: ir.EventTextDelta, Index: 1, Delta: "yes"},
		{Type: ir.EventBlockStop, Index: 1},
	} {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	out := buf.String()
	if strings.Contains(out, "rs_1") {
		t.Fatalf("stream carries the opaque item:\n%s", out)
	}
	for _, f := range readFrames(t, out) {
		if f.Name != "response.output_item.added" {
			continue
		}
		var added struct {
			OutputIndex int `json:"output_index"`
		}
		if err := json.Unmarshal(f.Data, &added); err != nil {
			t.Fatal(err)
		}
		if added.OutputIndex != 0 {
			t.Fatalf("text item at output_index %d, want 0", added.OutputIndex)
		}
	}
}

// A reasoning item that came back with its encrypted_content is kept as
// an opaque block after its summary, in the form ir.Opaque documents:
// the body's indentation is gone and < is escaped, so every later
// marshal leaves the bytes as they are.
func TestBackendDecodeResponseKeepsReasoningItem(t *testing.T) {
	body := `{"id":"resp_1","status":"completed","output":[
		{
			"id": "rs_1",
			"type": "reasoning",
			"summary": [{"type": "summary_text", "text": "a < b"}],
			"encrypted_content": "gAAAAABo"
		},
		{"type":"message","role":"assistant","content":[{"type":"output_text","text":"yes"}]}
	]}`
	resp, err := NewBackend().DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if got := blockKinds(resp.Blocks); !reflect.DeepEqual(got, []string{"thinking", "opaque", "text"}) {
		t.Fatalf("blocks = %v", got)
	}
	op := resp.Blocks[1].Opaque
	const want = `{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"a \u003c b"}],"encrypted_content":"gAAAAABo"}`
	if op.Dialect != DialectName || op.Kind != "reasoning" || string(op.Raw) != want {
		t.Fatalf("opaque = %s %s %s", op.Dialect, op.Kind, op.Raw)
	}
	again, err := json.Marshal(op.Raw)
	if err != nil || string(again) != want {
		t.Fatalf("a later marshal changed the bytes: %s", again)
	}
}

// Without encrypted_content (the request did not ask) the item is not
// replayable and no opaque block appears, so a caller that never asked
// sees what it always saw.
func TestBackendDecodeResponseSkipsUnaskedReasoningItem(t *testing.T) {
	body := `{"id":"resp_1","status":"completed","output":[
		{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"hm"}]},
		{"id":"rs_2","type":"reasoning","summary":[],"encrypted_content":null}
	]}`
	resp, err := NewBackend().DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if got := blockKinds(resp.Blocks); !reflect.DeepEqual(got, []string{"thinking"}) {
		t.Fatalf("blocks = %v", got)
	}
}

// An empty summary gives no thinking block, and the item alone is kept.
func TestBackendDecodeResponseReasoningItemWithoutSummary(t *testing.T) {
	body := `{"id":"resp_1","output":[{"id":"rs_1","type":"reasoning","summary":[],"encrypted_content":"gAAAAABo"}]}`
	resp, err := NewBackend().DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if got := blockKinds(resp.Blocks); !reflect.DeepEqual(got, []string{"opaque"}) {
		t.Fatalf("blocks = %v", got)
	}
}

func TestBackendDecodeResponseRejectsNonObjectItem(t *testing.T) {
	if _, err := NewBackend().DecodeResponse([]byte(`{"output":["rs_1"]}`)); err == nil {
		t.Fatal("want error for an output item that is not an object")
	}
}

func TestReasoningBlockRejectsInvalidJSON(t *testing.T) {
	if _, err := reasoningBlock(json.RawMessage(`{`)); err == nil {
		t.Fatal("want error for an item that is not JSON")
	}
}

// streamOf frames Responses events as SSE.
func streamOf(frames ...string) string {
	var b strings.Builder
	for _, f := range frames {
		b.WriteString("data: " + f + "\n\n")
	}
	return b.String()
}

func drainEvents(t *testing.T, stream string) []ir.Event {
	t.Helper()
	dec := NewBackend().NewEventDecoder(strings.NewReader(stream))
	var out []ir.Event
	for {
		ev, err := dec.Next()
		if err != nil {
			return out
		}
		out = append(out, ev)
	}
}

// In a stream the item is complete only on its output_item.done frame,
// so its opaque block follows the summary's thinking block at the next
// index, one header with the payload and its stop, and later blocks
// move up by one. The raw bytes are the frame's.
func TestBackendEventDecoderKeepsReasoningItem(t *testing.T) {
	const item = `{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"hm"}],"encrypted_content":"gAAAAABo"}`
	events := drainEvents(t, streamOf(
		`{"type":"response.created","response":{"id":"resp_1","model":"m"}}`,
		`{"type":"response.output_item.added","item":{"id":"rs_1","type":"reasoning","summary":[]}}`,
		`{"type":"response.reasoning_summary_text.delta","delta":"hm"}`,
		`{"type":"response.output_item.done","item":`+item+`}`,
		`{"type":"response.output_item.added","item":{"type":"message"}}`,
		`{"type":"response.output_text.delta","delta":"yes"}`,
		`{"type":"response.output_item.done","item":{"type":"message"}}`,
		`{"type":"response.completed","response":{"status":"completed"}}`,
	))
	type step struct {
		typ   ir.EventType
		index int
	}
	var got []step
	for _, ev := range events {
		got = append(got, step{ev.Type, ev.Index})
	}
	want := []step{
		{ir.EventMessageStart, 0},
		{ir.EventBlockStart, 0}, {ir.EventThinkingDelta, 0}, {ir.EventBlockStop, 0},
		{ir.EventBlockStart, 1}, {ir.EventBlockStop, 1},
		{ir.EventBlockStart, 2}, {ir.EventTextDelta, 2}, {ir.EventBlockStop, 2},
		{ir.EventMessageDelta, 0}, {ir.EventMessageStop, 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v\nwant %v", got, want)
	}
	op := events[4].Block.Opaque
	if events[4].Block.Type != ir.BlockOpaque || op.Dialect != DialectName || op.Kind != "reasoning" || string(op.Raw) != item {
		t.Fatalf("opaque header = %+v", events[4].Block)
	}
}

func TestBackendEventDecoderSkipsUnaskedReasoningItem(t *testing.T) {
	events := drainEvents(t, streamOf(
		`{"type":"response.created","response":{"id":"resp_1"}}`,
		`{"type":"response.output_item.added","item":{"type":"reasoning"}}`,
		`{"type":"response.output_item.done","item":{"id":"rs_1","type":"reasoning","summary":[]}}`,
		`{"type":"response.completed","response":{"status":"completed"}}`,
	))
	for _, ev := range events {
		if ev.Block != nil && ev.Block.Type == ir.BlockOpaque {
			t.Fatalf("opaque block for an item without encrypted_content: %+v", ev)
		}
	}
}

func TestBackendEventDecoderRejectsNonObjectItem(t *testing.T) {
	dec := NewBackend().NewEventDecoder(strings.NewReader(streamOf(
		`{"type":"response.output_item.done","item":"rs_1"}`,
	)))
	if _, err := dec.Next(); err == nil {
		t.Fatal("want error for an item that is not an object")
	}
}

// ReasoningReplay asks for the items' encrypted_content and stores
// nothing upstream; it joins the logprobs ask rather than replacing it.
func TestBackendEncodeReasoningReplay(t *testing.T) {
	msgs := []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}}}}
	for name, tc := range map[string]struct {
		req     ir.Request
		include []any
		store   any
	}{
		"replay":          {ir.Request{ReasoningReplay: true}, []any{"reasoning.encrypted_content"}, false},
		"replay+logprobs": {ir.Request{ReasoningReplay: true, LogProbs: true}, []any{"message.output_text.logprobs", "reasoning.encrypted_content"}, false},
		"neither":         {ir.Request{}, nil, nil},
	} {
		req := tc.req
		req.Model, req.Messages = "m", msgs
		raw, err := NewBackend().EncodeRequest(&req)
		if err != nil {
			t.Fatal(err)
		}
		body := mustJSON(t, raw)
		if inc, _ := body["include"].([]any); !reflect.DeepEqual(inc, tc.include) {
			t.Errorf("%s: include = %v, want %v", name, body["include"], tc.include)
		}
		if body["store"] != tc.store {
			t.Errorf("%s: store = %v, want %v", name, body["store"], tc.store)
		}
		if losses := req.Loss.Strings(); losses != nil {
			t.Errorf("%s: loss = %v", name, losses)
		}
	}
}

// A thinking block is carried by the reasoning item right after it and
// travels without loss; any other thinking is still reported.
func TestBackendEncodeThinkingBesideReasoningItem(t *testing.T) {
	other := ownOpaque(ownItem)
	other.Opaque = &ir.Opaque{Dialect: DialectName, Kind: "compaction", Raw: json.RawMessage(`{"type":"compaction"}`)}
	for name, tc := range map[string]struct {
		blocks []ir.Block
		loss   []string
	}{
		"summary of the next item": {[]ir.Block{{Type: ir.BlockThinking, Text: "hm"}, ownOpaque(ownItem)}, nil},
		"item of another kind":     {[]ir.Block{{Type: ir.BlockThinking, Text: "hm"}, other}, []string{"thinking"}},
		"item before the thinking": {[]ir.Block{ownOpaque(ownItem), {Type: ir.BlockThinking, Text: "hm"}}, []string{"thinking"}},
		"redacted before an item":  {[]ir.Block{{Type: ir.BlockRedactedThinking, Redacted: "x"}, ownOpaque(ownItem)}, []string{"thinking"}},
	} {
		req := &ir.Request{Model: "m", Messages: []ir.Message{{Role: ir.RoleAssistant, Blocks: tc.blocks}}}
		raw, err := NewBackend().EncodeRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		if got := req.Loss.Strings(); !reflect.DeepEqual(got, tc.loss) {
			t.Errorf("%s: loss = %v, want %v", name, got, tc.loss)
		}
		if strings.Contains(string(raw), `"hm"`) {
			t.Errorf("%s: thinking text written outside its item:\n%s", name, raw)
		}
	}
}
