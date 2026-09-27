// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openairesp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/internal/sse"
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

// encodeStream runs events through the frontend's stream encoder and
// returns the frames it wrote.
func encodeStream(t *testing.T, events ...ir.Event) []sse.Event {
	t.Helper()
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	return readFrames(t, buf.String())
}

// outputFrame is the head of a response.output_item.added or .done
// frame, with its item raw.
type outputFrame struct {
	name  string
	index int
	item  json.RawMessage
}

func outputFrames(t *testing.T, frames []sse.Event) []outputFrame {
	t.Helper()
	var out []outputFrame
	for _, f := range frames {
		if f.Name != "response.output_item.added" && f.Name != "response.output_item.done" {
			continue
		}
		var wire struct {
			OutputIndex int             `json:"output_index"`
			Item        json.RawMessage `json:"item"`
		}
		if err := json.Unmarshal(f.Data, &wire); err != nil {
			t.Fatal(err)
		}
		out = append(out, outputFrame{f.Name, wire.OutputIndex, wire.Item})
	}
	return out
}

// completedOutput is the output list of the stream's final
// response.completed or response.incomplete frame.
func completedOutput(t *testing.T, frames []sse.Event) []json.RawMessage {
	t.Helper()
	last := frames[len(frames)-1]
	var wire struct {
		Response struct {
			Output []json.RawMessage `json:"output"`
		} `json:"response"`
	}
	if err := json.Unmarshal(last.Data, &wire); err != nil {
		t.Fatal(err)
	}
	return wire.Response.Output
}

// responseOutput is the output list of an encoded response body.
func responseOutput(t *testing.T, body []byte) []json.RawMessage {
	t.Helper()
	var wire struct {
		Output []json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	return wire.Output
}

func itemType(t *testing.T, item json.RawMessage) string {
	t.Helper()
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(item, &head); err != nil {
		t.Fatal(err)
	}
	return head.Type
}

// Opaque blocks of another dialect, and of this dialect with a kind
// that is not reasoning, have no output item: a response and a stream
// carry none of them, and the stream's output indices stay dense.
func TestFrontendSkipsOtherOpaque(t *testing.T) {
	foreign := ir.Block{Type: ir.BlockOpaque, Opaque: &ir.Opaque{
		Dialect: ir.DialectAnthropicMessages, Kind: "reasoning", Raw: json.RawMessage(`{"id":"w_1"}`),
	}}
	otherKind := ir.Block{Type: ir.BlockOpaque, Opaque: &ir.Opaque{
		Dialect: DialectName, Kind: "compaction", Raw: json.RawMessage(`{"id":"cmp_1","type":"compaction"}`),
	}}
	for name, blk := range map[string]ir.Block{"foreign": foreign, "other kind": otherKind} {
		raw, err := NewFrontend().EncodeResponse(&ir.Response{ID: "r1", Blocks: []ir.Block{
			{Type: ir.BlockThinking, Text: "hm"}, blk, {Type: ir.BlockText, Text: "yes"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "w_1") || strings.Contains(string(raw), "cmp_1") {
			t.Fatalf("%s: response carries the opaque item:\n%s", name, raw)
		}
		if got := len(responseOutput(t, raw)); got != 2 {
			t.Fatalf("%s: want the thinking and text items, got %d:\n%s", name, got, raw)
		}

		frames := encodeStream(t,
			ir.Event{Type: ir.EventMessageStart, ID: "r1", Model: "m"},
			ir.Event{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockThinking}},
			ir.Event{Type: ir.EventThinkingDelta, Index: 0, Delta: "hm"},
			ir.Event{Type: ir.EventBlockStop, Index: 0},
			ir.Event{Type: ir.EventBlockStart, Index: 1, Block: &blk},
			ir.Event{Type: ir.EventBlockStop, Index: 1},
			ir.Event{Type: ir.EventBlockStart, Index: 2, Block: &ir.Block{Type: ir.BlockText}},
			ir.Event{Type: ir.EventTextDelta, Index: 2, Delta: "yes"},
			ir.Event{Type: ir.EventBlockStop, Index: 2},
			ir.Event{Type: ir.EventMessageDelta, StopReason: ir.StopEndTurn},
		)
		var steps []string
		for _, f := range outputFrames(t, frames) {
			if strings.Contains(string(f.item), "w_1") || strings.Contains(string(f.item), "cmp_1") {
				t.Fatalf("%s: stream carries the opaque item: %s", name, f.item)
			}
			steps = append(steps, fmt.Sprintf("%s %d %s", f.name, f.index, itemType(t, f.item)))
		}
		want := []string{
			"response.output_item.added 0 reasoning", "response.output_item.done 0 reasoning",
			"response.output_item.added 1 message", "response.output_item.done 1 message",
		}
		if !reflect.DeepEqual(steps, want) {
			t.Fatalf("%s: frames = %v\nwant %v", name, steps, want)
		}
	}
}

// A reasoning item of this dialect is written back as the output item
// it was, byte for byte, where it stands. The thinking block before it
// is its summary and has no item of its own; thinking that no item
// follows keeps its own reasoning item.
func TestFrontendWritesReasoningItem(t *testing.T) {
	const second = `{"id":"rs_2","type":"reasoning","summary":[],"encrypted_content":"gAAAAABp"}`
	raw, err := NewFrontend().EncodeResponse(&ir.Response{ID: "r1", Blocks: []ir.Block{
		{Type: ir.BlockThinking, Text: "hm"},
		ownOpaque(ownItem),
		{Type: ir.BlockText, Text: "yes"},
		ownOpaque(second),
		{Type: ir.BlockThinking, Text: "alone"},
		{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "call_1", Name: "shell", Args: json.RawMessage(`{}`)}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	output := responseOutput(t, raw)
	var kinds []string
	for _, it := range output {
		kinds = append(kinds, itemType(t, it))
	}
	if want := []string{"reasoning", "message", "reasoning", "reasoning", "function_call"}; !reflect.DeepEqual(kinds, want) {
		t.Fatalf("output = %v, want %v\n%s", kinds, want, raw)
	}
	if string(output[0]) != ownItem || string(output[2]) != second {
		t.Fatalf("reasoning items not written verbatim:\n%s", raw)
	}
	if !strings.Contains(string(output[3]), `"alone"`) {
		t.Fatalf("thinking without an item lost its own item: %s", output[3])
	}
}

func TestFrontendRejectsEmptyReasoningItem(t *testing.T) {
	if _, err := NewFrontend().EncodeResponse(&ir.Response{ID: "r1", Blocks: []ir.Block{ownOpaque("")}}); err == nil {
		t.Fatal("response: want error for a reasoning item with no JSON")
	}
	enc := NewFrontend().NewEventEncoder(&bytes.Buffer{})
	for name, raw := range map[string]string{"empty": "", "not an object": `"rs_1"`} {
		blk := ownOpaque(raw)
		if err := enc.Encode(ir.Event{Type: ir.EventBlockStart, Block: &blk}); err == nil {
			t.Errorf("stream, %s: want error", name)
		}
	}
}

// In a stream the thinking block and the reasoning item after it are
// one output item: added with the summary's deltas, then done carrying
// the item byte for byte. A reasoning item alone gets its own added
// frame with the item's head. response.completed lists the items as the
// done frames carried them, and indices stay dense.
func TestFrontendStreamsReasoningItem(t *testing.T) {
	const second = `{"id":"rs_2","type":"reasoning","summary":[],"encrypted_content":"gAAAAABp"}`
	first, alone := ownOpaque(ownItem), ownOpaque(second)
	frames := encodeStream(t,
		ir.Event{Type: ir.EventMessageStart, ID: "r1", Model: "m"},
		ir.Event{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockThinking}},
		ir.Event{Type: ir.EventThinkingDelta, Index: 0, Delta: "hm"},
		ir.Event{Type: ir.EventBlockStop, Index: 0},
		ir.Event{Type: ir.EventBlockStart, Index: 1, Block: &first},
		ir.Event{Type: ir.EventBlockStop, Index: 1},
		ir.Event{Type: ir.EventBlockStart, Index: 2, Block: &alone},
		ir.Event{Type: ir.EventBlockStop, Index: 2},
		ir.Event{Type: ir.EventBlockStart, Index: 3, Block: &ir.Block{Type: ir.BlockText}},
		ir.Event{Type: ir.EventTextDelta, Index: 3, Delta: "yes"},
		ir.Event{Type: ir.EventBlockStop, Index: 3},
		ir.Event{Type: ir.EventMessageDelta, StopReason: ir.StopEndTurn},
		ir.Event{Type: ir.EventMessageStop},
	)
	var names []string
	for _, f := range frames {
		names = append(names, f.Name)
	}
	wantNames := []string{
		"response.created", "response.in_progress",
		"response.output_item.added", "response.reasoning_summary_text.delta", "response.output_item.done",
		"response.output_item.added", "response.output_item.done",
		"response.output_item.added", "response.content_part.added", "response.output_text.delta",
		"response.output_text.done", "response.output_item.done",
		"response.completed",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("frames = %v\nwant %v", names, wantNames)
	}
	items := outputFrames(t, frames)
	if items[0].index != 0 || items[1].index != 0 || string(items[1].item) != ownItem {
		t.Fatalf("summary and item not one output item: %+v", items[:2])
	}
	if items[2].index != 1 || string(items[2].item) != `{"id":"rs_2","summary":[],"type":"reasoning"}` {
		t.Fatalf("added frame of a lone item = %d %s", items[2].index, items[2].item)
	}
	if items[3].index != 1 || string(items[3].item) != second {
		t.Fatalf("done frame of a lone item = %d %s", items[3].index, items[3].item)
	}
	if items[4].index != 2 || items[5].index != 2 {
		t.Fatalf("message item at %d/%d, want 2", items[4].index, items[5].index)
	}
	output := completedOutput(t, frames)
	if len(output) != 3 || string(output[0]) != ownItem || string(output[1]) != second {
		t.Fatalf("completed output = %s", output)
	}
	for i, f := range frames {
		var head struct {
			Seq int `json:"sequence_number"`
		}
		if err := json.Unmarshal(f.Data, &head); err != nil || head.Seq != i {
			t.Fatalf("sequence_number[%d] = %d (%v)", i, head.Seq, err)
		}
	}
}

// Thinking that ends the stream still gets its done frame, before the
// response's final frame lists it.
func TestFrontendStreamsTrailingThinking(t *testing.T) {
	frames := encodeStream(t,
		ir.Event{Type: ir.EventMessageStart, ID: "r1", Model: "m"},
		ir.Event{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockThinking}},
		ir.Event{Type: ir.EventThinkingDelta, Index: 0, Delta: "hm"},
		ir.Event{Type: ir.EventBlockStop, Index: 0},
		ir.Event{Type: ir.EventMessageDelta, StopReason: ir.StopEndTurn},
	)
	items := outputFrames(t, frames)
	if len(items) != 2 || items[1].name != "response.output_item.done" || !strings.Contains(string(items[1].item), `"hm"`) {
		t.Fatalf("output frames = %+v", items)
	}
	if output := completedOutput(t, frames); len(output) != 1 {
		t.Fatalf("completed output = %s", output)
	}
}

// A caller's reasoning item with its encrypted_content is kept as an
// opaque block of this dialect in the assistant turn where it stands,
// in the form ir.Opaque documents: the body's indentation is gone and <
// is escaped. One without encrypted_content names an item only the
// upstream's store could resolve and is reported lost.
func TestFrontendDecodesReasoningItem(t *testing.T) {
	req := decode(t, `{"model":"m","include":["reasoning.encrypted_content"],"input":[
		{"type":"message","role":"user","content":"hi"},
		{"type":"message","role":"assistant","content":[{"type":"output_text","text":"looking"}]},
		{
			"id": "rs_1",
			"type": "reasoning",
			"summary": [{"type": "summary_text", "text": "a < b"}],
			"encrypted_content": "gAAAAABo"
		},
		{"id":"rs_2","type":"reasoning","summary":[]},
		{"type":"function_call","call_id":"call_1","name":"shell","arguments":"{}"},
		{"type":"function_call_output","call_id":"call_1","output":"ok"}
	]}`)
	if !req.ReasoningReplay {
		t.Fatal("include reasoning.encrypted_content did not ask for replay")
	}
	if want := []string{string(ir.LossReasoningItems)}; !reflect.DeepEqual(req.Loss.Strings(), want) {
		t.Fatalf("loss = %v, want %v", req.Loss.Strings(), want)
	}
	if len(req.Messages) != 3 {
		t.Fatalf("messages = %+v", req.Messages)
	}
	asst := req.Messages[1]
	if got := blockKinds(asst.Blocks); asst.Role != ir.RoleAssistant || !reflect.DeepEqual(got, []string{"text", "opaque", "tool_use"}) {
		t.Fatalf("assistant turn = %s %v", asst.Role, got)
	}
	op := asst.Blocks[1].Opaque
	const want = `{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"a \u003c b"}],"encrypted_content":"gAAAAABo"}`
	if op.Dialect != DialectName || op.Kind != "reasoning" || string(op.Raw) != want {
		t.Fatalf("opaque = %s %s %s", op.Dialect, op.Kind, op.Raw)
	}
}

func TestFrontendRejectsNonObjectItem(t *testing.T) {
	if _, err := NewFrontend().DecodeRequest([]byte(`{"model":"m","input":["rs_1"]}`)); err == nil {
		t.Fatal("want error for an input item that is not an object")
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
