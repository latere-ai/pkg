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
