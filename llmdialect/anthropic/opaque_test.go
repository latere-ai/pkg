// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

const opaqueItem = `{"id":"rs_1","type":"reasoning","encrypted_content":"gAAAAABo"}`

func opaqueBlock() ir.Block {
	return ir.Block{Type: ir.BlockOpaque, Opaque: &ir.Opaque{
		Dialect: ir.DialectOpenAIResponses, Kind: "reasoning", Raw: json.RawMessage(opaqueItem),
	}}
}

// Messages defines no opaque items, so another dialect's block is
// dropped from either turn with the loss recorded, and nothing of it
// reaches the body.
func TestBackendDropsOpaque(t *testing.T) {
	req := &ir.Request{Model: "claude-sonnet-5", Messages: []ir.Message{
		{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}, opaqueBlock()}},
		{Role: ir.RoleAssistant, Blocks: []ir.Block{opaqueBlock(), {Type: ir.BlockText, Text: "yes"}}},
	}}
	raw, err := NewBackend(BackendOptions{}).EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{string(ir.LossOpaque)}; !reflect.DeepEqual(req.Loss.Strings(), want) {
		t.Fatalf("loss = %v, want %v", req.Loss.Strings(), want)
	}
	for _, trace := range []string{"rs_1", "encrypted_content", "opaque"} {
		if strings.Contains(string(raw), trace) {
			t.Fatalf("body carries %q:\n%s", trace, raw)
		}
	}
	var body struct {
		Messages []struct {
			Content []map[string]any `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Messages) != 2 || len(body.Messages[0].Content) != 1 || len(body.Messages[1].Content) != 1 {
		t.Fatalf("messages = %+v", body.Messages)
	}
}

func TestEncodeResponseSkipsOpaque(t *testing.T) {
	raw, err := NewFrontend().EncodeResponse(&ir.Response{ID: "m1", Blocks: []ir.Block{
		{Type: ir.BlockThinking, Text: "hm"}, opaqueBlock(), {Type: ir.BlockText, Text: "yes"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Content []map[string]any `json:"content"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Content) != 2 || body.Content[0]["type"] != "thinking" || body.Content[1]["type"] != "text" {
		t.Fatalf("content = %v", body.Content)
	}
}

// The stream drops the opaque block's events and shifts every later
// index down past it, so a client that files deltas under
// content[index] sees the dense indices a Messages stream carries.
func TestEventEncoderDropsOpaqueAndKeepsIndicesDense(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	blk := opaqueBlock()
	events := []ir.Event{
		{Type: ir.EventMessageStart, ID: "m1", Model: "gpt-5.6-sol"},
		{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockThinking}},
		{Type: ir.EventThinkingDelta, Index: 0, Delta: "hm"},
		{Type: ir.EventBlockStop, Index: 0},
		{Type: ir.EventBlockStart, Index: 1, Block: &blk},
		{Type: ir.EventBlockStop, Index: 1},
		{Type: ir.EventBlockStart, Index: 2, Block: &ir.Block{Type: ir.BlockText}},
		{Type: ir.EventTextDelta, Index: 2, Delta: "yes"},
		{Type: ir.EventBlockStop, Index: 2},
		{Type: ir.EventMessageDelta, StopReason: ir.StopEndTurn},
		{Type: ir.EventMessageStop},
	}
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(buf.String(), "rs_1") {
		t.Fatalf("stream carries the opaque item:\n%s", buf.String())
	}
	type frame struct {
		name  string
		index float64
	}
	var got []frame
	for _, f := range readEvents(t, buf.String()) {
		if !strings.HasPrefix(f.Name, "content_block_") {
			continue
		}
		var data map[string]any
		if err := json.Unmarshal(f.Data, &data); err != nil {
			t.Fatal(err)
		}
		got = append(got, frame{f.Name, data["index"].(float64)})
	}
	want := []frame{
		{"content_block_start", 0}, {"content_block_delta", 0}, {"content_block_stop", 0},
		{"content_block_start", 1}, {"content_block_delta", 1}, {"content_block_stop", 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("frames = %v\nwant %v", got, want)
	}
}

// A block that starts at an index an opaque block already took is a
// malformed stream: there is no dense index to give it.
func TestEventEncoderRejectsReusedOpaqueIndex(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	blk := opaqueBlock()
	if err := enc.Encode(ir.Event{Type: ir.EventBlockStart, Index: 0, Block: &blk}); err != nil {
		t.Fatal(err)
	}
	err := enc.Encode(ir.Event{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockText}})
	if err == nil {
		t.Fatal("want error for a block start at a dropped index")
	}
}

// Messages thinking blocks carry their signatures whether asked or not,
// so the replay ask changes nothing in the body and loses nothing.
func TestBackendServesReasoningReplayUnasked(t *testing.T) {
	build := func(replay bool) (*ir.Request, []byte) {
		req := &ir.Request{Model: "claude-sonnet-5", ReasoningReplay: replay, Messages: []ir.Message{userMsg("hi")}}
		raw, err := NewBackend(BackendOptions{}).EncodeRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		return req, raw
	}
	req, asked := build(true)
	_, plain := build(false)
	if losses := req.Loss.Strings(); losses != nil {
		t.Fatalf("loss = %v", losses)
	}
	if !bytes.Equal(asked, plain) {
		t.Fatalf("body changed:\n%s\nvs\n%s", asked, plain)
	}
}
