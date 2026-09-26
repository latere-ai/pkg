// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openaichat

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

// Chat Completions defines no opaque items, so another dialect's block
// is dropped from either turn with the loss recorded, and nothing of it
// reaches the body.
func TestBackendDropsOpaque(t *testing.T) {
	req := &ir.Request{Model: "qwen3", Messages: []ir.Message{
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
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Messages) != 2 || body.Messages[0]["content"] != "hi" || body.Messages[1]["content"] != "yes" {
		t.Fatalf("messages = %v", body.Messages)
	}
}

func TestEncodeResponseSkipsOpaque(t *testing.T) {
	raw, err := NewFrontend().EncodeResponse(&ir.Response{ID: "c1", Blocks: []ir.Block{
		opaqueBlock(), {Type: ir.BlockText, Text: "yes"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "rs_1") {
		t.Fatalf("response carries the opaque item:\n%s", raw)
	}
	var body struct {
		Choices []struct {
			Message map[string]any `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.Choices[0].Message["content"] != "yes" {
		t.Fatalf("message = %v", body.Choices[0].Message)
	}
}

// The stream writes nothing for an opaque block: its start is not a
// tool call and its stop closes nothing.
func TestEventEncoderSkipsOpaque(t *testing.T) {
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	blk := opaqueBlock()
	for _, ev := range []ir.Event{
		{Type: ir.EventMessageStart, ID: "c1", Model: "m"},
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
	if strings.Contains(out, "rs_1") || strings.Count(out, "data: ") != 2 || !strings.Contains(out, `"content":"yes"`) {
		t.Fatalf("stream = %s", out)
	}
}
