// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package lux

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// reasoningItem is a Responses reasoning item in the form ir.Opaque
// documents: compact, with the HTML characters escaped.
const reasoningItem = `{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"a \u003c b"}],"encrypted_content":"gAAAAABo"}`

func opaqueBlock() ir.Block {
	return ir.Block{Type: ir.BlockOpaque, Opaque: &ir.Opaque{
		Dialect: ir.DialectOpenAIResponses, Kind: "reasoning", Raw: raw(reasoningItem),
	}}
}

// An opaque block of any dialect crosses the lux wire in a request and
// comes back as the same IR, raw bytes included, with no loss: the lux
// dialect is the IR, so it is where such blocks are stored.
func TestOpaqueRequestRoundTrip(t *testing.T) {
	want := &ir.Request{
		Model: "gpt-5.6-sol",
		Messages: []ir.Message{
			{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}}},
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockThinking, Text: "a < b"},
				opaqueBlock(),
				{Type: ir.BlockText, Text: "yes"},
			}},
		},
	}
	body, err := NewBackend().EncodeRequest(want)
	if err != nil {
		t.Fatal(err)
	}
	wireBlock := `{"type":"opaque","opaque":{"dialect":"openai-responses","kind":"reasoning","raw":` + reasoningItem + `}}`
	if !strings.Contains(string(body), wireBlock) {
		t.Fatalf("wire block not carried as a JSON value:\n%s", body)
	}
	got, err := NewFrontend().DecodeRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if losses := got.Loss.Strings(); losses != nil {
		t.Fatalf("lost fields: %v", losses)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\ngot  %#v\nwant %#v", got, want)
	}
	if raw := got.Messages[1].Blocks[1].Opaque.Raw; string(raw) != reasoningItem {
		t.Fatalf("raw changed:\ngot  %s\nwant %s", raw, reasoningItem)
	}
}

func TestOpaqueResponseRoundTrip(t *testing.T) {
	want := &ir.Response{
		ID:         "r1",
		Model:      "m",
		Blocks:     []ir.Block{{Type: ir.BlockThinking, Text: "a < b"}, opaqueBlock(), {Type: ir.BlockText, Text: "yes"}},
		StopReason: ir.StopEndTurn,
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

// In a stream the opaque block is one header carrying the payload and
// its stop; both survive the lux SSE framing.
func TestOpaqueStreamRoundTrip(t *testing.T) {
	blk := opaqueBlock()
	want := []ir.Event{
		{Type: ir.EventMessageStart, ID: "r1", Model: "m"},
		{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockThinking}},
		{Type: ir.EventThinkingDelta, Index: 0, Delta: "a < b"},
		{Type: ir.EventBlockStop, Index: 0},
		{Type: ir.EventBlockStart, Index: 1, Block: &blk},
		{Type: ir.EventBlockStop, Index: 1},
		{Type: ir.EventMessageDelta, StopReason: ir.StopEndTurn},
		{Type: ir.EventMessageStop},
	}
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
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

// A lux body written by another encoder (indented, HTML characters
// unescaped) decodes to the raw form ir.Opaque documents, the same bytes
// this codec would have written.
func TestOpaqueDecodeNormalizesRaw(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"assistant","blocks":[
		{"type":"opaque","opaque":{"dialect":"openai-responses","kind":"reasoning","raw":{
			"id": "rs_1",
			"type": "reasoning",
			"summary": [{"type": "summary_text", "text": "a < b"}],
			"encrypted_content": "gAAAAABo"
		}}}]}]}`
	got, err := NewFrontend().DecodeRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if raw := got.Messages[0].Blocks[0].Opaque.Raw; string(raw) != reasoningItem {
		t.Fatalf("raw not normalized:\ngot  %s\nwant %s", raw, reasoningItem)
	}
}

func TestOpaqueDecodeErrors(t *testing.T) {
	for name, blk := range map[string]string{
		"missing payload": `{"type":"opaque"}`,
		"missing dialect": `{"type":"opaque","opaque":{"kind":"reasoning","raw":{}}}`,
		"missing raw":     `{"type":"opaque","opaque":{"dialect":"openai-responses"}}`,
	} {
		body := `{"model":"m","messages":[{"role":"assistant","blocks":[` + blk + `]}]}`
		if _, err := NewFrontend().DecodeRequest([]byte(body)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	// A wire block built in Go rather than decoded can hold bytes that
	// are not JSON at all.
	var loss ir.Loss
	_, _, err := blockToIR(Block{Type: ir.BlockOpaque, Opaque: &Opaque{Dialect: ir.DialectOpenAIResponses, Raw: raw("{")}}, &loss)
	if err == nil || !strings.Contains(err.Error(), "opaque block raw") {
		t.Fatalf("invalid raw: err = %v", err)
	}
}

func TestOpaqueEncodeRequiresPayload(t *testing.T) {
	req := &ir.Request{Model: "m", Messages: []ir.Message{
		{Role: ir.RoleAssistant, Blocks: []ir.Block{{Type: ir.BlockOpaque}}},
	}}
	if _, err := NewBackend().EncodeRequest(req); err == nil {
		t.Fatal("want error for an opaque block without a payload")
	}
}

// The wire block holds its own copy of Raw, so a caller that reuses the
// IR buffer cannot reach what was already converted.
func TestOpaqueRawNotAliased(t *testing.T) {
	blk := opaqueBlock()
	wire, err := blockFromIR(blk)
	if err != nil {
		t.Fatal(err)
	}
	blk.Opaque.Raw[0] = '['
	if string(wire.Opaque.Raw) != reasoningItem {
		t.Fatalf("wire raw shares memory with the IR: %s", wire.Opaque.Raw)
	}
}
