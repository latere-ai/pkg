// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package llmdialect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/anthropic"
	"latere.ai/x/pkg/llmdialect/ir"
	"latere.ai/x/pkg/llmdialect/lux"
	"latere.ai/x/pkg/llmdialect/openaichat"
	"latere.ai/x/pkg/llmdialect/openairesp"
)

// The fixtures under testdata are one Responses turn of a reasoning
// model asked for include reasoning.encrypted_content with store false:
// a reasoning item with its summary and encrypted_content, then a
// function call. reasoning_response.json is the non-streaming body,
// indented as the API writes it; reasoning_stream.sse is the same turn
// streamed.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// streamedReasoningItem is the reasoning item exactly as its
// response.output_item.done frame carried it.
func streamedReasoningItem(t *testing.T, sse []byte) []byte {
	t.Helper()
	for line := range strings.SplitSeq(string(sse), "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var frame struct {
			Type string          `json:"type"`
			Item json.RawMessage `json:"item"`
		}
		if err := json.Unmarshal([]byte(data), &frame); err != nil {
			t.Fatal(err)
		}
		if frame.Type != "response.output_item.done" {
			continue
		}
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(frame.Item, &head); err != nil {
			t.Fatal(err)
		}
		if head.Type == "reasoning" {
			return frame.Item
		}
	}
	t.Fatal("no reasoning item in the stream")
	return nil
}

// respondedReasoningItem is the reasoning item of the non-streaming
// body, compacted: the body is indented, and ir.Opaque keeps the item
// in the form encoding/json writes.
func respondedReasoningItem(t *testing.T, body []byte) []byte {
	t.Helper()
	var wire struct {
		Output []json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, wire.Output[0]); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// collectBlocks assembles the blocks a stream carried, the way a
// harness accumulating a streamed turn would.
func collectBlocks(t *testing.T, dec ir.EventDecoder) []ir.Block {
	t.Helper()
	var blocks []ir.Block
	for {
		ev, err := dec.Next()
		if errors.Is(err, io.EOF) {
			return blocks
		}
		if err != nil {
			t.Fatal(err)
		}
		switch ev.Type {
		case ir.EventBlockStart:
			blk := *ev.Block
			if blk.ToolUse != nil {
				tu := *blk.ToolUse
				blk.ToolUse = &tu
			}
			blocks = append(blocks, blk)
		case ir.EventTextDelta, ir.EventThinkingDelta:
			blocks[len(blocks)-1].Text += ev.Delta
		case ir.EventArgsDelta:
			tu := blocks[len(blocks)-1].ToolUse
			tu.Args = append(tu.Args, ev.Delta...)
		}
	}
}

// throughLuxResponse stores a decoded turn the way a harness keeps it,
// as lux response JSON, and reads it back.
func throughLuxResponse(t *testing.T, resp *ir.Response) *ir.Response {
	t.Helper()
	stored, err := lux.NewFrontend().EncodeResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	back, err := lux.NewBackend().DecodeResponse(stored)
	if err != nil {
		t.Fatal(err)
	}
	return back
}

// throughLuxStream carries a backend's events over the lux SSE wire and
// assembles the blocks on the far side.
func throughLuxStream(t *testing.T, dec ir.EventDecoder) []ir.Block {
	t.Helper()
	var buf bytes.Buffer
	enc := lux.NewFrontend().NewEventEncoder(&buf)
	for {
		ev, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	return collectBlocks(t, lux.NewBackend().NewEventDecoder(&buf))
}

// nextTurn is the request that continues the conversation after the
// assistant turn: the tool's result, with the turn replayed as it came.
func nextTurn(assistant []ir.Block) *ir.Request {
	return &ir.Request{
		Model:           "gpt-5.6-sol",
		ReasoningReplay: true,
		Messages: []ir.Message{
			{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "list the files"}}},
			{Role: ir.RoleAssistant, Blocks: assistant},
			{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{
				ToolUseID: "call_Qm3tW9", Blocks: []ir.Block{{Type: ir.BlockText, Text: "a.txt\nb.txt"}},
			}}}},
		},
	}
}

// throughLuxRequest sends the request over the lux wire, as a harness
// behind the gateway would, and decodes it on the gateway's side.
func throughLuxRequest(t *testing.T, req *ir.Request) *ir.Request {
	t.Helper()
	body, err := lux.NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	back, err := lux.NewFrontend().DecodeRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if losses := back.Loss.Strings(); losses != nil {
		t.Fatalf("lux wire lost fields: %v", losses)
	}
	return back
}

// assertReplayed encodes the request for Responses and checks the
// reasoning item comes back as the input item before the function
// call, byte for byte, with an empty loss report.
func assertReplayed(t *testing.T, req *ir.Request, item []byte) {
	t.Helper()
	body, err := openairesp.NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if losses := req.Loss.Strings(); losses != nil {
		t.Fatalf("loss = %v, want none", losses)
	}
	var wire struct {
		Input   []json.RawMessage `json:"input"`
		Include []string          `json:"include"`
		Store   *bool             `json:"store"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Input) != 4 {
		t.Fatalf("input = %s", body)
	}
	if !bytes.Equal(wire.Input[1], item) {
		t.Fatalf("reasoning item not replayed byte for byte:\ngot  %s\nwant %s", wire.Input[1], item)
	}
	var kinds []string
	for _, it := range wire.Input {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(it, &head); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, head.Type)
	}
	if want := []string{"message", "reasoning", "function_call", "function_call_output"}; !slices.Equal(kinds, want) {
		t.Fatalf("input items = %v, want %v", kinds, want)
	}
	if !slices.Contains(wire.Include, "reasoning.encrypted_content") || wire.Store == nil || *wire.Store {
		t.Fatalf("include = %v, store = %v", wire.Include, wire.Store)
	}
}

// A reasoning item decoded from a non-streaming Responses body survives
// the lux wire, stored as a response and sent as a request, and is
// replayed to Responses byte for byte with nothing lost.
func TestOpaqueReasoningReplaysFromResponse(t *testing.T) {
	body := readFixture(t, "reasoning_response.json")
	resp, err := openairesp.NewBackend().DecodeResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	item := respondedReasoningItem(t, body)
	if got := resp.Blocks[1].Opaque; got == nil || !bytes.Equal(got.Raw, item) {
		t.Fatalf("decoded blocks = %+v", resp.Blocks)
	}
	stored := throughLuxResponse(t, resp)
	assertReplayed(t, throughLuxRequest(t, nextTurn(stored.Blocks)), item)
}

// The same holds for the streamed turn, where the item is taken from
// its response.output_item.done frame exactly as the frame carried it.
func TestOpaqueReasoningReplaysFromStream(t *testing.T) {
	sse := readFixture(t, "reasoning_stream.sse")
	blocks := throughLuxStream(t, openairesp.NewBackend().NewEventDecoder(bytes.NewReader(sse)))
	var kinds []ir.BlockType
	for _, b := range blocks {
		kinds = append(kinds, b.Type)
	}
	if want := []ir.BlockType{ir.BlockThinking, ir.BlockOpaque, ir.BlockToolUse}; !slices.Equal(kinds, want) {
		t.Fatalf("streamed blocks = %v, want %v", kinds, want)
	}
	assertReplayed(t, throughLuxRequest(t, nextTurn(blocks)), streamedReasoningItem(t, sse))
}

// Toward another dialect the item is dropped with the loss recorded,
// and nothing of it reaches the body.
func TestOpaqueReasoningDroppedForOtherDialects(t *testing.T) {
	body := readFixture(t, "reasoning_response.json")
	resp, err := openairesp.NewBackend().DecodeResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	var item struct {
		ID               string `json:"id"`
		EncryptedContent string `json:"encrypted_content"`
	}
	if err := json.Unmarshal(respondedReasoningItem(t, body), &item); err != nil {
		t.Fatal(err)
	}
	for _, be := range []Backend{
		anthropic.NewBackend(anthropic.BackendOptions{}),
		openaichat.NewBackend(openaichat.BackendOptions{}),
	} {
		req := nextTurn(resp.Blocks)
		out, err := be.EncodeRequest(req)
		if err != nil {
			t.Fatalf("%s: %v", be.Name(), err)
		}
		if !slices.Contains(req.Loss.Fields(), ir.LossOpaque) {
			t.Errorf("%s: loss = %v, want %q", be.Name(), req.Loss.Strings(), ir.LossOpaque)
		}
		for _, trace := range []string{item.ID, item.EncryptedContent, "encrypted_content"} {
			if strings.Contains(string(out), trace) {
				t.Errorf("%s: body carries %q:\n%s", be.Name(), trace, out)
			}
		}
	}
}

// responsesTranslator is a Responses client in front of a Responses
// upstream, the path a Responses client of the gateway takes to an
// OpenAI reasoning model.
func responsesTranslator() *Translator {
	return &Translator{Frontend: openairesp.NewFrontend(), Backend: openairesp.NewBackend()}
}

// clientTurn is the Responses request that continues the conversation
// after an assistant turn the client got back: the prior output items
// as they came, then the tool's result. The first item is indented and
// holds a <, as a client may write it, so the decoder has to bring it
// into the form ir.Opaque documents.
func clientTurn(t *testing.T, items ...json.RawMessage) []byte {
	t.Helper()
	input := []json.RawMessage{json.RawMessage(`{"type":"message","role":"user","content":"list the files"}`)}
	input = append(input, items...)
	input = append(input, json.RawMessage(`{"type":"function_call_output","call_id":"call_Qm3tW9","output":"a.txt\nb.txt"}`))
	body, err := json.Marshal(map[string]any{
		"model":   "gpt-5.6-sol",
		"include": []string{"reasoning.encrypted_content"},
		"input":   input,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// indentedItem is a reasoning item written by a client with indentation
// and a < in its summary; canonicalItem is the same item in the form
// ir.Opaque documents.
const (
	indentedItem = `{
		"id": "rs_1",
		"type": "reasoning",
		"summary": [{"type": "summary_text", "text": "a < b"}],
		"encrypted_content": "gAAAAABo"
	}`
	canonicalItem = `{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"a \u003c b"}],"encrypted_content":"gAAAAABo"}`
)

var priorCall = json.RawMessage(`{"type":"function_call","call_id":"call_Qm3tW9","name":"shell","arguments":"{\"cmd\":\"ls\"}"}`)

// A Responses client's request that asks for encrypted reasoning and
// carries a prior reasoning item reaches a Responses upstream with the
// ask and the item: include and store false upstream, the item in its
// input where the client put it, with nothing lost.
func TestResponsesClientReplaysReasoningUpstream(t *testing.T) {
	out, req, err := responsesTranslator().Request(clientTurn(t, json.RawMessage(indentedItem), priorCall))
	if err != nil {
		t.Fatal(err)
	}
	if losses := req.Loss.Strings(); losses != nil {
		t.Fatalf("loss = %v, want none", losses)
	}
	var wire struct {
		Input   []json.RawMessage `json:"input"`
		Include []string          `json:"include"`
		Store   *bool             `json:"store"`
	}
	if err := json.Unmarshal(out, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Input) != 4 || string(wire.Input[1]) != canonicalItem {
		t.Fatalf("upstream input = %s", out)
	}
	if !slices.Equal(wire.Include, []string{"reasoning.encrypted_content"}) || wire.Store == nil || *wire.Store {
		t.Fatalf("include = %v, store = %v", wire.Include, wire.Store)
	}
}

// A reasoning item an upstream returns reaches the Responses client as
// the output item it was, byte for byte, alone (its summary travels
// inside it), and the client's next request replays it upstream
// unchanged: Responses in, Responses out keeps the reasoning across
// turns.
func TestResponsesClientKeepsReasoningFromResponse(t *testing.T) {
	body := readFixture(t, "reasoning_response.json")
	client, err := responsesTranslator().Response(body)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Output []json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(client, &wire); err != nil {
		t.Fatal(err)
	}
	item := respondedReasoningItem(t, body)
	if len(wire.Output) != 2 || !bytes.Equal(wire.Output[0], item) {
		t.Fatalf("client output = %s\nwant the reasoning item %s first, then the call", client, item)
	}
	assertReplayedFromClient(t, wire.Output, item)
}

// The same holds for a streamed turn: the reasoning item's
// output_item.done frame to the client carries the item exactly as the
// upstream frame did, response.completed lists it once, and the next
// request replays it.
func TestResponsesClientKeepsReasoningFromStream(t *testing.T) {
	sse := readFixture(t, "reasoning_stream.sse")
	var buf bytes.Buffer
	if err := responsesTranslator().Stream(&buf, bytes.NewReader(sse)); err != nil {
		t.Fatal(err)
	}
	item := streamedReasoningItem(t, sse)
	if got := streamedReasoningItem(t, buf.Bytes()); !bytes.Equal(got, item) {
		t.Fatalf("client done frame item = %s\nwant %s", got, item)
	}
	var output []json.RawMessage
	for line := range strings.SplitSeq(buf.String(), "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var frame struct {
			Type     string `json:"type"`
			Response struct {
				Output []json.RawMessage `json:"output"`
			} `json:"response"`
		}
		if err := json.Unmarshal([]byte(data), &frame); err != nil {
			t.Fatal(err)
		}
		if frame.Type == "response.completed" {
			output = frame.Response.Output
		}
	}
	if len(output) != 2 || !bytes.Equal(output[0], item) {
		t.Fatalf("completed output = %s", output)
	}
	assertReplayedFromClient(t, output, item)
}

// assertReplayedFromClient sends the client's output items back as the
// next request's input and checks the upstream gets the reasoning item
// byte for byte, with nothing lost.
func assertReplayedFromClient(t *testing.T, output []json.RawMessage, item []byte) {
	t.Helper()
	out, req, err := responsesTranslator().Request(clientTurn(t, output...))
	if err != nil {
		t.Fatal(err)
	}
	if losses := req.Loss.Strings(); losses != nil {
		t.Fatalf("next turn loss = %v, want none", losses)
	}
	var wire struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(out, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Input) != 4 || !bytes.Equal(wire.Input[1], item) {
		t.Fatalf("next turn upstream input = %s\nwant the reasoning item %s second", out, item)
	}
}

// Toward an upstream of another dialect the client's reasoning item is
// dropped as an opaque block and reported, and nothing of it reaches
// the body. The replay ask needs nothing on the Messages side, whose
// thinking blocks carry their signatures, and is reported on the Chat
// side, which has no replayable reasoning.
func TestResponsesClientReasoningToOtherDialects(t *testing.T) {
	for _, tc := range []struct {
		be   Backend
		loss []ir.LossField
	}{
		{anthropic.NewBackend(anthropic.BackendOptions{}), []ir.LossField{ir.LossOpaque}},
		{openaichat.NewBackend(openaichat.BackendOptions{}), []ir.LossField{ir.LossOpaque, ir.LossReasoningReplay}},
	} {
		tr := &Translator{Frontend: openairesp.NewFrontend(), Backend: tc.be}
		out, req, err := tr.Request(clientTurn(t, json.RawMessage(indentedItem), priorCall))
		if err != nil {
			t.Fatalf("%s: %v", tc.be.Name(), err)
		}
		got := req.Loss.Fields()
		slices.Sort(got)
		if !slices.Equal(got, tc.loss) {
			t.Errorf("%s: loss = %v, want %v", tc.be.Name(), got, tc.loss)
		}
		for _, trace := range []string{"rs_1", "gAAAAABo", "encrypted_content"} {
			if strings.Contains(string(out), trace) {
				t.Errorf("%s: body carries %q:\n%s", tc.be.Name(), trace, out)
			}
		}
	}
}

// A reasoning item without encrypted_content names an item only the
// upstream's store could resolve; the surface stores nothing, so the
// item is reported lost rather than sent to be rejected.
func TestResponsesClientReasoningWithoutContent(t *testing.T) {
	out, req, err := responsesTranslator().Request(clientTurn(t,
		json.RawMessage(`{"id":"rs_2","type":"reasoning","summary":[]}`), priorCall))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Loss.Fields(); !slices.Equal(got, []ir.LossField{ir.LossReasoningItems}) {
		t.Fatalf("loss = %v, want %v", got, ir.LossReasoningItems)
	}
	if strings.Contains(string(out), "rs_2") {
		t.Fatalf("upstream body carries the item:\n%s", out)
	}
}
