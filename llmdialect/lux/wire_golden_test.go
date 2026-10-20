// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package lux

import (
	"bytes"
	"encoding/json"
	"flag"
	"math"
	"os"
	"path/filepath"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

var updateWire = flag.Bool("update-wire", false, "rewrite testdata/wire_golden.txt from the codec")

// TestWireBytesAreUnchanged holds the lux wire format to the bytes the codec
// wrote before its types moved into the SDK: a request and a response that
// set every field, each decoded back to the IR and re-encoded, and an SSE
// frame of every event type. The golden was written by this test on the
// codec as it stood before the move, so a renamed, reordered or retagged
// field, a changed omitempty, or a LogProb that stops writing null fails it.
func TestWireBytesAreUnchanged(t *testing.T) {
	var out bytes.Buffer
	maxTokens, topK := int64(256), int64(40)
	temperature, topP := 0.5, 0.9
	read, write, cost := int64(0), int64(7), int64(12)
	req := Request{
		Model:  "anthropic/claude-sonnet-4.5",
		System: []Block{{Type: ir.BlockText, Text: "Be brief.", CacheHint: true}},
		Messages: []Message{
			{Role: ir.RoleUser, Blocks: []Block{
				{Type: ir.BlockText, Text: "Hi"},
				{Type: ir.BlockImage, Image: &Image{MediaType: "image/png", Data: "aGk="}},
				{Type: ir.BlockToolResult, ToolResult: &ToolResult{ToolUseID: "tu_0", IsError: true, Blocks: []Block{{Type: ir.BlockText, Text: "no"}}}},
			}},
			{Role: ir.RoleAssistant, Blocks: []Block{
				{Type: ir.BlockThinking, Text: "hm", Signature: "sig"},
				{Type: ir.BlockRedactedThinking, Redacted: "xx"},
				{Type: ir.BlockOpaque, Opaque: &Opaque{Dialect: ir.DialectOpenAIResponses, Kind: "reasoning", Raw: json.RawMessage(`{"id":"rs_1"}`)}},
				{Type: ir.BlockToolUse, ToolUse: &ToolUse{ID: "tu_1", Name: "bash", Args: json.RawMessage(`{"cmd":"ls"}`)}},
			}},
		},
		Tools:           []Tool{{Name: "bash", Description: "run", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		ServerTools:     []ServerTool{{Type: "web_search", Name: "search", Config: json.RawMessage(`{"max_uses":2}`)}},
		ToolChoice:      &ToolChoice{Mode: ir.ToolChoiceTool, Name: "bash", DisableParallel: true},
		MaxTokens:       &maxTokens,
		Temperature:     &temperature,
		TopP:            &topP,
		TopK:            &topK,
		StopSequences:   []string{"END"},
		Stream:          true,
		Reasoning:       &Reasoning{Effort: ir.EffortHigh},
		Schema:          &ResponseSchema{Name: "answer", Description: "d", Schema: json.RawMessage(`{"type":"object"}`), Strict: true},
		WebSearch:       &WebSearch{ContextSize: "low", UserLocation: json.RawMessage(`{"country":"DE"}`)},
		UserID:          "u_1",
		CacheKey:        "k",
		LogProbs:        true,
		TopLogProbs:     2,
		ReasoningReplay: true,
	}
	reqJSON, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	out.WriteString("request: ")
	out.Write(reqJSON)
	out.WriteByte('\n')
	if _, err := NewFrontend().DecodeRequest(reqJSON); err != nil {
		t.Fatalf("the codec refused its own request: %v", err)
	}

	resp := &ir.Response{
		ID: "msg_1", Model: "m", StopReason: ir.StopStopSequence, StopSequence: "END",
		Blocks: []ir.Block{
			{Type: ir.BlockText, Text: "Hello"},
			{Type: ir.BlockThinking, Text: "hm", Signature: "sig"},
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "tu_1", Name: "bash", Args: json.RawMessage(`{"cmd":"ls"}`)}},
		},
		Usage: ir.Usage{InputTokens: 3, OutputTokens: 4, CacheReadInputTokens: &read, CacheWriteInputTokens: &write, ReasoningTokens: 2, CostUSDMicro: &cost},
		LogProbs: []ir.TokenLogProb{
			{Token: "He", Bytes: []byte("He"), LogProb: ir.LogProb(math.Inf(-1)), Top: []ir.TokenLogProb{{Token: "Hi", LogProb: -0.5}}},
			{Token: "llo", LogProb: -0.25},
		},
	}
	respJSON, err := NewFrontend().EncodeResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	out.WriteString("response: ")
	out.Write(bytes.TrimSpace(respJSON))
	out.WriteByte('\n')

	enc := NewFrontend().NewEventEncoder(&out)
	for _, ev := range []ir.Event{
		{Type: ir.EventMessageStart, ID: "msg_1", Model: "m", Usage: &ir.Usage{InputTokens: 9}},
		{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "tu_1", Name: "bash"}}},
		{Type: ir.EventArgsDelta, Index: 0, Delta: `{"cmd":`},
		{Type: ir.EventBlockStop, Index: 0},
		{Type: ir.EventBlockStart, Index: 1, Block: &ir.Block{Type: ir.BlockThinking}},
		{Type: ir.EventThinkingDelta, Index: 1, Delta: "hm"},
		{Type: ir.EventSignatureDelta, Index: 1, Delta: "sig"},
		{Type: ir.EventBlockStop, Index: 1},
		{Type: ir.EventBlockStart, Index: 2, Block: &ir.Block{Type: ir.BlockText}},
		{Type: ir.EventTextDelta, Index: 2, Delta: "Hel", LogProbs: []ir.TokenLogProb{{Token: "Hel", LogProb: ir.LogProb(math.Inf(-1))}}},
		{Type: ir.EventBlockStop, Index: 2},
		{Type: ir.EventMessageDelta, StopReason: ir.StopToolUse, Usage: &ir.Usage{OutputTokens: 7, CostUSDMicro: &cost}},
		{Type: ir.EventMessageStop},
	} {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}

	golden := filepath.Join("testdata", "wire_golden.txt")
	if *updateWire {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("the wire bytes changed:\n got: %s\nwant: %s", out.Bytes(), want)
	}
}
