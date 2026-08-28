package anthropic

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func TestBackendEncodeImagesInUserAndToolResult(t *testing.T) {
	req := &ir.Request{
		Model: "m",
		Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{
			{Type: ir.BlockImage, Image: &ir.Image{MediaType: "image/png", Data: "AA"}, CacheHint: true},
			{Type: ir.BlockImage, Image: &ir.Image{URL: "https://x/y.png"}},
		}}},
	}
	got := encodeBack(t, req, BackendOptions{})
	content := got["messages"].([]any)[0].(map[string]any)["content"].([]any)
	b64 := content[0].(map[string]any)
	src := b64["source"].(map[string]any)
	if src["type"] != "base64" || src["media_type"] != "image/png" || b64["cache_control"] == nil {
		t.Fatalf("base64 image wrong: %v", b64)
	}
	url := content[1].(map[string]any)["source"].(map[string]any)
	if url["type"] != "url" || url["url"] != "https://x/y.png" {
		t.Fatalf("url image wrong: %v", url)
	}
}

func TestBackendEncodeUnknownBlockError(t *testing.T) {
	req := &ir.Request{Model: "m", Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: "weird"}}}}}
	if _, err := NewBackend(BackendOptions{}).EncodeRequest(req); err == nil {
		t.Fatal("want error for unknown block type")
	}
}

func TestBackendEncodeToolChoiceModes(t *testing.T) {
	for mode, wire := range map[ir.ToolChoiceMode]string{
		ir.ToolChoiceAuto: "auto", ir.ToolChoiceAny: "any", ir.ToolChoiceNone: "none",
	} {
		req := &ir.Request{Model: "m", ToolChoice: &ir.ToolChoice{Mode: mode},
			Messages: []ir.Message{userMsg("x")}}
		got := encodeBack(t, req, BackendOptions{})
		if got["tool_choice"].(map[string]any)["type"] != wire {
			t.Fatalf("%s → %v", mode, got["tool_choice"])
		}
	}
}

func TestBackendDecodeResponseStopSequenceAndUnknownBlock(t *testing.T) {
	body := `{
		"id": "msg_2", "model": "c",
		"content": [
			{"type": "server_tool_use", "id": "x"},
			{"type": "text", "text": "hi"}
		],
		"stop_reason": "stop_sequence", "stop_sequence": "END",
		"usage": {"input_tokens": 1, "output_tokens": 1}
	}`
	resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StopReason != ir.StopStopSequence || resp.StopSequence != "END" {
		t.Fatalf("stop wrong: %+v", resp)
	}
	if len(resp.Blocks) != 1 || resp.Blocks[0].Text != "hi" {
		t.Fatalf("unknown block must be skipped: %+v", resp.Blocks)
	}
}

func TestBackendEventDecoderMalformedFrames(t *testing.T) {
	cases := map[string]string{
		"start missing message":     anthropicSSE([2]string{"message_start", `{"type":"message_start"}`}),
		"block start missing block": anthropicSSE([2]string{"content_block_start", `{"type":"content_block_start","index":0}`}),
		"error without body":        anthropicSSE([2]string{"error", `{"type":"error"}`}),
	}
	for name, stream := range cases {
		dec := NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader(stream))
		var err error
		for err == nil {
			_, err = dec.Next()
		}
		if err.Error() == "EOF" {
			t.Fatalf("%s: want error, got clean EOF", name)
		}
	}
}

func TestBackendEventDecoderTolerantFrames(t *testing.T) {
	// Nil deltas, unknown delta types, unknown block types, and pings
	// must not break the stream.
	stream := anthropicSSE(
		[2]string{"message_start", `{"type":"message_start","message":{"id":"m","model":"c","usage":{"input_tokens":1}}}`},
		[2]string{"ping", `{"type":"ping"}`},
		[2]string{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","id":"x"}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":0}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"citations_delta"}}`},
		[2]string{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		[2]string{"message_delta", `{"type":"message_delta"}`},
		[2]string{"message_stop", `{"type":"message_stop"}`},
	)
	events := drainBackend(t, stream)
	// The unknown block header degrades to a text block.
	if events[1].Type != ir.EventBlockStart || events[1].Block.Type != ir.BlockText {
		t.Fatalf("unknown block fallback wrong: %+v", events[1])
	}
	last := events[len(events)-1]
	if last.Type != ir.EventMessageStop {
		t.Fatalf("tail wrong: %+v", events)
	}
}

type failSink struct{}

func (failSink) Write([]byte) (int, error) { return 0, errors.New("sink closed") }

func TestEventEncoderWriteError(t *testing.T) {
	enc := NewFrontend().NewEventEncoder(failSink{})
	if err := enc.Encode(ir.Event{Type: ir.EventMessageStop}); err == nil {
		t.Fatal("want write error")
	}
}

func TestBackendEncodeEmptyToolArgs(t *testing.T) {
	req := &ir.Request{
		Model: "m",
		Messages: []ir.Message{{Role: ir.RoleAssistant, Blocks: []ir.Block{
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t", Name: "f"}},
		}}},
	}
	got := encodeBack(t, req, BackendOptions{})
	tu := got["messages"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if !jsonEqual(tu["input"], map[string]any{}) {
		t.Fatalf("empty args wrong: %v", tu)
	}
}

func jsonEqual(got any, want map[string]any) bool {
	raw, _ := json.Marshal(got)
	var m map[string]any
	return json.Unmarshal(raw, &m) == nil && len(m) == len(want)
}

// TestEncodeRequestReportsLogProbsAsLoss: the Messages API has no
// logprobs member, so an ask reaches the loss report rather than the
// upstream body. A gateway surfaces that report; silently dropping it
// would tell a caller their request was served whole.
func TestEncodeRequestReportsLogProbsAsLoss(t *testing.T) {
	req := &ir.Request{
		Model:       "claude-sonnet-5",
		Messages:    []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}}}},
		LogProbs:    true,
		TopLogProbs: 3,
	}
	raw, err := NewBackend(BackendOptions{DefaultMaxTokens: 16}).EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "logprobs") {
		t.Fatalf("a member this dialect does not have reached the body: %s", raw)
	}
	got := req.Loss.Strings()
	if !slices.Contains(got, "logprobs") || !slices.Contains(got, "top_logprobs") {
		t.Fatalf("loss = %v, want both members", got)
	}
}
