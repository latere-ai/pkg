// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// benchSizes maps a payload class to the number of conversation turns and
// tool definitions in the request body it produces.
var benchSizes = []struct {
	name             string
	turns, tool, pct int
}{
	{"small", 1, 1, 12},
	{"medium", 8, 4, 60},
	{"large", 115, 20, 100},
}

const benchSentence = "The deployment finished without errors, but the readiness probe on the second replica kept flapping until the connection pool was drained and the migration lock was released. "

func benchText(n int, seed int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "%s(%d) ", benchSentence, seed+i)
	}
	return b.String()[:n]
}

func benchRequest(turns, tools, pct int) *ir.Request {
	sc := func(n int) int { return n * pct / 100 }
	maxTokens := int64(8192)
	temp := 0.2
	req := &ir.Request{
		Model:       "claude-sonnet-5-5",
		System:      []ir.Block{{Type: ir.BlockText, Text: benchText(sc(300), 1)}},
		MaxTokens:   &maxTokens,
		Temperature: &temp,
		Stream:      true,
		UserID:      "user_01HZX3K9Q2",
	}
	for i := range tools {
		req.Tools = append(req.Tools, ir.Tool{
			Name:        fmt.Sprintf("tool_%02d", i),
			Description: benchText(sc(200), 100+i),
			InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"File path relative to the workspace root"},"query":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":500},"flags":{"type":"array","items":{"type":"string"}}},"required":["path"]}`),
		})
	}
	for i := range turns {
		id := fmt.Sprintf("toolu_%04d", i)
		req.Messages = append(req.Messages,
			ir.Message{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: benchText(sc(400), 1000+i)}}},
			ir.Message{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockText, Text: benchText(sc(300), 2000+i)},
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: id, Name: "tool_00", Args: json.RawMessage(fmt.Sprintf(`{"path":"internal/svc/handler_%d.go","limit":200}`, i))}},
			}},
			ir.Message{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: id, Blocks: []ir.Block{{Type: ir.BlockText, Text: benchText(sc(600), 3000+i)}}}},
			}},
		)
	}
	req.Messages = append(req.Messages, ir.Message{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "Continue."}}})
	return req
}

func benchResponse(textLen int) *ir.Response {
	cr := int64(1200)
	return &ir.Response{
		ID:    "msg_01XFDUDYJgAACzvnptvVoYEL",
		Model: "claude-sonnet-5-5",
		Blocks: []ir.Block{
			{Type: ir.BlockText, Text: benchText(textLen, 7)},
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "toolu_01A09q90qw90lq917835lq9", Name: "tool_00", Args: json.RawMessage(`{"path":"internal/svc/handler.go","limit":200}`)}},
		},
		StopReason: ir.StopToolUse,
		Usage:      ir.Usage{InputTokens: 2048, OutputTokens: 311, CacheReadInputTokens: &cr},
	}
}

func benchEvents(deltas int) []ir.Event {
	evs := []ir.Event{{Type: ir.EventMessageStart, ID: "msg_01XFDUDYJgAACzvnptvVoYEL", Model: "claude-sonnet-5-5", Usage: &ir.Usage{InputTokens: 2048}}}
	evs = append(evs, ir.Event{Type: ir.EventBlockStart, Index: 0, Block: &ir.Block{Type: ir.BlockText}})
	for i := range deltas {
		evs = append(evs, ir.Event{Type: ir.EventTextDelta, Index: 0, Delta: fmt.Sprintf("token%d ", i)})
	}
	evs = append(evs,
		ir.Event{Type: ir.EventBlockStop, Index: 0},
		ir.Event{Type: ir.EventBlockStart, Index: 1, Block: &ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "toolu_01A09q90qw90lq917835lq9", Name: "tool_00"}}},
	)
	for _, part := range []string{`{"path":`, `"internal/svc/`, `handler.go",`, `"limit":200}`} {
		evs = append(evs, ir.Event{Type: ir.EventArgsDelta, Index: 1, Delta: part})
	}
	evs = append(evs,
		ir.Event{Type: ir.EventBlockStop, Index: 1},
		ir.Event{Type: ir.EventMessageDelta, StopReason: ir.StopToolUse, Usage: &ir.Usage{InputTokens: 2048, OutputTokens: int64(deltas)}},
		ir.Event{Type: ir.EventMessageStop},
	)
	return evs
}

// benchStream renders evs through the frontend's SSE encoder.
func benchStream(b *testing.B, evs []ir.Event) []byte {
	b.Helper()
	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	for _, ev := range evs {
		if err := enc.Encode(ev); err != nil {
			b.Fatal(err)
		}
	}
	return buf.Bytes()
}

// BenchmarkJSONMessagesRequestEncode is the gateway building the upstream
// Messages body for an inference call.
func BenchmarkJSONMessagesRequestEncode(b *testing.B) {
	for _, sz := range benchSizes {
		b.Run(sz.name, func(b *testing.B) {
			be := NewBackend(BackendOptions{})
			req := benchRequest(sz.turns, sz.tool, sz.pct)
			body, err := be.EncodeRequest(req)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				if _, err := be.EncodeRequest(req); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkJSONMessagesRequestDecode is the gateway reading a caller's
// Messages request body into the IR.
func BenchmarkJSONMessagesRequestDecode(b *testing.B) {
	for _, sz := range benchSizes {
		b.Run(sz.name, func(b *testing.B) {
			body, err := NewBackend(BackendOptions{}).EncodeRequest(benchRequest(sz.turns, sz.tool, sz.pct))
			if err != nil {
				b.Fatal(err)
			}
			fe := NewFrontend()
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				if _, err := fe.DecodeRequest(body); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkJSONMessagesResponseEncode is the gateway answering a caller
// with a non-streaming Messages response.
func BenchmarkJSONMessagesResponseEncode(b *testing.B) {
	for _, sz := range []struct {
		name string
		n    int
	}{{"small", 300}, {"medium", 8000}} {
		b.Run(sz.name, func(b *testing.B) {
			fe := NewFrontend()
			resp := benchResponse(sz.n)
			body, err := fe.EncodeResponse(resp)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				if _, err := fe.EncodeResponse(resp); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkJSONMessagesResponseDecode is the gateway parsing the upstream
// non-streaming Messages response.
func BenchmarkJSONMessagesResponseDecode(b *testing.B) {
	for _, sz := range []struct {
		name string
		n    int
	}{{"small", 300}, {"medium", 8000}} {
		b.Run(sz.name, func(b *testing.B) {
			body, err := NewFrontend().EncodeResponse(benchResponse(sz.n))
			if err != nil {
				b.Fatal(err)
			}
			be := NewBackend(BackendOptions{})
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				if _, err := be.DecodeResponse(body); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkJSONMessagesStreamEncode is the gateway writing a streamed
// response to the caller, one SSE frame set per IR event.
func BenchmarkJSONMessagesStreamEncode(b *testing.B) {
	evs := benchEvents(300)
	fe := NewFrontend()
	size := len(benchStream(b, evs))
	b.ReportAllocs()
	b.SetBytes(int64(size))
	for b.Loop() {
		enc := fe.NewEventEncoder(io.Discard)
		for _, ev := range evs {
			if err := enc.Encode(ev); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkJSONMessagesStreamDecode is the gateway reading the upstream SSE
// stream into IR events.
func BenchmarkJSONMessagesStreamDecode(b *testing.B) {
	stream := benchStream(b, benchEvents(300))
	be := NewBackend(BackendOptions{})
	b.ReportAllocs()
	b.SetBytes(int64(len(stream)))
	for b.Loop() {
		dec := be.NewEventDecoder(bytes.NewReader(stream))
		n := 0
		for {
			_, err := dec.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
			n++
		}
		if n == 0 {
			b.Fatal("no events decoded")
		}
	}
}
