package tokencount

import (
	"encoding/json"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func TestEstimateProse(t *testing.T) {
	// ~2000 bytes of prose ≈ 500 tokens; assert the right order of
	// magnitude, not an exact figure.
	text := strings.Repeat("the quick brown fox jumps over the lazy dog ", 45) // ~2025 bytes
	req := &ir.Request{
		System:   []ir.Block{{Type: ir.BlockText, Text: "be brief"}},
		Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: text}}}},
	}
	got := Estimate(req)
	if got < 300 || got > 800 {
		t.Fatalf("estimate = %d, want roughly 500", got)
	}
}

func TestEstimateCoversAllBlockKinds(t *testing.T) {
	req := &ir.Request{
		Messages: []ir.Message{
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockThinking, Text: "let me think about this"},
				{Type: ir.BlockRedactedThinking, Redacted: strings.Repeat("x", 400)},
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{Name: "bash", Args: json.RawMessage(`{"cmd":"ls -la"}`)}},
			}},
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockImage, Image: &ir.Image{URL: "https://x/y.png"}},
				{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{Blocks: []ir.Block{{Type: ir.BlockText, Text: "output text"}}}},
				{Type: "unknown"},
			}},
		},
		Tools: []ir.Tool{{Name: "bash", Description: "run a command", InputSchema: json.RawMessage(`{"type":"object","properties":{"cmd":{"type":"string"}}}`)}},
	}
	got := Estimate(req)
	// Image dominates: at least the flat image cost plus overheads.
	if got < perImageCost {
		t.Fatalf("estimate = %d, want >= image cost %d", got, perImageCost)
	}
}

func TestEstimateNeverZero(t *testing.T) {
	if got := Estimate(&ir.Request{}); got != 1 {
		t.Fatalf("empty request estimate = %d, want 1", got)
	}
	// Tiny text still counts at least one token.
	req := &ir.Request{Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}}}}}
	if got := Estimate(req); got < 1 {
		t.Fatalf("tiny estimate = %d", got)
	}
}
