// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package tokencount estimates the input token count of an IR request
// without a model tokenizer. It exists for count_tokens emulation when
// the backend dialect has no counting endpoint: the estimate targets
// the right order of magnitude (harness context-window bookkeeping),
// not billing accuracy — metering always uses the backend's reported
// usage, never this.
package tokencount

import (
	"latere.ai/x/pkg/llmdialect/ir"
)

// Heuristics: ~4 bytes of prose per token (English-biased; JSON and
// code run denser), a small per-message and per-tool framing overhead,
// and a flat charge per image (Anthropic bills a resized image at up
// to ~1590 tokens; most land lower).
const (
	bytesPerToken   = 4
	perMessageCost  = 5
	perToolCost     = 8
	perImageCost    = 1200
	perThinkingCost = 2
)

// Estimate returns the approximate input token count for req.
func Estimate(req *ir.Request) int64 {
	var total int64
	for _, blk := range req.System {
		total += blockTokens(blk)
	}
	for _, msg := range req.Messages {
		total += perMessageCost
		for _, blk := range msg.Blocks {
			total += blockTokens(blk)
		}
	}
	for _, tool := range req.Tools {
		total += perToolCost
		total += textTokens(tool.Name) + textTokens(tool.Description)
		total += int64(len(tool.InputSchema)) / bytesPerToken
	}
	if total == 0 {
		total = 1
	}
	return total
}

func blockTokens(blk ir.Block) int64 {
	switch blk.Type {
	case ir.BlockText:
		return textTokens(blk.Text)
	case ir.BlockThinking:
		return perThinkingCost + textTokens(blk.Text)
	case ir.BlockRedactedThinking:
		return int64(len(blk.Redacted)) / bytesPerToken
	case ir.BlockImage:
		return perImageCost
	case ir.BlockToolUse:
		return perToolCost + textTokens(blk.ToolUse.Name) + int64(len(blk.ToolUse.Args))/bytesPerToken
	case ir.BlockToolResult:
		var total int64 = perToolCost
		for _, inner := range blk.ToolResult.Blocks {
			total += blockTokens(inner)
		}
		return total
	}
	return 0
}

func textTokens(s string) int64 {
	if s == "" {
		return 0
	}
	n := int64(len(s)) / bytesPerToken
	if n == 0 {
		n = 1
	}
	return n
}
