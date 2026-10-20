// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package lux

// The lux wire vocabulary is the public Lux dialect, defined once in
// latere.ai/x/sdk-go/llm/wire and aliased here, so the gateway's codec and
// the SDK's client read and write the same types and cannot drift. The IR's
// structs stay free to evolve; the conversions in this file absorb the
// difference.

import (
	"bytes"
	"encoding/json"
	"fmt"

	"latere.ai/x/sdk-go/llm/wire"

	"latere.ai/x/pkg/llmdialect/ir"
)

// The wire types, by their lux names.
type (
	Request        = wire.Request
	TokenLogProb   = wire.TokenLogProb
	Message        = wire.Message
	Block          = wire.Block
	Opaque         = wire.Opaque
	Image          = wire.Image
	ToolUse        = wire.ToolUse
	ToolResult     = wire.ToolResult
	Tool           = wire.Tool
	ServerTool     = wire.ServerTool
	WebSearch      = wire.WebSearch
	ToolChoice     = wire.ToolChoice
	Reasoning      = wire.Reasoning
	ResponseSchema = wire.ResponseSchema
	Usage          = wire.Usage
	Response       = wire.Response
	Event          = wire.Event
)

// validEventTypes is the closed set of event names on the wire.
var validEventTypes = map[ir.EventType]bool{
	ir.EventMessageStart:   true,
	ir.EventBlockStart:     true,
	ir.EventTextDelta:      true,
	ir.EventArgsDelta:      true,
	ir.EventThinkingDelta:  true,
	ir.EventSignatureDelta: true,
	ir.EventBlockStop:      true,
	ir.EventMessageDelta:   true,
	ir.EventMessageStop:    true,
}

// blockToIR converts a wire block. Unknown block types land in the
// loss report and return ok=false; malformed known types error.
func blockToIR(b Block, loss *ir.Loss) (ir.Block, bool, error) {
	switch b.Type {
	case ir.BlockText:
		return ir.Block{Type: ir.BlockText, Text: b.Text, CacheHint: b.CacheHint}, true, nil
	case ir.BlockImage:
		if b.Image == nil {
			return ir.Block{}, false, fmt.Errorf("image block missing image payload")
		}
		if b.Image.Data == "" && b.Image.URL == "" {
			return ir.Block{}, false, fmt.Errorf("image block needs data or url")
		}
		img := *b.Image
		return ir.Block{Type: ir.BlockImage, Image: &ir.Image{MediaType: img.MediaType, Data: img.Data, URL: img.URL}, CacheHint: b.CacheHint}, true, nil
	case ir.BlockToolUse:
		if b.ToolUse == nil {
			return ir.Block{}, false, fmt.Errorf("tool_use block missing tool_use payload")
		}
		return ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: b.ToolUse.ID, Name: b.ToolUse.Name, Args: b.ToolUse.Args}, CacheHint: b.CacheHint}, true, nil
	case ir.BlockToolResult:
		if b.ToolResult == nil {
			return ir.Block{}, false, fmt.Errorf("tool_result block missing tool_result payload")
		}
		var inner []ir.Block
		for _, ib := range b.ToolResult.Blocks {
			blk, ok, err := blockToIR(ib, loss)
			if err != nil {
				return ir.Block{}, false, fmt.Errorf("tool_result content: %w", err)
			}
			if ok {
				inner = append(inner, blk)
			}
		}
		return ir.Block{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: b.ToolResult.ToolUseID, Blocks: inner, IsError: b.ToolResult.IsError}, CacheHint: b.CacheHint}, true, nil
	case ir.BlockThinking:
		return ir.Block{Type: ir.BlockThinking, Text: b.Text, Signature: b.Signature}, true, nil
	case ir.BlockRedactedThinking:
		return ir.Block{Type: ir.BlockRedactedThinking, Redacted: b.Redacted}, true, nil
	case ir.BlockOpaque:
		op, err := opaqueToIR(b.Opaque)
		if err != nil {
			return ir.Block{}, false, err
		}
		return ir.Block{Type: ir.BlockOpaque, Opaque: op, CacheHint: b.CacheHint}, true, nil
	default:
		loss.Add(ir.LossContentTypeOf(string(b.Type)))
		return ir.Block{}, false, nil
	}
}

// opaqueToIR validates a wire opaque payload and brings Raw into the
// form ir.Opaque documents, so a body written by another JSON encoder
// (indented, say) decodes to the same IR as the one this codec wrote.
func opaqueToIR(o *Opaque) (*ir.Opaque, error) {
	if o == nil {
		return nil, fmt.Errorf("opaque block missing opaque payload")
	}
	if o.Dialect == "" {
		return nil, fmt.Errorf("opaque block needs a dialect")
	}
	if len(o.Raw) == 0 {
		return nil, fmt.Errorf("opaque block needs raw")
	}
	raw, err := json.Marshal(o.Raw)
	if err != nil {
		return nil, fmt.Errorf("opaque block raw: %w", err)
	}
	return &ir.Opaque{Dialect: o.Dialect, Kind: o.Kind, Raw: raw}, nil
}

// blockFromIR converts an IR block to the wire. The lux dialect is the
// IR, so every IR block is representable; an unknown type is a
// programming error.
func blockFromIR(b ir.Block) (Block, error) {
	switch b.Type {
	case ir.BlockText:
		return Block{Type: ir.BlockText, Text: b.Text, CacheHint: b.CacheHint}, nil
	case ir.BlockImage:
		if b.Image == nil {
			return Block{}, fmt.Errorf("image block missing image payload")
		}
		return Block{Type: ir.BlockImage, Image: &Image{MediaType: b.Image.MediaType, Data: b.Image.Data, URL: b.Image.URL}, CacheHint: b.CacheHint}, nil
	case ir.BlockToolUse:
		if b.ToolUse == nil {
			return Block{}, fmt.Errorf("tool_use block missing tool_use payload")
		}
		return Block{Type: ir.BlockToolUse, ToolUse: &ToolUse{ID: b.ToolUse.ID, Name: b.ToolUse.Name, Args: b.ToolUse.Args}, CacheHint: b.CacheHint}, nil
	case ir.BlockToolResult:
		if b.ToolResult == nil {
			return Block{}, fmt.Errorf("tool_result block missing tool_result payload")
		}
		var inner []Block
		for _, ib := range b.ToolResult.Blocks {
			blk, err := blockFromIR(ib)
			if err != nil {
				return Block{}, fmt.Errorf("tool_result content: %w", err)
			}
			inner = append(inner, blk)
		}
		return Block{Type: ir.BlockToolResult, ToolResult: &ToolResult{ToolUseID: b.ToolResult.ToolUseID, Blocks: inner, IsError: b.ToolResult.IsError}, CacheHint: b.CacheHint}, nil
	case ir.BlockThinking:
		return Block{Type: ir.BlockThinking, Text: b.Text, Signature: b.Signature}, nil
	case ir.BlockRedactedThinking:
		return Block{Type: ir.BlockRedactedThinking, Redacted: b.Redacted}, nil
	case ir.BlockOpaque:
		if b.Opaque == nil {
			return Block{}, fmt.Errorf("opaque block missing opaque payload")
		}
		return Block{Type: ir.BlockOpaque, Opaque: &Opaque{
			Dialect: b.Opaque.Dialect, Kind: b.Opaque.Kind, Raw: bytes.Clone(b.Opaque.Raw),
		}, CacheHint: b.CacheHint}, nil
	default:
		return Block{}, fmt.Errorf("lux: block type %q not representable", b.Type)
	}
}

// logProbsToIR and logProbsFromIR copy rather than alias, for the
// reason copyInt64 gives: the wire struct and the IR must never share
// backing memory, so a mutation on one side cannot reach the other.
func logProbsToIR(in []TokenLogProb) []ir.TokenLogProb {
	if len(in) == 0 {
		return nil
	}
	out := make([]ir.TokenLogProb, len(in))
	for i, p := range in {
		out[i] = ir.TokenLogProb{
			Token:   p.Token,
			Bytes:   bytes.Clone(p.Bytes),
			LogProb: p.LogProb,
			Top:     logProbsToIR(p.Top),
		}
	}
	return out
}

func logProbsFromIR(in []ir.TokenLogProb) []TokenLogProb {
	if len(in) == 0 {
		return nil
	}
	out := make([]TokenLogProb, len(in))
	for i, p := range in {
		out[i] = TokenLogProb{
			Token:   p.Token,
			Bytes:   bytes.Clone(p.Bytes),
			LogProb: p.LogProb,
			Top:     logProbsFromIR(p.Top),
		}
	}
	return out
}

func usageToIR(u Usage) ir.Usage {
	return ir.Usage{
		InputTokens:           u.InputTokens,
		OutputTokens:          u.OutputTokens,
		CacheReadInputTokens:  copyInt64(u.CacheReadInputTokens),
		CacheWriteInputTokens: copyInt64(u.CacheWriteInputTokens),
		ReasoningTokens:       u.ReasoningTokens,
		CostUSDMicro:          copyInt64(u.CostUSDMicro),
	}
}

func usageFromIR(u ir.Usage) Usage {
	return Usage{
		InputTokens:           u.InputTokens,
		OutputTokens:          u.OutputTokens,
		CacheReadInputTokens:  copyInt64(u.CacheReadInputTokens),
		CacheWriteInputTokens: copyInt64(u.CacheWriteInputTokens),
		ReasoningTokens:       u.ReasoningTokens,
		CostUSDMicro:          copyInt64(u.CostUSDMicro),
	}
}

// copyInt64 copies an optional value across the wire/IR boundary, so
// the two structs never share a pointer and a mutation on one side
// cannot reach the other.
func copyInt64(v *int64) *int64 {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

// EventFromIR converts a canonical IR event to the wire vocabulary.
// Exported for consumers that drive a non-lux SSE decoder and want
// the lux wire shape out, as llmdirect does.
func EventFromIR(ev ir.Event) (Event, error) { return eventFromIR(ev) }

// eventFromIR converts a canonical IR event to the wire.
func eventFromIR(ev ir.Event) (Event, error) {
	if !validEventTypes[ev.Type] {
		return Event{}, fmt.Errorf("lux: unknown event type %q", ev.Type)
	}
	out := Event{
		Type:         ev.Type,
		ID:           ev.ID,
		Model:        ev.Model,
		Index:        ev.Index,
		Delta:        ev.Delta,
		StopReason:   ev.StopReason,
		StopSequence: ev.StopSequence,
		LogProbs:     logProbsFromIR(ev.LogProbs),
	}
	if ev.Block != nil {
		blk, err := blockFromIR(*ev.Block)
		if err != nil {
			return Event{}, err
		}
		out.Block = &blk
	}
	if ev.Usage != nil {
		u := usageFromIR(*ev.Usage)
		out.Usage = &u
	}
	return out, nil
}

// eventToIR converts a wire event to the canonical IR.
func eventToIR(ev Event) (ir.Event, error) {
	if !validEventTypes[ev.Type] {
		return ir.Event{}, fmt.Errorf("lux: unknown event type %q", ev.Type)
	}
	out := ir.Event{
		Type:         ev.Type,
		ID:           ev.ID,
		Model:        ev.Model,
		Index:        ev.Index,
		Delta:        ev.Delta,
		StopReason:   ev.StopReason,
		StopSequence: ev.StopSequence,
		LogProbs:     logProbsToIR(ev.LogProbs),
	}
	if ev.Block != nil {
		var loss ir.Loss
		blk, ok, err := blockToIR(*ev.Block, &loss)
		if err != nil {
			return ir.Event{}, err
		}
		if ok {
			out.Block = &blk
		}
	}
	if ev.Usage != nil {
		u := usageToIR(*ev.Usage)
		out.Usage = &u
	}
	return out, nil
}
