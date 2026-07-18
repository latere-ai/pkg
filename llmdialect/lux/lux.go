// Package lux implements the lux-native dialect for llmdialect: the
// neutral IR itself, made public as a stable, snake_case JSON wire
// format (spec lux/33). Because the dialect is the IR, the frontend
// leg is lossless by construction — the only representational loss on
// a lux-fronted call happens on the backend leg.
//
// This file carries the frontend codec (caller side): decoding a lux
// request into the IR, encoding an IR response back to a lux body, and
// emitting the lux SSE event stream (one `event: <type>` frame per IR
// event, grammar identical to the IR's).
package lux

import (
	"encoding/json"
	"fmt"
	"io"

	"latere.ai/x/pkg/llmdialect/internal/sse"
	"latere.ai/x/pkg/llmdialect/ir"
)

// DialectName identifies this dialect.
const DialectName = ir.DialectLux

// Frontend is the caller-side lux codec.
type Frontend struct{}

// NewFrontend returns the lux frontend codec.
func NewFrontend() *Frontend { return &Frontend{} }

// Name returns the dialect name.
func (*Frontend) Name() ir.Dialect { return DialectName }

// requestKeys are the top-level lux request fields the decoder
// understands. Anything else lands in the loss report.
var requestKeys = map[string]bool{
	"model": true, "system": true, "messages": true, "tools": true,
	"tool_choice": true, "max_tokens": true, "temperature": true,
	"top_p": true, "top_k": true, "stop_sequences": true, "stream": true,
	"reasoning": true, "schema": true, "user_id": true,
}

// DecodeRequest parses a lux request body into the IR.
func (*Frontend) DecodeRequest(body []byte) (*ir.Request, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("lux: invalid request JSON: %w", err)
	}
	req := &ir.Request{}
	for k := range top {
		if !requestKeys[k] {
			req.Loss.Add(ir.LossRequestFieldOf(k))
		}
	}

	var wire Request
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("lux: malformed request: %w", err)
	}
	if wire.Model == "" {
		return nil, fmt.Errorf("lux: model is required")
	}
	if len(wire.Messages) == 0 {
		return nil, fmt.Errorf("lux: messages is required")
	}

	req.Model = wire.Model
	req.MaxTokens = wire.MaxTokens
	req.Temperature = wire.Temperature
	req.TopP = wire.TopP
	req.TopK = wire.TopK
	req.StopSequences = wire.StopSequences
	req.Stream = wire.Stream
	req.UserID = wire.UserID

	for _, b := range wire.System {
		if b.Type != ir.BlockText {
			req.Loss.Add(ir.LossSystemTypeOf(string(b.Type)))
			continue
		}
		req.System = append(req.System, ir.Block{Type: ir.BlockText, Text: b.Text, CacheHint: b.CacheHint})
	}
	for i, m := range wire.Messages {
		msg, err := messageToIR(m, &req.Loss)
		if err != nil {
			return nil, fmt.Errorf("lux: messages[%d]: %w", i, err)
		}
		req.Messages = append(req.Messages, msg)
	}
	for _, t := range wire.Tools {
		req.Tools = append(req.Tools, ir.Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	if wire.ToolChoice != nil {
		tc, err := toolChoiceToIR(*wire.ToolChoice)
		if err != nil {
			return nil, err
		}
		req.ToolChoice = tc
	}
	if wire.Reasoning != nil {
		if wire.Reasoning.Effort != "" && wire.Reasoning.BudgetTokens != 0 {
			return nil, fmt.Errorf("lux: reasoning takes effort or budget_tokens, not both")
		}
		req.Reasoning = &ir.Reasoning{Effort: wire.Reasoning.Effort, BudgetTokens: wire.Reasoning.BudgetTokens}
	}
	if wire.Schema != nil {
		req.Schema = &ir.ResponseSchema{
			Name:        wire.Schema.Name,
			Description: wire.Schema.Description,
			Schema:      wire.Schema.Schema,
			Strict:      wire.Schema.Strict,
		}
	}
	return req, nil
}

func messageToIR(m Message, loss *ir.Loss) (ir.Message, error) {
	switch m.Role {
	case ir.RoleUser, ir.RoleAssistant:
	default:
		return ir.Message{}, fmt.Errorf("unknown role %q", m.Role)
	}
	if len(m.Blocks) == 0 {
		return ir.Message{}, fmt.Errorf("blocks is required")
	}
	var out []ir.Block
	for _, b := range m.Blocks {
		blk, ok, err := blockToIR(b, loss)
		if err != nil {
			return ir.Message{}, err
		}
		if ok {
			out = append(out, blk)
		}
	}
	return ir.Message{Role: m.Role, Blocks: out}, nil
}

func toolChoiceToIR(tc ToolChoice) (*ir.ToolChoice, error) {
	switch tc.Mode {
	case ir.ToolChoiceAuto, ir.ToolChoiceAny, ir.ToolChoiceNone:
	case ir.ToolChoiceTool:
		if tc.Name == "" {
			return nil, fmt.Errorf("lux: tool_choice mode %q requires name", tc.Mode)
		}
	default:
		return nil, fmt.Errorf("lux: unknown tool_choice mode %q", tc.Mode)
	}
	return &ir.ToolChoice{Mode: tc.Mode, Name: tc.Name, DisableParallel: tc.DisableParallel}, nil
}

// EncodeResponse renders an IR response as a lux response body.
func (*Frontend) EncodeResponse(resp *ir.Response) ([]byte, error) {
	out := Response{
		ID:           resp.ID,
		Model:        resp.Model,
		StopReason:   resp.StopReason,
		StopSequence: resp.StopSequence,
		Usage:        usageFromIR(resp.Usage),
	}
	if out.StopReason == "" {
		out.StopReason = ir.StopEndTurn
	}
	for _, b := range resp.Blocks {
		blk, err := blockFromIR(b)
		if err != nil {
			return nil, err
		}
		out.Blocks = append(out.Blocks, blk)
	}
	return json.Marshal(out)
}

// EventEncoder writes the lux SSE stream: one `event: <type>` frame
// per IR event, data the wire Event JSON.
type EventEncoder struct {
	w *sse.Writer
}

// NewEventEncoder returns an encoder writing lux SSE frames to w.
func (*Frontend) NewEventEncoder(w io.Writer) ir.EventEncoder {
	return &EventEncoder{w: sse.NewWriter(w)}
}

// Encode writes the SSE frame for one IR event.
func (e *EventEncoder) Encode(ev ir.Event) error {
	wireEv, err := eventFromIR(ev)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(wireEv)
	if err != nil {
		return err
	}
	return e.w.WriteEvent(string(wireEv.Type), raw)
}
