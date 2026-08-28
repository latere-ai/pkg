// Package anthropic implements the Anthropic Messages dialect for
// llmdialect. This file carries the frontend codec (caller side):
// decoding a Messages API request into the IR, encoding an IR response
// back to a Messages API body, and re-synthesizing the Messages SSE
// event sequence from canonical IR events.
//
// The backend codec (upstream side, for driving native Anthropic
// models from other dialects) ships separately.
package anthropic

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"latere.ai/x/pkg/llmdialect/internal/sse"
	"latere.ai/x/pkg/llmdialect/ir"
)

// unknownValue rejects a closed-vocabulary value, naming the JSON path
// it sits at, the value found there, and the whole set that would have
// been accepted. Each of those vocabularies is defined a few lines from
// its check, so the accepted set is mechanically derivable and there is
// no reason to make a caller read this source to learn it.
//
// The message reaches end users verbatim: Lux puts err.Error() into the
// 400 body its /compat/anthropic surface returns.
//
// Errors from here are bare. The "anthropic:" prefix is added once, by
// the exported method at the boundary, so a caller can tell which layer
// rejected the request without reading it twice.
func unknownValue(path, got string, want ...string) error {
	return fmt.Errorf("%s: unknown value %q; expected one of: %s", path, got, strings.Join(want, ", "))
}

// DialectName identifies this dialect.
const DialectName = ir.DialectAnthropicMessages

// Frontend is the caller-side Messages codec.
type Frontend struct{}

// NewFrontend returns the Messages frontend codec.
func NewFrontend() *Frontend { return &Frontend{} }

// Name returns the dialect name.
func (*Frontend) Name() ir.Dialect { return DialectName }

// requestKeys are the top-level Messages request fields the decoder
// understands. Anything else lands in the loss report.
var requestKeys = map[string]bool{
	"model": true, "max_tokens": true, "system": true, "messages": true,
	"tools": true, "tool_choice": true, "temperature": true, "top_p": true,
	"top_k": true, "stop_sequences": true, "stream": true, "metadata": true,
	"thinking": true, "output_format": true,
}

// DecodeRequest parses a Messages API request body into the IR.
func (*Frontend) DecodeRequest(body []byte) (*ir.Request, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("anthropic: invalid request JSON: %w", err)
	}
	req := &ir.Request{}
	for k := range top {
		if !requestKeys[k] {
			req.Loss.Add(ir.LossRequestFieldOf(k))
		}
	}

	var wire struct {
		Model         string          `json:"model"`
		MaxTokens     *int64          `json:"max_tokens"`
		System        json.RawMessage `json:"system"`
		Messages      []wireMessage   `json:"messages"`
		Tools         []wireTool      `json:"tools"`
		ToolChoice    *wireToolChoice `json:"tool_choice"`
		Temperature   *float64        `json:"temperature"`
		TopP          *float64        `json:"top_p"`
		TopK          *int64          `json:"top_k"`
		StopSequences []string        `json:"stop_sequences"`
		Stream        bool            `json:"stream"`
		Metadata      struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
		Thinking *struct {
			Type         string `json:"type"`
			BudgetTokens int64  `json:"budget_tokens"`
		} `json:"thinking"`
		OutputConfig *struct {
			Effort string `json:"effort"`
		} `json:"output_config"`
		OutputFormat *struct {
			Type   string          `json:"type"`
			Schema json.RawMessage `json:"schema"`
		} `json:"output_format"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("anthropic: malformed request: %w", err)
	}
	if wire.Model == "" {
		return nil, fmt.Errorf("anthropic: model is required")
	}
	if len(wire.Messages) == 0 {
		return nil, fmt.Errorf("anthropic: messages is required")
	}

	req.Model = wire.Model
	req.MaxTokens = wire.MaxTokens
	req.Temperature = wire.Temperature
	req.TopP = wire.TopP
	req.TopK = wire.TopK
	req.StopSequences = wire.StopSequences
	req.Stream = wire.Stream
	req.UserID = wire.Metadata.UserID

	if len(wire.System) > 0 {
		sys, err := decodeSystem(wire.System, &req.Loss, "system")
		if err != nil {
			return nil, fmt.Errorf("anthropic: %w", err)
		}
		req.System = sys
	}
	for i, m := range wire.Messages {
		path := fmt.Sprintf("messages[%d]", i)
		// The native Messages API also accepts system-role turns
		// inside messages (Claude Code sends them); fold those into
		// the system prompt like the openaichat frontend does.
		if m.Role == "system" {
			sys, err := decodeSystem(m.Content, &req.Loss, path+".content")
			if err != nil {
				return nil, fmt.Errorf("anthropic: %w", err)
			}
			req.System = append(req.System, sys...)
			continue
		}
		msg, err := decodeMessage(m, &req.Loss, path)
		if err != nil {
			return nil, fmt.Errorf("anthropic: %w", err)
		}
		req.Messages = append(req.Messages, msg)
	}
	for _, t := range wire.Tools {
		if t.Type != "" && t.Type != "custom" {
			req.Loss.Add(ir.LossToolTypeOf(t.Type))
			continue
		}
		if len(t.CacheControl) > 0 {
			req.Loss.Add(ir.LossToolCacheControl)
		}
		req.Tools = append(req.Tools, ir.Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	if wire.ToolChoice != nil {
		tc, err := decodeToolChoice(*wire.ToolChoice)
		if err != nil {
			return nil, fmt.Errorf("anthropic: %w", err)
		}
		req.ToolChoice = tc
	}
	// Reasoning is signalled two ways: the current API uses
	// output_config.effort (with thinking:{adaptive}), the deprecated one
	// thinking:{enabled, budget_tokens}. Effort wins when present.
	switch {
	case wire.OutputConfig != nil && wire.OutputConfig.Effort != "":
		req.Reasoning = &ir.Reasoning{Effort: ir.Effort(wire.OutputConfig.Effort)}
	case wire.Thinking != nil && wire.Thinking.Type == "enabled":
		req.Reasoning = &ir.Reasoning{BudgetTokens: wire.Thinking.BudgetTokens}
	case wire.Thinking != nil && wire.Thinking.Type == "adaptive":
		req.Reasoning = &ir.Reasoning{}
	}
	if wire.OutputFormat != nil {
		if wire.OutputFormat.Type != "json_schema" {
			return nil, fmt.Errorf("anthropic: %w", unknownValue("output_format.type", wire.OutputFormat.Type, "json_schema"))
		}
		req.Schema = &ir.ResponseSchema{Name: "output", Schema: wire.OutputFormat.Schema}
	}
	return req, nil
}

type wireMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type wireTool struct {
	Type         string          `json:"type"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	InputSchema  json.RawMessage `json:"input_schema"`
	CacheControl json.RawMessage `json:"cache_control"`
}

type wireToolChoice struct {
	Type                   string `json:"type"`
	Name                   string `json:"name"`
	DisableParallelToolUse bool   `json:"disable_parallel_tool_use"`
}

type wireBlock struct {
	Type string `json:"type"`

	Text         string          `json:"text,omitempty"`
	Source       *wireImage      `json:"source,omitempty"`
	ID           string          `json:"id,omitempty"`
	Name         string          `json:"name,omitempty"`
	Input        json.RawMessage `json:"input,omitempty"`
	ToolUseID    string          `json:"tool_use_id,omitempty"`
	Content      json.RawMessage `json:"content,omitempty"`
	IsError      bool            `json:"is_error,omitempty"`
	Thinking     string          `json:"thinking,omitempty"`
	Signature    string          `json:"signature,omitempty"`
	Data         string          `json:"data,omitempty"`
	CacheControl json.RawMessage `json:"cache_control,omitempty"`
	Citations    json.RawMessage `json:"citations,omitempty"`
}

type wireImage struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type,omitempty"`
	Data      string `json:"data,omitempty"`
	URL       string `json:"url,omitempty"`
}

// decodeSystem accepts the string and block-array forms of `system`.
func decodeSystem(raw json.RawMessage, loss *ir.Loss, path string) ([]ir.Block, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []ir.Block{{Type: ir.BlockText, Text: s}}, nil
	}
	var blocks []wireBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, fmt.Errorf("%s: must be a string or a block array", path)
	}
	var out []ir.Block
	for _, b := range blocks {
		if b.Type != "text" {
			loss.Add(ir.LossSystemTypeOf(b.Type))
			continue
		}
		out = append(out, ir.Block{Type: ir.BlockText, Text: b.Text, CacheHint: len(b.CacheControl) > 0})
	}
	return out, nil
}

func decodeMessage(m wireMessage, loss *ir.Loss, path string) (ir.Message, error) {
	var role ir.Role
	switch m.Role {
	case "user":
		role = ir.RoleUser
	case "assistant":
		role = ir.RoleAssistant
	default:
		// "system" is in the accepted set because DecodeRequest folds a
		// system-role turn into the system prompt before it gets here.
		return ir.Message{}, unknownValue(path+".role", m.Role, "user", "assistant", "system")
	}
	blocks, err := decodeContent(m.Content, loss, path+".content")
	if err != nil {
		return ir.Message{}, err
	}
	return ir.Message{Role: role, Blocks: blocks}, nil
}

// decodeContent accepts the string and block-array forms of message
// (and tool_result) content. path names the content member itself, so
// a block error can point at its own index inside it.
func decodeContent(raw json.RawMessage, loss *ir.Loss, path string) ([]ir.Block, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []ir.Block{{Type: ir.BlockText, Text: s}}, nil
	}
	var wire []wireBlock
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("%s: must be a string or a block array", path)
	}
	var out []ir.Block
	for i, b := range wire {
		blk, ok, err := decodeBlock(b, loss, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, blk)
		}
	}
	return out, nil
}

func decodeBlock(b wireBlock, loss *ir.Loss, path string) (ir.Block, bool, error) {
	cache := len(b.CacheControl) > 0
	if len(b.Citations) > 0 && string(b.Citations) != "null" {
		loss.Add(ir.LossCitations)
	}
	switch b.Type {
	case "text":
		return ir.Block{Type: ir.BlockText, Text: b.Text, CacheHint: cache}, true, nil
	case "image":
		if b.Source == nil {
			return ir.Block{}, false, fmt.Errorf("%s: image block missing source", path)
		}
		switch b.Source.Type {
		case "base64":
			return ir.Block{Type: ir.BlockImage, Image: &ir.Image{MediaType: b.Source.MediaType, Data: b.Source.Data}, CacheHint: cache}, true, nil
		case "url":
			return ir.Block{Type: ir.BlockImage, Image: &ir.Image{URL: b.Source.URL}, CacheHint: cache}, true, nil
		default:
			return ir.Block{}, false, unknownValue(path+".source.type", b.Source.Type, "base64", "url")
		}
	case "tool_use":
		return ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: b.ID, Name: b.Name, Args: b.Input}, CacheHint: cache}, true, nil
	case "tool_result":
		var blocks []ir.Block
		if len(b.Content) > 0 {
			inner, err := decodeContent(b.Content, loss, path+".content")
			if err != nil {
				return ir.Block{}, false, err
			}
			blocks = inner
		}
		return ir.Block{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: b.ToolUseID, Blocks: blocks, IsError: b.IsError}, CacheHint: cache}, true, nil
	case "thinking":
		return ir.Block{Type: ir.BlockThinking, Text: b.Thinking, Signature: b.Signature}, true, nil
	case "redacted_thinking":
		return ir.Block{Type: ir.BlockRedactedThinking, Redacted: b.Data}, true, nil
	default:
		loss.Add(ir.LossContentTypeOf(b.Type))
		return ir.Block{}, false, nil
	}
}

func decodeToolChoice(tc wireToolChoice) (*ir.ToolChoice, error) {
	out := &ir.ToolChoice{DisableParallel: tc.DisableParallelToolUse}
	switch tc.Type {
	case "auto":
		out.Mode = ir.ToolChoiceAuto
	case "any":
		out.Mode = ir.ToolChoiceAny
	case "none":
		out.Mode = ir.ToolChoiceNone
	case "tool":
		out.Mode = ir.ToolChoiceTool
		out.Name = tc.Name
	default:
		return nil, unknownValue("tool_choice.type", tc.Type, "auto", "any", "none", "tool")
	}
	return out, nil
}

// EncodeResponse renders an IR response as a Messages API message.
func (*Frontend) EncodeResponse(resp *ir.Response) ([]byte, error) {
	content := make([]map[string]any, 0, len(resp.Blocks))
	for _, b := range resp.Blocks {
		enc, err := encodeResponseBlock(b)
		if err != nil {
			return nil, err
		}
		content = append(content, enc)
	}
	stop := resp.StopReason
	if stop == "" {
		stop = ir.StopEndTurn
	}
	out := map[string]any{
		"id":            resp.ID,
		"type":          "message",
		"role":          "assistant",
		"model":         resp.Model,
		"content":       content,
		"stop_reason":   string(stop),
		"stop_sequence": nullableString(resp.StopSequence),
		"usage":         encodeUsage(resp.Usage),
	}
	return json.Marshal(out)
}

func encodeResponseBlock(b ir.Block) (map[string]any, error) {
	switch b.Type {
	case ir.BlockText:
		return map[string]any{"type": "text", "text": b.Text}, nil
	case ir.BlockToolUse:
		args := json.RawMessage(b.ToolUse.Args)
		if len(args) == 0 {
			args = json.RawMessage("{}")
		}
		return map[string]any{"type": "tool_use", "id": b.ToolUse.ID, "name": b.ToolUse.Name, "input": args}, nil
	case ir.BlockThinking:
		return map[string]any{"type": "thinking", "thinking": b.Text, "signature": b.Signature}, nil
	case ir.BlockRedactedThinking:
		return map[string]any{"type": "redacted_thinking", "data": b.Redacted}, nil
	default:
		return nil, fmt.Errorf("anthropic: block type %q not representable in a response", b.Type)
	}
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func encodeUsage(u ir.Usage) map[string]any {
	return map[string]any{
		"input_tokens":                u.InputTokens,
		"output_tokens":               u.OutputTokens,
		"cache_read_input_tokens":     u.CacheReadInputTokens,
		"cache_creation_input_tokens": u.CacheWriteInputTokens,
	}
}

// EventEncoder re-synthesizes the Messages SSE event sequence
// (message_start, ping, content_block_start/delta/stop, message_delta,
// message_stop) from canonical IR events.
type EventEncoder struct {
	w *sse.Writer
}

// NewEventEncoder returns an encoder writing Messages SSE frames to w.
func (*Frontend) NewEventEncoder(w io.Writer) ir.EventEncoder {
	return &EventEncoder{w: sse.NewWriter(w)}
}

// Encode writes the SSE frame(s) for one IR event.
func (e *EventEncoder) Encode(ev ir.Event) error {
	switch ev.Type {
	case ir.EventMessageStart:
		usage := ir.Usage{}
		if ev.Usage != nil {
			usage = *ev.Usage
		}
		if err := e.write("message_start", map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"id":            ev.ID,
				"type":          "message",
				"role":          "assistant",
				"model":         ev.Model,
				"content":       []any{},
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage":         encodeUsage(usage),
			},
		}); err != nil {
			return err
		}
		// The Messages API sends a ping right after message_start;
		// some SDK stream states expect it.
		return e.write("ping", map[string]any{"type": "ping"})
	case ir.EventBlockStart:
		blk, err := encodeStreamBlockHeader(ev.Block)
		if err != nil {
			return err
		}
		return e.write("content_block_start", map[string]any{
			"type": "content_block_start", "index": ev.Index, "content_block": blk,
		})
	case ir.EventTextDelta:
		return e.blockDelta(ev.Index, map[string]any{"type": "text_delta", "text": ev.Delta})
	case ir.EventArgsDelta:
		return e.blockDelta(ev.Index, map[string]any{"type": "input_json_delta", "partial_json": ev.Delta})
	case ir.EventThinkingDelta:
		return e.blockDelta(ev.Index, map[string]any{"type": "thinking_delta", "thinking": ev.Delta})
	case ir.EventSignatureDelta:
		return e.blockDelta(ev.Index, map[string]any{"type": "signature_delta", "signature": ev.Delta})
	case ir.EventBlockStop:
		return e.write("content_block_stop", map[string]any{"type": "content_block_stop", "index": ev.Index})
	case ir.EventMessageDelta:
		stop := ev.StopReason
		if stop == "" {
			stop = ir.StopEndTurn
		}
		data := map[string]any{
			"type":  "message_delta",
			"delta": map[string]any{"stop_reason": string(stop), "stop_sequence": nullableString(ev.StopSequence)},
		}
		if ev.Usage != nil {
			data["usage"] = encodeUsage(*ev.Usage)
		}
		return e.write("message_delta", data)
	case ir.EventMessageStop:
		return e.write("message_stop", map[string]any{"type": "message_stop"})
	default:
		return fmt.Errorf("anthropic: unknown event type %q", ev.Type)
	}
}

func (e *EventEncoder) blockDelta(index int, delta map[string]any) error {
	return e.write("content_block_delta", map[string]any{
		"type": "content_block_delta", "index": index, "delta": delta,
	})
}

func encodeStreamBlockHeader(b *ir.Block) (map[string]any, error) {
	if b == nil {
		return nil, fmt.Errorf("anthropic: block_start event missing block header")
	}
	switch b.Type {
	case ir.BlockText:
		return map[string]any{"type": "text", "text": ""}, nil
	case ir.BlockToolUse:
		return map[string]any{"type": "tool_use", "id": b.ToolUse.ID, "name": b.ToolUse.Name, "input": map[string]any{}}, nil
	case ir.BlockThinking:
		return map[string]any{"type": "thinking", "thinking": ""}, nil
	default:
		return nil, fmt.Errorf("anthropic: block type %q not streamable", b.Type)
	}
}

func (e *EventEncoder) write(name string, data map[string]any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return e.w.WriteEvent(name, raw)
}
