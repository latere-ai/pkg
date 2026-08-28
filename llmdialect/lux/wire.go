package lux

// The lux wire vocabulary: exported, JSON-tagged mirrors of the IR
// types. These structs ARE the public lux dialect — luxsdk re-exports
// them as its request/response/event types — so they freeze at v1
// while the internal IR stays free to evolve; the conversions in this
// file absorb drift.

import (
	"bytes"
	"encoding/json"
	"fmt"

	"latere.ai/x/pkg/llmdialect/ir"
)

// Request is a lux-dialect inference request.
type Request struct {
	Model         string          `json:"model"`
	System        []Block         `json:"system,omitempty"`
	Messages      []Message       `json:"messages"`
	Tools         []Tool          `json:"tools,omitempty"`
	ToolChoice    *ToolChoice     `json:"tool_choice,omitempty"`
	MaxTokens     *int64          `json:"max_tokens,omitempty"`
	Temperature   *float64        `json:"temperature,omitempty"`
	TopP          *float64        `json:"top_p,omitempty"`
	TopK          *int64          `json:"top_k,omitempty"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
	Stream        bool            `json:"stream,omitempty"`
	Reasoning     *Reasoning      `json:"reasoning,omitempty"`
	Schema        *ResponseSchema `json:"schema,omitempty"`
	UserID        string          `json:"user_id,omitempty"`
	LogProbs      bool            `json:"logprobs,omitempty"`
	TopLogProbs   int             `json:"top_logprobs,omitempty"`
}

// TokenLogProb is one token and its log probability under the
// distribution it was drawn from. A token the policy masked scores
// -Inf, which travels as null: JSON has no infinity, and a floor value
// is a number a consumer averages.
//
// Bytes is the base64 string encoding/json gives a []byte. The lux
// dialect is the IR made public, so its members are spelled the way Go
// spells them rather than in a second dialect's shape.
type TokenLogProb struct {
	Token   string         `json:"token"`
	Bytes   []byte         `json:"bytes,omitempty"`
	LogProb ir.LogProb     `json:"logprob"`
	Top     []TokenLogProb `json:"top,omitempty"`
}

// Message is one conversation turn.
type Message struct {
	Role   ir.Role `json:"role"`
	Blocks []Block `json:"blocks"`
}

// Block is one typed content unit. Exactly the fields for its Type
// are set.
type Block struct {
	Type       ir.BlockType `json:"type"`
	Text       string       `json:"text,omitempty"`
	Image      *Image       `json:"image,omitempty"`
	ToolUse    *ToolUse     `json:"tool_use,omitempty"`
	ToolResult *ToolResult  `json:"tool_result,omitempty"`
	Signature  string       `json:"signature,omitempty"`
	Redacted   string       `json:"redacted,omitempty"`
	CacheHint  bool         `json:"cache_hint,omitempty"`
}

// Image is image content, either inline base64 or by URL.
type Image struct {
	MediaType string `json:"media_type,omitempty"`
	Data      string `json:"data,omitempty"`
	URL       string `json:"url,omitempty"`
}

// ToolUse is a model-issued tool invocation.
type ToolUse struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

// ToolResult is a caller-supplied result for a prior ToolUse.
type ToolResult struct {
	ToolUseID string  `json:"tool_use_id"`
	Blocks    []Block `json:"blocks,omitempty"`
	IsError   bool    `json:"is_error,omitempty"`
}

// Tool is a callable tool definition.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ToolChoice constrains tool use for a request.
type ToolChoice struct {
	Mode            ir.ToolChoiceMode `json:"mode"`
	Name            string            `json:"name,omitempty"`
	DisableParallel bool              `json:"disable_parallel,omitempty"`
}

// Reasoning configures extended thinking. Exactly one of Effort
// (OpenAI style) or BudgetTokens (Anthropic style) is set.
type Reasoning struct {
	Effort       ir.Effort `json:"effort,omitempty"`
	BudgetTokens int64     `json:"budget_tokens,omitempty"`
}

// ResponseSchema requests structured output conforming to Schema.
type ResponseSchema struct {
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema"`
	Strict      bool            `json:"strict,omitempty"`
}

// Usage is token and cost accounting for one call.
type Usage struct {
	InputTokens           int64 `json:"input_tokens"`
	OutputTokens          int64 `json:"output_tokens"`
	CacheReadInputTokens  int64 `json:"cache_read_input_tokens,omitempty"`
	CacheWriteInputTokens int64 `json:"cache_write_input_tokens,omitempty"`
	ReasoningTokens       int64 `json:"reasoning_tokens,omitempty"`
	// CostUSDMicro is the gateway-reported cost in millionths of a USD.
	// The pointer carries the nil/zero distinction onto the wire:
	// omitempty drops only nil, so an explicitly reported zero cost
	// still travels as "cost_usd_micro":0 and stays distinguishable
	// from a gateway that reported nothing.
	CostUSDMicro *int64 `json:"cost_usd_micro,omitempty"`
}

// Response is a lux-dialect non-streaming response.
type Response struct {
	ID           string         `json:"id"`
	Model        string         `json:"model"`
	Blocks       []Block        `json:"blocks"`
	StopReason   ir.StopReason  `json:"stop_reason"`
	StopSequence string         `json:"stop_sequence,omitempty"`
	Usage        Usage          `json:"usage"`
	LogProbs     []TokenLogProb `json:"logprobs,omitempty"`
}

// Event is one lux-dialect streaming event, carried as the data of an
// SSE frame whose event name equals Type. The stream grammar is the
// IR grammar verbatim:
//
//	message_start (block_start (text_delta|args_delta|thinking_delta|signature_delta)* block_stop)* message_delta message_stop
type Event struct {
	Type         ir.EventType   `json:"type"`
	ID           string         `json:"id,omitempty"`
	Model        string         `json:"model,omitempty"`
	Index        int            `json:"index"`
	Block        *Block         `json:"block,omitempty"`
	Delta        string         `json:"delta,omitempty"`
	StopReason   ir.StopReason  `json:"stop_reason,omitempty"`
	StopSequence string         `json:"stop_sequence,omitempty"`
	Usage        *Usage         `json:"usage,omitempty"`
	LogProbs     []TokenLogProb `json:"logprobs,omitempty"`
}

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
	default:
		loss.Add(ir.LossContentTypeOf(string(b.Type)))
		return ir.Block{}, false, nil
	}
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
		CacheReadInputTokens:  u.CacheReadInputTokens,
		CacheWriteInputTokens: u.CacheWriteInputTokens,
		ReasoningTokens:       u.ReasoningTokens,
		CostUSDMicro:          copyInt64(u.CostUSDMicro),
	}
}

func usageFromIR(u ir.Usage) Usage {
	return Usage{
		InputTokens:           u.InputTokens,
		OutputTokens:          u.OutputTokens,
		CacheReadInputTokens:  u.CacheReadInputTokens,
		CacheWriteInputTokens: u.CacheWriteInputTokens,
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
// the lux wire shape out (luxsdk's direct mode).
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
