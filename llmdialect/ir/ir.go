// Package ir defines the neutral intermediate representation that all
// llmdialect frontends and backends translate through. The IR is a
// superset of the OpenAI (Chat Completions, Responses) and Anthropic
// (Messages) wire dialects: every codec decodes its dialect into these
// types and encodes them back out, so translation is hub-and-spoke and
// never pairwise.
//
// Fields a target dialect cannot represent are recorded in the request
// Loss report rather than silently dropped; consumers surface the
// report (Lux emits it as an X-Lux-Compat-Loss header and OTEL
// counters).
package ir

import "encoding/json"

// Role is a conversation turn author. The IR keeps the Anthropic
// two-role model; system content lives on Request.System and
// tool results are blocks inside a user message.
type Role string

// Roles.
const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// BlockType discriminates Block variants.
type BlockType string

// Block types.
const (
	BlockText             BlockType = "text"
	BlockImage            BlockType = "image"
	BlockToolUse          BlockType = "tool_use"
	BlockToolResult       BlockType = "tool_result"
	BlockThinking         BlockType = "thinking"
	BlockRedactedThinking BlockType = "redacted_thinking"
)

// Block is one typed content unit inside a message (or the system
// prompt). Exactly the fields for its Type are set.
type Block struct {
	Type BlockType

	// Text carries BlockText and BlockThinking content.
	Text string

	Image      *Image
	ToolUse    *ToolUse
	ToolResult *ToolResult

	// Signature is the provider-issued replay token on a thinking
	// block. Synthesized thinking blocks have none; codecs must never
	// fabricate one.
	Signature string

	// Redacted is the opaque payload of a redacted_thinking block.
	Redacted string

	// CacheHint marks a prompt-cache breakpoint after this block
	// (Anthropic cache_control). Backends without explicit caching
	// drop it into the loss report.
	CacheHint bool
}

// Image is image content, either inline base64 or by URL.
type Image struct {
	MediaType string // MIME type for inline data, e.g. image/png
	Data      string // base64 payload; empty when URL-sourced
	URL       string // https URL; empty when inline
}

// ToolUse is a model-issued tool invocation.
type ToolUse struct {
	ID   string
	Name string
	Args json.RawMessage // arguments object as JSON
}

// ToolResult is a caller-supplied result for a prior ToolUse.
type ToolResult struct {
	ToolUseID string
	Blocks    []Block // text and image blocks
	IsError   bool
}

// Message is one conversation turn.
type Message struct {
	Role   Role
	Blocks []Block
}

// Tool is a callable tool definition.
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage // JSON Schema object
}

// ToolChoiceMode says how the model may use tools.
type ToolChoiceMode string

// Tool choice modes.
const (
	ToolChoiceAuto ToolChoiceMode = "auto" // model decides
	ToolChoiceAny  ToolChoiceMode = "any"  // must call some tool
	ToolChoiceNone ToolChoiceMode = "none" // must not call tools
	ToolChoiceTool ToolChoiceMode = "tool" // must call Name
)

// ToolChoice constrains tool use for a request.
type ToolChoice struct {
	Mode            ToolChoiceMode
	Name            string // for ToolChoiceTool
	DisableParallel bool
}

// Reasoning configures extended thinking. Exactly one of Effort
// (OpenAI style: minimal/low/medium/high) or BudgetTokens (Anthropic
// style) is set by a decoder; encoders map between them by the banding
// documented in the codec packages.
type Reasoning struct {
	Effort       string
	BudgetTokens int64
}

// ResponseSchema requests structured output conforming to Schema.
type ResponseSchema struct {
	Name        string
	Description string
	Schema      json.RawMessage
	Strict      bool
}

// Request is a dialect-neutral inference request.
type Request struct {
	Model         string
	System        []Block // text blocks only
	Messages      []Message
	Tools         []Tool
	ToolChoice    *ToolChoice
	MaxTokens     *int64
	Temperature   *float64
	TopP          *float64
	TopK          *int64
	StopSequences []string
	Stream        bool
	Reasoning     *Reasoning
	Schema        *ResponseSchema
	UserID        string // caller-supplied end-user identifier

	// Loss accumulates fields dropped or approximated during decode
	// and encode, as dialect-qualified names (e.g. "cache_control").
	Loss Loss
}

// Loss is an ordered, deduplicated list of lost field names.
type Loss struct {
	fields []string
}

// Add records a lost field once.
func (l *Loss) Add(field string) {
	for _, f := range l.fields {
		if f == field {
			return
		}
	}
	l.fields = append(l.fields, field)
}

// Fields returns the recorded losses in insertion order.
func (l *Loss) Fields() []string { return l.fields }

// StopReason says why generation ended, in Anthropic vocabulary (the
// richer of the two); codecs map to dialect-native values.
type StopReason string

// Stop reasons.
const (
	StopEndTurn      StopReason = "end_turn"
	StopToolUse      StopReason = "tool_use"
	StopMaxTokens    StopReason = "max_tokens"
	StopStopSequence StopReason = "stop_sequence"
	StopRefusal      StopReason = "refusal"
)

// Usage is token accounting for one call.
type Usage struct {
	InputTokens           int64
	OutputTokens          int64
	CacheReadInputTokens  int64
	CacheWriteInputTokens int64
	ReasoningTokens       int64
}

// Response is a dialect-neutral non-streaming inference response.
type Response struct {
	ID           string
	Model        string
	Blocks       []Block
	StopReason   StopReason
	StopSequence string
	Usage        Usage
}

// EventType discriminates streaming events.
type EventType string

// Event types. A well-formed stream is:
//
//	MessageStart (BlockStart (TextDelta|ArgsDelta|ThinkingDelta|SignatureDelta)* BlockStop)* MessageDelta MessageStop
const (
	EventMessageStart   EventType = "message_start"
	EventBlockStart     EventType = "block_start"
	EventTextDelta      EventType = "text_delta"
	EventArgsDelta      EventType = "args_delta"
	EventThinkingDelta  EventType = "thinking_delta"
	EventSignatureDelta EventType = "signature_delta"
	EventBlockStop      EventType = "block_stop"
	EventMessageDelta   EventType = "message_delta"
	EventMessageStop    EventType = "message_stop"
)

// EventEncoder writes one dialect-native SSE frame set per IR event.
// Frontend codecs return one from their NewEventEncoder constructor.
type EventEncoder interface {
	Encode(ev Event) error
}

// EventDecoder yields canonical IR events from a dialect-native SSE
// stream, returning io.EOF after the final event. Backend codecs
// return one from their NewEventDecoder constructor.
type EventDecoder interface {
	Next() (Event, error)
}

// Event is one canonical streaming event. Backends decode their native
// SSE into this sequence; frontends re-synthesize their native events
// from it, so the transform stays incremental.
type Event struct {
	Type EventType

	// MessageStart fields.
	ID    string
	Model string

	// Block-scoped fields (BlockStart..BlockStop). Index is the
	// zero-based output block ordinal. Block carries the header on
	// BlockStart (type, and tool id/name for tool_use).
	Index int
	Block *Block

	// Delta is the incremental payload for the delta event types.
	Delta string

	// MessageDelta fields. Usage also appears on MessageStart when the
	// backend reports input tokens up front (Anthropic does; OpenAI
	// reports everything at the end).
	StopReason   StopReason
	StopSequence string
	Usage        *Usage
}
