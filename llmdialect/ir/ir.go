// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

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

import (
	"encoding/json"
	"math"
	"slices"
)

// Dialect names an LLM inference wire dialect. Every codec package
// exports its own DialectName typed as this.
type Dialect string

// Dialects.
const (
	DialectAnthropicMessages Dialect = "anthropic-messages"
	DialectOpenAIChat        Dialect = "openai-chat"
	DialectOpenAIResponses   Dialect = "openai-responses"
	DialectLux               Dialect = "lux"
)

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

// ServerTool is a tool the provider runs itself.
//
// It is deliberately not a [Tool]. A Tool is a capability the caller
// implements: the model asks for it, the caller executes it, and the answer
// comes back as a tool_result block. A ServerTool never leaves the provider —
// it runs mid-turn and its outcome is folded into the response — so a caller
// that walks Tools to build its dispatch table must not find web search in
// there.
//
// The fields are opaque on purpose. Server tools are versioned per provider
// and gain options faster than an IR can model them, so the type string and
// its sibling fields pass through unread. A dialect that has no server tools
// records [LossServerToolOf] rather than inventing one.
type ServerTool struct {
	// Type is the provider's versioned identifier for the tool, e.g.
	// "web_search_20250305". It is what selects the behaviour.
	Type string

	// Name is what the model calls the tool by, e.g. "web_search".
	Name string

	// Config carries the fields that sit beside Type and Name in the same
	// object — max_uses, allowed_domains, and whatever a provider adds
	// next — as a JSON object. Nil when the tool takes no options.
	Config json.RawMessage
}

// WebSearch asks the provider to ground the answer in a web search it runs
// itself. It is a request-level switch rather than a [ServerTool] because
// that is how the OpenAI Chat Completions dialect expresses it: a sibling of
// tools, not an entry in it.
type WebSearch struct {
	// ContextSize is how much retrieved material the provider should feed
	// the model: "low", "medium" or "high". Empty leaves it to the
	// provider's default.
	ContextSize string

	// UserLocation biases results geographically. Provider-shaped and
	// passed through unread, since the dialects that accept it do not
	// agree on its fields.
	UserLocation json.RawMessage
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

// Effort is the OpenAI-style reasoning effort scale. It is an open
// enum: decoders pass unknown wire values through unchanged so a new
// upstream tier does not break translation.
type Effort string

// Efforts.
const (
	EffortMinimal Effort = "minimal"
	EffortLow     Effort = "low"
	EffortMedium  Effort = "medium"
	EffortHigh    Effort = "high"
)

// Reasoning configures extended thinking. Exactly one of Effort
// (OpenAI style) or BudgetTokens (Anthropic style) is set by a
// decoder; encoders map between them by the banding documented in the
// codec packages.
type Reasoning struct {
	Effort       Effort
	BudgetTokens int64
}

// LogProb is a natural-log probability that survives JSON. A token the
// sampling policy masked scores math.Inf(-1) — it could not have been
// drawn at all — and JSON has no infinity, so any non-finite value
// encodes as null and null decodes back to math.Inf(-1). null is what
// "this token could not be drawn" means; a floor value is worse,
// because a consumer averages it.
type LogProb float64

// MarshalJSON renders the value, or null when it is not finite.
func (l LogProb) MarshalJSON() ([]byte, error) {
	f := float64(l)
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return []byte("null"), nil
	}
	return json.Marshal(f)
}

// UnmarshalJSON reads the value, mapping null back to math.Inf(-1).
func (l *LogProb) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*l = LogProb(math.Inf(-1))
		return nil
	}
	var f float64
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	*l = LogProb(f)
	return nil
}

// TokenLogProb is one token and its log probability under the
// distribution it was drawn from: the post-policy distribution, after
// bias, penalties, temperature and top-k/top-p. That is the number a
// provider must report, because a raw softmax over the untruncated
// vocabulary describes a distribution nothing sampled from.
type TokenLogProb struct {
	Token string

	// Bytes is the UTF-8 encoding of Token. A byte-level vocabulary
	// splits many characters across several tokens, so a consumer that
	// joins bytes can reconstruct text that one joining strings cannot.
	// Nil when the dialect reports none (the Responses streaming shape
	// carries no bytes member).
	Bytes []byte

	LogProb LogProb

	// Top is the most likely alternatives at this position, most likely
	// first, as many as the request asked for. Entries in Top have no
	// Top of their own.
	Top []TokenLogProb
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
	ServerTools   []ServerTool
	ToolChoice    *ToolChoice
	MaxTokens     *int64
	Temperature   *float64
	TopP          *float64
	TopK          *int64
	StopSequences []string
	Stream        bool
	Reasoning     *Reasoning
	Schema        *ResponseSchema
	WebSearch     *WebSearch
	UserID        string // caller-supplied end-user identifier

	// LogProbs asks for the log probability of every token the model
	// emits, and TopLogProbs for that many alternatives at each
	// position. TopLogProbs > 0 implies LogProbs: alternatives to a
	// number the caller did not ask for is not what any OpenAI client
	// means by it, so decoders set both.
	LogProbs    bool
	TopLogProbs int

	// Loss accumulates fields dropped or approximated during decode
	// and encode.
	Loss Loss
}

// LossField names one dropped or approximated field in a loss report.
// The static vocabulary is enumerated below; structurally dynamic
// entries (an unknown tool type, an unrecognized content block) are
// built with the Loss*Of constructors so their shape stays uniform.
type LossField string

// Static loss fields.
const (
	LossCacheControl      LossField = "cache_control"
	LossCitations         LossField = "citations"
	LossInclude           LossField = "include"
	LossLogProbs          LossField = "logprobs"
	LossReasoningEffort   LossField = "reasoning_effort"
	LossReasoningItems    LossField = "reasoning"
	LossReasoningSummary  LossField = "reasoning.summary"
	LossStopSequences     LossField = "stop_sequences"
	LossTemperature       LossField = "temperature"
	LossTextVerbosity     LossField = "text.verbosity"
	LossThinking          LossField = "thinking"
	LossThinkingBudget    LossField = "thinking.budget_tokens"
	LossToolCacheControl  LossField = "tools.cache_control"
	LossToolResultImage   LossField = "tool_result.image"
	LossToolResultIsError LossField = "tool_result.is_error"
	LossToolStrict        LossField = "tools.strict"
	LossTopK              LossField = "top_k"
	LossTopLogProbs       LossField = "top_logprobs"
	LossTopP              LossField = "top_p"
	LossUserTruncated     LossField = "user.truncated"
	LossWebSearch         LossField = "web_search_options"
	LossWebSearchLocation LossField = "web_search_options.user_location"
)

// Dynamic loss-field constructors.

// LossRequestFieldOf marks an unrecognized top-level request field.
func LossRequestFieldOf(name string) LossField { return LossField(name) }

// LossToolTypeOf marks an unsupported tool type.
func LossToolTypeOf(t string) LossField { return LossField("tools." + t) }

// LossServerToolOf marks a provider-executed tool the target dialect has no
// way to express. The type is carried so a reader can tell which capability
// went missing, not merely that one did.
func LossServerToolOf(t string) LossField { return LossField("server_tools." + t) }

// LossContentTypeOf marks an unsupported content block/part type.
func LossContentTypeOf(t string) LossField { return LossField("content." + t) }

// LossSystemTypeOf marks an unsupported system block type.
func LossSystemTypeOf(t string) LossField { return LossField("system." + t) }

// LossInputTypeOf marks an unsupported Responses input item type.
func LossInputTypeOf(t string) LossField { return LossField("input." + t) }

// LossTextFormatOf marks an unsupported Responses text.format type.
func LossTextFormatOf(t string) LossField { return LossField("text.format." + t) }

// LossResponseFormatOf marks an unsupported response_format type.
func LossResponseFormatOf(t string) LossField { return LossField("response_format." + t) }

// Loss is an ordered, deduplicated list of lost fields.
type Loss struct {
	fields []LossField
}

// Add records a lost field once.
func (l *Loss) Add(field LossField) {
	if slices.Contains(l.fields, field) {
		return
	}
	l.fields = append(l.fields, field)
}

// Fields returns the recorded losses in insertion order.
func (l *Loss) Fields() []LossField { return l.fields }

// Strings returns the recorded losses as plain strings, for callers
// that serialize the report (headers, metrics).
func (l *Loss) Strings() []string {
	if len(l.fields) == 0 {
		return nil
	}
	out := make([]string, len(l.fields))
	for i, f := range l.fields {
		out[i] = string(f)
	}
	return out
}

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

// Usage is token and cost accounting for one call.
type Usage struct {
	InputTokens           int64
	OutputTokens          int64
	CacheReadInputTokens  int64
	CacheWriteInputTokens int64
	ReasoningTokens       int64
	// CostUSDMicro is the gateway-reported cost in millionths of a USD,
	// or nil when the gateway reported none. Nil means unknown, never
	// zero: zero is a legitimate cost (local and cached calls report
	// it), so a consumer that fails closed on an unknown cost must be
	// able to tell the two apart. Carried verbatim, including a
	// gateway's own unpriced sentinel; this layer computes no prices.
	CostUSDMicro *int64
}

// Response is a dialect-neutral non-streaming inference response.
type Response struct {
	ID           string
	Model        string
	Blocks       []Block
	StopReason   StopReason
	StopSequence string
	Usage        Usage

	// LogProbs is one entry per token of the response text, in
	// emission order, and empty unless Request.LogProbs asked for
	// them. It is flat rather than per block because the dialects that
	// carry it report one sequence per choice.
	LogProbs []TokenLogProb
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

	// LogProbs is the tokens Delta decodes from, on a TextDelta event
	// and only when the request asked. It is per event rather than per
	// message because both dialects that carry logprobs put them on the
	// same frame as the text, so a stream stays translatable one event
	// at a time. A delta can decode from several tokens, or from part
	// of one, so the count does not track the event count.
	LogProbs []TokenLogProb

	// MessageDelta fields. Usage also appears on MessageStart when the
	// backend reports input tokens up front (Anthropic does; OpenAI
	// reports everything at the end).
	StopReason   StopReason
	StopSequence string
	Usage        *Usage
}
