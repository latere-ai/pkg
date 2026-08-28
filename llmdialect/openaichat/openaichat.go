// Package openaichat implements the OpenAI Chat Completions dialect
// for llmdialect. This file carries the backend codec (upstream side):
// encoding an IR request as a Chat Completions body, decoding the
// response, and decoding the chunked SSE stream into canonical IR
// events. It targets the dialect as spoken by OpenAI itself and the
// openai-compatible runtimes (vLLM, Ollama, LM Studio, llama.cpp,
// OpenRouter, Gemini's compat endpoint), including the widespread
// reasoning_content extension.
//
// The frontend codec (caller side) ships separately.
package openaichat

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"latere.ai/x/pkg/llmdialect/internal/sse"
	"latere.ai/x/pkg/llmdialect/ir"
)

// DialectName identifies this dialect ("openai-compat" runtimes
// speak it).
const DialectName = ir.DialectOpenAIChat

// maxStopSequences is the Chat Completions `stop` limit.
const maxStopSequences = 4

// BackendOptions tune encoding for upstream quirks.
type BackendOptions struct {
	// UseMaxCompletionTokens emits max_completion_tokens instead of
	// max_tokens (required by newer api.openai.com models; the
	// open-weights runtimes still expect max_tokens).
	UseMaxCompletionTokens bool
}

// Backend is the upstream-side Chat Completions codec.
type Backend struct {
	opts BackendOptions
}

// NewBackend returns a Chat Completions backend codec.
func NewBackend(opts BackendOptions) *Backend { return &Backend{opts: opts} }

// Name returns the dialect name.
func (*Backend) Name() ir.Dialect { return DialectName }

// EncodeRequest renders the IR request as a Chat Completions body.
// Unrepresentable fields are recorded in req.Loss.
func (b *Backend) EncodeRequest(req *ir.Request) ([]byte, error) {
	body := map[string]any{"model": req.Model}

	var messages []map[string]any
	if sys := encodeSystem(req); sys != nil {
		messages = append(messages, sys)
	}
	for i, m := range req.Messages {
		enc, err := encodeMessage(m, req)
		if err != nil {
			return nil, fmt.Errorf("openaichat: messages[%d]: %w", i, err)
		}
		messages = append(messages, enc...)
	}
	body["messages"] = messages

	if len(req.Tools) > 0 {
		tools := make([]map[string]any, 0, len(req.Tools))
		for _, t := range req.Tools {
			schema := t.InputSchema
			if len(schema) == 0 {
				schema = json.RawMessage(`{"type":"object"}`)
			}
			fn := map[string]any{"name": t.Name, "parameters": schema}
			if t.Description != "" {
				fn["description"] = t.Description
			}
			tools = append(tools, map[string]any{"type": "function", "function": fn})
		}
		body["tools"] = tools
	}
	if req.ToolChoice != nil {
		switch req.ToolChoice.Mode {
		case ir.ToolChoiceAuto:
			body["tool_choice"] = "auto"
		case ir.ToolChoiceAny:
			body["tool_choice"] = "required"
		case ir.ToolChoiceNone:
			body["tool_choice"] = "none"
		case ir.ToolChoiceTool:
			body["tool_choice"] = map[string]any{"type": "function", "function": map[string]any{"name": req.ToolChoice.Name}}
		default:
			return nil, fmt.Errorf("openaichat: unknown tool choice mode %q", req.ToolChoice.Mode)
		}
		if req.ToolChoice.DisableParallel {
			body["parallel_tool_calls"] = false
		}
	}

	if req.MaxTokens != nil {
		if b.opts.UseMaxCompletionTokens {
			body["max_completion_tokens"] = *req.MaxTokens
		} else {
			body["max_tokens"] = *req.MaxTokens
		}
	}
	if req.Temperature != nil {
		body["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		body["top_p"] = *req.TopP
	}
	if req.TopK != nil {
		req.Loss.Add(ir.LossTopK)
	}
	if n := len(req.StopSequences); n > 0 {
		stop := req.StopSequences
		if n > maxStopSequences {
			stop = stop[:maxStopSequences]
			req.Loss.Add(ir.LossStopSequences)
		}
		body["stop"] = stop
	}
	if req.Reasoning != nil {
		body["reasoning_effort"] = reasoningEffort(req)
	}
	if req.Schema != nil {
		js := map[string]any{"name": req.Schema.Name, "schema": req.Schema.Schema}
		if req.Schema.Description != "" {
			js["description"] = req.Schema.Description
		}
		if req.Schema.Strict {
			js["strict"] = true
		}
		body["response_format"] = map[string]any{"type": "json_schema", "json_schema": js}
	}
	if req.UserID != "" {
		body["user"] = req.UserID
	}
	if req.LogProbs {
		body["logprobs"] = true
		// top_logprobs without logprobs:true is a 400 upstream, so the
		// count travels only with the flag that makes it legal.
		if req.TopLogProbs > 0 {
			body["top_logprobs"] = req.TopLogProbs
		}
	}
	if req.Stream {
		body["stream"] = true
		// Always opt into the final usage chunk so gateways can meter
		// streamed calls (mirrors lux's passthrough injection).
		body["stream_options"] = map[string]any{"include_usage": true}
	}
	return json.Marshal(body)
}

// Effort banding thresholds for Anthropic-style token budgets.
const (
	effortLowMaxBudget    = 2048
	effortMediumMaxBudget = 8192
)

// reasoningEffort maps an IR reasoning config to the OpenAI effort
// scale. Anthropic-style token budgets band by the thresholds above.
// The banding is an approximation, so the budget is recorded as a
// loss.
func reasoningEffort(req *ir.Request) string {
	r := req.Reasoning
	if r.Effort != "" {
		return string(r.Effort)
	}
	req.Loss.Add(ir.LossThinkingBudget)
	switch {
	case r.BudgetTokens <= effortLowMaxBudget:
		return string(ir.EffortLow)
	case r.BudgetTokens <= effortMediumMaxBudget:
		return string(ir.EffortMedium)
	default:
		return string(ir.EffortHigh)
	}
}

// encodeSystem folds the IR system blocks into one system message.
func encodeSystem(req *ir.Request) map[string]any {
	var parts []string
	for _, blk := range req.System {
		if blk.CacheHint {
			req.Loss.Add(ir.LossCacheControl)
		}
		if blk.Type == ir.BlockText {
			parts = append(parts, blk.Text)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return map[string]any{"role": "system", "content": strings.Join(parts, "\n\n")}
}

// encodeMessage converts one IR message into one or more Chat
// Completions messages: tool results become role-"tool" messages, the
// remainder of a user turn becomes a user message, an assistant turn
// becomes an assistant message with tool_calls.
func encodeMessage(m ir.Message, req *ir.Request) ([]map[string]any, error) {
	var out []map[string]any
	switch m.Role {
	case ir.RoleUser:
		var content []map[string]any
		textOnly := true
		flushContent := func() {
			if len(content) == 0 {
				return
			}
			msg := map[string]any{"role": "user"}
			if textOnly && len(content) == 1 {
				msg["content"] = content[0]["text"]
			} else {
				msg["content"] = content
			}
			out = append(out, msg)
			content = nil
			textOnly = true
		}
		for _, blk := range m.Blocks {
			if blk.CacheHint {
				req.Loss.Add(ir.LossCacheControl)
			}
			switch blk.Type {
			case ir.BlockToolResult:
				flushContent()
				out = append(out, encodeToolResult(blk, req))
			case ir.BlockText:
				content = append(content, map[string]any{"type": "text", "text": blk.Text})
			case ir.BlockImage:
				textOnly = false
				content = append(content, map[string]any{"type": "image_url", "image_url": map[string]any{"url": imageURL(blk.Image)}})
			default:
				return nil, fmt.Errorf("block type %q not allowed in a user message", blk.Type)
			}
		}
		flushContent()
	case ir.RoleAssistant:
		var texts []string
		var toolCalls []map[string]any
		for _, blk := range m.Blocks {
			switch blk.Type {
			case ir.BlockText:
				texts = append(texts, blk.Text)
			case ir.BlockToolUse:
				args := string(blk.ToolUse.Args)
				if args == "" {
					args = "{}"
				}
				toolCalls = append(toolCalls, map[string]any{
					"id":   blk.ToolUse.ID,
					"type": "function",
					"function": map[string]any{
						"name":      blk.ToolUse.Name,
						"arguments": args,
					},
				})
			case ir.BlockThinking, ir.BlockRedactedThinking:
				// Never replayed toward a non-Anthropic backend
				// (signatures cannot be preserved).
				req.Loss.Add(ir.LossThinking)
			default:
				return nil, fmt.Errorf("block type %q not allowed in an assistant message", blk.Type)
			}
		}
		msg := map[string]any{"role": "assistant"}
		if len(texts) > 0 {
			msg["content"] = strings.Join(texts, "\n\n")
		} else {
			msg["content"] = nil
		}
		if len(toolCalls) > 0 {
			msg["tool_calls"] = toolCalls
		}
		out = append(out, msg)
	default:
		return nil, fmt.Errorf("unknown role %q", m.Role)
	}
	return out, nil
}

func encodeToolResult(blk ir.Block, req *ir.Request) map[string]any {
	tr := blk.ToolResult
	var texts []string
	for _, inner := range tr.Blocks {
		switch inner.Type {
		case ir.BlockText:
			texts = append(texts, inner.Text)
		case ir.BlockImage:
			// The tool role only carries text in this dialect.
			req.Loss.Add(ir.LossToolResultImage)
		}
	}
	if tr.IsError {
		// No error flag exists on tool messages; the text itself must
		// convey the failure (harnesses already phrase it that way).
		req.Loss.Add(ir.LossToolResultIsError)
	}
	return map[string]any{
		"role":         "tool",
		"tool_call_id": tr.ToolUseID,
		"content":      strings.Join(texts, "\n\n"),
	}
}

func imageURL(img *ir.Image) string {
	if img.URL != "" {
		return img.URL
	}
	return "data:" + img.MediaType + ";base64," + img.Data
}

// wireUsage is the Chat Completions usage object.
type wireUsage struct {
	PromptTokens        int64 `json:"prompt_tokens"`
	CompletionTokens    int64 `json:"completion_tokens"`
	PromptTokensDetails struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionTokensDetails struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

// toUsage converts wire usage to IR semantics: IR input tokens exclude
// cache reads (Anthropic convention), while prompt_tokens includes
// them.
func (u *wireUsage) toUsage() *ir.Usage {
	in := max(u.PromptTokens-u.PromptTokensDetails.CachedTokens, 0)
	return &ir.Usage{
		InputTokens:          in,
		OutputTokens:         u.CompletionTokens,
		CacheReadInputTokens: u.PromptTokensDetails.CachedTokens,
		ReasoningTokens:      u.CompletionTokensDetails.ReasoningTokens,
	}
}

// wireLogProbs is the per-choice logprobs object, on the response body
// and on every stream chunk alike.
type wireLogProbs struct {
	Content []wireTokenLogProb `json:"content"`
}

// wireTokenLogProb is one token's entry. Bytes is a JSON array of
// integers here, not the base64 string encoding/json gives a []byte, so
// it decodes through []int.
type wireTokenLogProb struct {
	Token   string             `json:"token"`
	LogProb ir.LogProb         `json:"logprob"`
	Bytes   []int              `json:"bytes"`
	Top     []wireTokenLogProb `json:"top_logprobs"`
}

func (w *wireLogProbs) toIR() []ir.TokenLogProb {
	if w == nil {
		return nil
	}
	return tokenLogProbsToIR(w.Content)
}

func tokenLogProbsToIR(in []wireTokenLogProb) []ir.TokenLogProb {
	if len(in) == 0 {
		return nil
	}
	out := make([]ir.TokenLogProb, len(in))
	for i, w := range in {
		out[i] = ir.TokenLogProb{
			Token:   w.Token,
			Bytes:   bytesFromInts(w.Bytes),
			LogProb: w.LogProb,
			Top:     tokenLogProbsToIR(w.Top),
		}
	}
	return out
}

// bytesFromInts narrows the wire's integer array. A value outside a
// byte is not a UTF-8 byte and the entry is dropped rather than
// truncated: a wrong byte reconstructs wrong text.
func bytesFromInts(in []int) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, 0, len(in))
	for _, v := range in {
		if v < 0 || v > 255 {
			return nil
		}
		out = append(out, byte(v))
	}
	return out
}

type wireToolCall struct {
	Index    *int   `json:"index"`
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// DecodeResponse parses a non-streaming Chat Completions response into
// the IR.
func (*Backend) DecodeResponse(body []byte) (*ir.Response, error) {
	var wire struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content          *string        `json:"content"`
				Refusal          *string        `json:"refusal"`
				ReasoningContent string         `json:"reasoning_content"`
				ToolCalls        []wireToolCall `json:"tool_calls"`
			} `json:"message"`
			LogProbs     *wireLogProbs `json:"logprobs"`
			FinishReason string        `json:"finish_reason"`
		} `json:"choices"`
		Usage *wireUsage `json:"usage"`
		Error *wireError `json:"error"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("openaichat: invalid response JSON: %w", err)
	}
	if wire.Error != nil {
		return nil, wire.Error
	}
	if len(wire.Choices) == 0 {
		return nil, fmt.Errorf("openaichat: response has no choices")
	}
	choice := wire.Choices[0]

	resp := &ir.Response{ID: wire.ID, Model: wire.Model}
	if choice.Message.ReasoningContent != "" {
		resp.Blocks = append(resp.Blocks, ir.Block{Type: ir.BlockThinking, Text: choice.Message.ReasoningContent})
	}
	if choice.Message.Content != nil && *choice.Message.Content != "" {
		resp.Blocks = append(resp.Blocks, ir.Block{Type: ir.BlockText, Text: *choice.Message.Content})
	}
	if choice.Message.Refusal != nil && *choice.Message.Refusal != "" {
		resp.Blocks = append(resp.Blocks, ir.Block{Type: ir.BlockText, Text: *choice.Message.Refusal})
		resp.StopReason = ir.StopRefusal
	}
	for _, tc := range choice.Message.ToolCalls {
		resp.Blocks = append(resp.Blocks, ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{
			ID: tc.ID, Name: tc.Function.Name, Args: json.RawMessage(tc.Function.Arguments),
		}})
	}
	resp.LogProbs = choice.LogProbs.toIR()
	if resp.StopReason == "" {
		resp.StopReason = stopReason(choice.FinishReason, len(choice.Message.ToolCalls) > 0)
	}
	if wire.Usage != nil {
		resp.Usage = *wire.Usage.toUsage()
	}
	return resp, nil
}

type wireError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (e *wireError) Error() string {
	return fmt.Sprintf("openaichat: upstream error (%s): %s", e.Type, e.Message)
}

// stopReason maps finish_reason to the IR vocabulary. Some
// openai-compatible runtimes report "stop" even when tool calls were
// emitted; the presence of tool calls wins so harnesses run their tool
// loop.
func stopReason(finish string, hasToolCalls bool) ir.StopReason {
	switch finish {
	case "tool_calls", "function_call":
		return ir.StopToolUse
	case "length":
		return ir.StopMaxTokens
	case "content_filter":
		return ir.StopRefusal
	default:
		if hasToolCalls {
			return ir.StopToolUse
		}
		return ir.StopEndTurn
	}
}

// NewEventDecoder returns a decoder for a Chat Completions SSE stream.
func (*Backend) NewEventDecoder(r io.Reader) ir.EventDecoder {
	return &EventDecoder{r: sse.NewReader(r), openTool: -1}
}

// blockKind tracks which output block is currently open while decoding
// the stream.
type blockKind int

const (
	blockNone blockKind = iota
	blockThinking
	blockText
	blockTool
)

// EventDecoder converts Chat Completions chunks into canonical IR
// events incrementally: one chunk in, zero or more events out.
type EventDecoder struct {
	r *sse.Reader

	pending   []ir.Event
	started   bool
	finished  bool
	nextIndex int
	open      blockKind
	openIndex int
	openTool  int // upstream tool_calls index of the open tool block
	toolIndex map[int]int
	stop      ir.StopReason
	usage     *ir.Usage
}

// Next returns the next IR event, or io.EOF after MessageStop.
func (d *EventDecoder) Next() (ir.Event, error) {
	for {
		if len(d.pending) > 0 {
			ev := d.pending[0]
			d.pending = d.pending[1:]
			return ev, nil
		}
		if d.finished {
			return ir.Event{}, io.EOF
		}
		frame, err := d.r.Next()
		if err == io.EOF {
			// Upstream closed without [DONE] (some runtimes do); still
			// emit a well-formed tail.
			d.finish()
			continue
		}
		if err != nil {
			return ir.Event{}, err
		}
		if string(frame.Data) == "[DONE]" {
			d.finish()
			continue
		}
		if err := d.consume(frame.Data); err != nil {
			return ir.Event{}, err
		}
	}
}

func (d *EventDecoder) finish() {
	d.closeOpenBlock()
	d.pending = append(d.pending,
		ir.Event{Type: ir.EventMessageDelta, StopReason: d.stopOrDefault(), Usage: d.usage},
		ir.Event{Type: ir.EventMessageStop},
	)
	d.finished = true
}

func (d *EventDecoder) stopOrDefault() ir.StopReason {
	if d.stop == "" {
		return ir.StopEndTurn
	}
	return d.stop
}

func (d *EventDecoder) consume(data []byte) error {
	var chunk struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Index int `json:"index"`
			Delta struct {
				Content          *string        `json:"content"`
				ReasoningContent string         `json:"reasoning_content"`
				ToolCalls        []wireToolCall `json:"tool_calls"`
			} `json:"delta"`
			LogProbs     *wireLogProbs `json:"logprobs"`
			FinishReason string        `json:"finish_reason"`
		} `json:"choices"`
		Usage *wireUsage `json:"usage"`
		Error *wireError `json:"error"`
	}
	if err := json.Unmarshal(data, &chunk); err != nil {
		return fmt.Errorf("openaichat: invalid stream chunk: %w", err)
	}
	if chunk.Error != nil {
		return chunk.Error
	}
	if !d.started {
		d.started = true
		d.pending = append(d.pending, ir.Event{Type: ir.EventMessageStart, ID: chunk.ID, Model: chunk.Model})
	}
	if chunk.Usage != nil {
		d.usage = chunk.Usage.toUsage()
	}
	for _, c := range chunk.Choices {
		if c.Index != 0 {
			continue // n>1 is not part of the IR; only choice 0 streams through
		}
		if rc := c.Delta.ReasoningContent; rc != "" {
			d.ensureBlock(blockThinking, ir.Block{Type: ir.BlockThinking})
			d.pending = append(d.pending, ir.Event{Type: ir.EventThinkingDelta, Index: d.openIndex, Delta: rc})
		}
		if c.Delta.Content != nil && *c.Delta.Content != "" {
			d.ensureBlock(blockText, ir.Block{Type: ir.BlockText})
			// The chunk's logprobs are the tokens this text delta
			// decodes from, so they ride the same IR event and the
			// stream stays translatable one event at a time.
			d.pending = append(d.pending, ir.Event{Type: ir.EventTextDelta, Index: d.openIndex,
				Delta: *c.Delta.Content, LogProbs: c.LogProbs.toIR()})
		}
		for _, tc := range c.Delta.ToolCalls {
			d.consumeToolDelta(tc)
		}
		if c.FinishReason != "" {
			d.stop = stopReason(c.FinishReason, len(d.toolIndex) > 0)
		}
	}
	return nil
}

// ensureBlock opens a block of the wanted kind, closing any different
// open block first.
func (d *EventDecoder) ensureBlock(kind blockKind, header ir.Block) {
	if d.open == kind {
		return
	}
	d.closeOpenBlock()
	d.open = kind
	d.openIndex = d.nextIndex
	d.nextIndex++
	h := header
	d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStart, Index: d.openIndex, Block: &h})
}

func (d *EventDecoder) consumeToolDelta(tc wireToolCall) {
	upstream := 0
	if tc.Index != nil {
		upstream = *tc.Index
	}
	if d.toolIndex == nil {
		d.toolIndex = make(map[int]int)
	}
	irIdx, seen := d.toolIndex[upstream]
	if !seen {
		d.closeOpenBlock()
		d.open = blockTool
		d.openTool = upstream
		irIdx = d.nextIndex
		d.nextIndex++
		d.openIndex = irIdx
		d.toolIndex[upstream] = irIdx
		d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStart, Index: irIdx, Block: &ir.Block{
			Type:    ir.BlockToolUse,
			ToolUse: &ir.ToolUse{ID: tc.ID, Name: tc.Function.Name},
		}})
	}
	if args := tc.Function.Arguments; args != "" {
		d.pending = append(d.pending, ir.Event{Type: ir.EventArgsDelta, Index: irIdx, Delta: args})
	}
}

func (d *EventDecoder) closeOpenBlock() {
	if d.open == blockNone {
		return
	}
	d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStop, Index: d.openIndex})
	d.open = blockNone
	d.openTool = -1
}
