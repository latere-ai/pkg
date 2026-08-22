package openaichat

// Frontend (caller-side) codec: decodes a Chat Completions request
// into the IR, encodes IR responses back to Chat Completions bodies,
// and re-synthesizes the chunked SSE stream from canonical IR events.

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"latere.ai/x/pkg/llmdialect/internal/sse"
	"latere.ai/x/pkg/llmdialect/ir"
)

// Frontend is the caller-side Chat Completions codec.
type Frontend struct{}

// NewFrontend returns the Chat Completions frontend codec.
func NewFrontend() *Frontend { return &Frontend{} }

// Name returns the dialect name.
func (*Frontend) Name() ir.Dialect { return DialectName }

// requestKeys are the top-level request fields the decoder
// understands. Anything else lands in the loss report.
var requestKeys = map[string]bool{
	"model": true, "messages": true, "tools": true, "tool_choice": true,
	"parallel_tool_calls": true, "max_tokens": true, "max_completion_tokens": true,
	"temperature": true, "top_p": true, "stop": true, "stream": true,
	"stream_options": true, "user": true, "response_format": true,
	"reasoning_effort": true, "n": true,
}

// DecodeRequest parses a Chat Completions request body into the IR.
func (*Frontend) DecodeRequest(body []byte) (*ir.Request, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("openaichat: invalid request JSON: %w", err)
	}
	req := &ir.Request{}
	for k := range top {
		if !requestKeys[k] {
			req.Loss.Add(ir.LossRequestFieldOf(k))
		}
	}

	var wire struct {
		Model               string          `json:"model"`
		Messages            []frontMessage  `json:"messages"`
		Tools               []frontTool     `json:"tools"`
		ToolChoice          json.RawMessage `json:"tool_choice"`
		ParallelToolCalls   *bool           `json:"parallel_tool_calls"`
		MaxTokens           *int64          `json:"max_tokens"`
		MaxCompletionTokens *int64          `json:"max_completion_tokens"`
		Temperature         *float64        `json:"temperature"`
		TopP                *float64        `json:"top_p"`
		Stop                json.RawMessage `json:"stop"`
		Stream              bool            `json:"stream"`
		User                string          `json:"user"`
		ResponseFormat      *struct {
			Type       string `json:"type"`
			JSONSchema *struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Schema      json.RawMessage `json:"schema"`
				Strict      bool            `json:"strict"`
			} `json:"json_schema"`
		} `json:"response_format"`
		ReasoningEffort string `json:"reasoning_effort"`
		N               *int   `json:"n"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("openaichat: malformed request: %w", err)
	}
	if wire.Model == "" {
		return nil, fmt.Errorf("openaichat: model is required")
	}
	if len(wire.Messages) == 0 {
		return nil, fmt.Errorf("openaichat: messages is required")
	}
	if wire.N != nil && *wire.N > 1 {
		return nil, fmt.Errorf("openaichat: n>1 is not supported on this surface")
	}

	req.Model = wire.Model
	req.Temperature = wire.Temperature
	req.TopP = wire.TopP
	req.Stream = wire.Stream
	req.UserID = wire.User
	req.MaxTokens = wire.MaxCompletionTokens
	if req.MaxTokens == nil {
		req.MaxTokens = wire.MaxTokens
	}
	if len(wire.Stop) > 0 {
		stop, err := decodeStop(wire.Stop)
		if err != nil {
			return nil, err
		}
		req.StopSequences = stop
	}
	if err := decodeFrontMessages(req, wire.Messages); err != nil {
		return nil, err
	}
	for _, t := range wire.Tools {
		if t.Type != "" && t.Type != "function" {
			req.Loss.Add(ir.LossToolTypeOf(t.Type))
			continue
		}
		if t.Function.Strict {
			req.Loss.Add(ir.LossToolStrict)
		}
		req.Tools = append(req.Tools, ir.Tool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			InputSchema: t.Function.Parameters,
		})
	}
	if len(wire.ToolChoice) > 0 {
		tc, err := decodeFrontToolChoice(wire.ToolChoice)
		if err != nil {
			return nil, err
		}
		req.ToolChoice = tc
	}
	if wire.ParallelToolCalls != nil && !*wire.ParallelToolCalls {
		if req.ToolChoice == nil {
			req.ToolChoice = &ir.ToolChoice{Mode: ir.ToolChoiceAuto}
		}
		req.ToolChoice.DisableParallel = true
	}
	if wire.ReasoningEffort != "" {
		req.Reasoning = &ir.Reasoning{Effort: ir.Effort(wire.ReasoningEffort)}
	}
	if wire.ResponseFormat != nil {
		switch wire.ResponseFormat.Type {
		case "", "text":
		case "json_schema":
			if wire.ResponseFormat.JSONSchema == nil {
				return nil, fmt.Errorf("openaichat: response_format json_schema missing schema")
			}
			js := wire.ResponseFormat.JSONSchema
			req.Schema = &ir.ResponseSchema{Name: js.Name, Description: js.Description, Schema: js.Schema, Strict: js.Strict}
		default:
			// json_object has no cross-dialect equivalent.
			req.Loss.Add(ir.LossResponseFormatOf(wire.ResponseFormat.Type))
		}
	}
	return req, nil
}

type frontMessage struct {
	Role             string          `json:"role"`
	Content          json.RawMessage `json:"content"`
	ToolCalls        []wireToolCall  `json:"tool_calls"`
	ToolCallID       string          `json:"tool_call_id"`
	ReasoningContent string          `json:"reasoning_content"`
}

type frontTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
		Strict      bool            `json:"strict"`
	} `json:"function"`
}

func decodeStop(raw json.RawMessage) ([]string, error) {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("openaichat: stop must be a string or string array")
	}
	return many, nil
}

// decodeFrontMessages folds the Chat Completions message list into the
// IR shape: system/developer turns join the system prompt, consecutive
// role-"tool" messages coalesce into one user turn of tool_result
// blocks (the Anthropic layout).
func decodeFrontMessages(req *ir.Request, msgs []frontMessage) error {
	for i := 0; i < len(msgs); i++ {
		m := msgs[i]
		switch m.Role {
		case "system", "developer":
			text, err := decodeFrontText(m.Content)
			if err != nil {
				return fmt.Errorf("openaichat: messages[%d]: %w", i, err)
			}
			req.System = append(req.System, ir.Block{Type: ir.BlockText, Text: text})
		case "user":
			blocks, err := decodeFrontUserContent(m.Content, &req.Loss)
			if err != nil {
				return fmt.Errorf("openaichat: messages[%d]: %w", i, err)
			}
			req.Messages = append(req.Messages, ir.Message{Role: ir.RoleUser, Blocks: blocks})
		case "assistant":
			var blocks []ir.Block
			if m.ReasoningContent != "" {
				blocks = append(blocks, ir.Block{Type: ir.BlockThinking, Text: m.ReasoningContent})
			}
			if len(m.Content) > 0 && string(m.Content) != "null" {
				text, err := decodeFrontText(m.Content)
				if err != nil {
					return fmt.Errorf("openaichat: messages[%d]: %w", i, err)
				}
				if text != "" {
					blocks = append(blocks, ir.Block{Type: ir.BlockText, Text: text})
				}
			}
			for _, tc := range m.ToolCalls {
				blocks = append(blocks, ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{
					ID: tc.ID, Name: tc.Function.Name, Args: json.RawMessage(tc.Function.Arguments),
				}})
			}
			req.Messages = append(req.Messages, ir.Message{Role: ir.RoleAssistant, Blocks: blocks})
		case "tool":
			var blocks []ir.Block
			for ; i < len(msgs) && msgs[i].Role == "tool"; i++ {
				text, err := decodeFrontText(msgs[i].Content)
				if err != nil {
					return fmt.Errorf("openaichat: messages[%d]: %w", i, err)
				}
				blocks = append(blocks, ir.Block{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{
					ToolUseID: msgs[i].ToolCallID,
					Blocks:    []ir.Block{{Type: ir.BlockText, Text: text}},
				}})
			}
			i--
			req.Messages = append(req.Messages, ir.Message{Role: ir.RoleUser, Blocks: blocks})
		default:
			return fmt.Errorf("openaichat: messages[%d]: unknown role %q", i, m.Role)
		}
	}
	return nil
}

// decodeFrontText accepts the string and text-parts forms of content.
func decodeFrontText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", fmt.Errorf("content must be a string or content parts")
	}
	var texts []string
	for _, p := range parts {
		if p.Type == "text" {
			texts = append(texts, p.Text)
		}
	}
	return strings.Join(texts, "\n\n"), nil
}

func decodeFrontUserContent(raw json.RawMessage, loss *ir.Loss) ([]ir.Block, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []ir.Block{{Type: ir.BlockText, Text: s}}, nil
	}
	var parts []struct {
		Type     string `json:"type"`
		Text     string `json:"text"`
		ImageURL *struct {
			URL string `json:"url"`
		} `json:"image_url"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, fmt.Errorf("content must be a string or content parts")
	}
	var out []ir.Block
	for _, p := range parts {
		switch p.Type {
		case "text":
			out = append(out, ir.Block{Type: ir.BlockText, Text: p.Text})
		case "image_url":
			if p.ImageURL == nil {
				return nil, fmt.Errorf("image_url part missing url")
			}
			img, err := decodeImageURL(p.ImageURL.URL)
			if err != nil {
				return nil, err
			}
			out = append(out, ir.Block{Type: ir.BlockImage, Image: img})
		default:
			loss.Add(ir.LossContentTypeOf(p.Type))
		}
	}
	return out, nil
}

// decodeImageURL splits a data URI into inline image data, or keeps an
// https URL as-is.
func decodeImageURL(url string) (*ir.Image, error) {
	if !strings.HasPrefix(url, "data:") {
		return &ir.Image{URL: url}, nil
	}
	rest := strings.TrimPrefix(url, "data:")
	before, after, ok := strings.Cut(rest, ";base64,")
	if !ok {
		return nil, fmt.Errorf("unsupported data URI (want ;base64,)")
	}
	return &ir.Image{MediaType: before, Data: after}, nil
}

func decodeFrontToolChoice(raw json.RawMessage) (*ir.ToolChoice, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch s {
		case "auto":
			return &ir.ToolChoice{Mode: ir.ToolChoiceAuto}, nil
		case "required":
			return &ir.ToolChoice{Mode: ir.ToolChoiceAny}, nil
		case "none":
			return &ir.ToolChoice{Mode: ir.ToolChoiceNone}, nil
		default:
			return nil, fmt.Errorf("openaichat: unknown tool_choice %q", s)
		}
	}
	var named struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &named); err != nil || named.Function.Name == "" {
		return nil, fmt.Errorf("openaichat: malformed tool_choice")
	}
	return &ir.ToolChoice{Mode: ir.ToolChoiceTool, Name: named.Function.Name}, nil
}

// EncodeResponse renders an IR response as a Chat Completions body.
func (*Frontend) EncodeResponse(resp *ir.Response) ([]byte, error) {
	message := map[string]any{"role": "assistant"}
	var texts, thinking []string
	var toolCalls []map[string]any
	for _, b := range resp.Blocks {
		switch b.Type {
		case ir.BlockText:
			texts = append(texts, b.Text)
		case ir.BlockThinking:
			thinking = append(thinking, b.Text)
		case ir.BlockRedactedThinking:
			// Opaque; nothing representable.
		case ir.BlockToolUse:
			args := string(b.ToolUse.Args)
			if args == "" {
				args = "{}"
			}
			toolCalls = append(toolCalls, map[string]any{
				"id": b.ToolUse.ID, "type": "function",
				"function": map[string]any{"name": b.ToolUse.Name, "arguments": args},
			})
		default:
			return nil, fmt.Errorf("openaichat: block type %q not representable in a response", b.Type)
		}
	}
	if len(texts) > 0 {
		message["content"] = strings.Join(texts, "\n\n")
	} else {
		message["content"] = nil
	}
	if len(thinking) > 0 {
		message["reasoning_content"] = strings.Join(thinking, "\n\n")
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	out := map[string]any{
		"id":      resp.ID,
		"object":  "chat.completion",
		"created": 0,
		"model":   resp.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason(resp.StopReason),
		}},
		"usage": encodeFrontUsage(resp.Usage),
	}
	return json.Marshal(out)
}

// finishReason maps the IR stop vocabulary to finish_reason.
func finishReason(stop ir.StopReason) string {
	switch stop {
	case ir.StopToolUse:
		return "tool_calls"
	case ir.StopMaxTokens:
		return "length"
	case ir.StopRefusal:
		return "content_filter"
	default: // end_turn, stop_sequence, ""
		return "stop"
	}
}

// encodeFrontUsage converts IR usage back to the Chat Completions
// shape: prompt_tokens includes cache reads, with the cached share in
// prompt_tokens_details.
func encodeFrontUsage(u ir.Usage) map[string]any {
	return map[string]any{
		"prompt_tokens":     u.InputTokens + u.CacheReadInputTokens,
		"completion_tokens": u.OutputTokens,
		"total_tokens":      u.InputTokens + u.CacheReadInputTokens + u.OutputTokens,
		"prompt_tokens_details": map[string]any{
			"cached_tokens": u.CacheReadInputTokens,
		},
		"completion_tokens_details": map[string]any{
			"reasoning_tokens": u.ReasoningTokens,
		},
	}
}

// NewEventEncoder returns an encoder writing Chat Completions SSE
// chunks to w.
func (*Frontend) NewEventEncoder(w io.Writer) ir.EventEncoder {
	return &frontEventEncoder{w: sse.NewWriter(w)}
}

// frontEventEncoder re-synthesizes chat.completion.chunk frames plus
// the trailing usage chunk and [DONE] marker from IR events.
type frontEventEncoder struct {
	w        *sse.Writer
	id       string
	model    string
	toolIdx  int  // next tool_calls index to assign
	openTool bool // whether the currently open block is a tool call
	curTool  int  // tool_calls index of the open tool block
}

// Encode writes the SSE frame(s) for one IR event.
func (e *frontEventEncoder) Encode(ev ir.Event) error {
	switch ev.Type {
	case ir.EventMessageStart:
		e.id = ev.ID
		e.model = ev.Model
		return e.chunk(map[string]any{"role": "assistant"}, nil, nil)
	case ir.EventBlockStart:
		if ev.Block == nil {
			return fmt.Errorf("openaichat: block_start event missing block header")
		}
		e.openTool = false
		if ev.Block.Type == ir.BlockToolUse {
			e.openTool = true
			e.curTool = e.toolIdx
			e.toolIdx++
			return e.chunk(map[string]any{"tool_calls": []map[string]any{{
				"index": e.curTool,
				"id":    ev.Block.ToolUse.ID,
				"type":  "function",
				"function": map[string]any{
					"name":      ev.Block.ToolUse.Name,
					"arguments": "",
				},
			}}}, nil, nil)
		}
		return nil
	case ir.EventTextDelta:
		return e.chunk(map[string]any{"content": ev.Delta}, nil, nil)
	case ir.EventThinkingDelta:
		return e.chunk(map[string]any{"reasoning_content": ev.Delta}, nil, nil)
	case ir.EventArgsDelta:
		if !e.openTool {
			return fmt.Errorf("openaichat: args delta outside a tool block")
		}
		return e.chunk(map[string]any{"tool_calls": []map[string]any{{
			"index":    e.curTool,
			"function": map[string]any{"arguments": ev.Delta},
		}}}, nil, nil)
	case ir.EventSignatureDelta, ir.EventBlockStop:
		return nil
	case ir.EventMessageDelta:
		finish := finishReason(ev.StopReason)
		if err := e.chunk(map[string]any{}, &finish, nil); err != nil {
			return err
		}
		if ev.Usage != nil {
			return e.usageChunk(*ev.Usage)
		}
		return nil
	case ir.EventMessageStop:
		return e.w.WriteEvent("", []byte("[DONE]"))
	default:
		return fmt.Errorf("openaichat: unknown event type %q", ev.Type)
	}
}

func (e *frontEventEncoder) chunk(delta map[string]any, finish *string, usage map[string]any) error {
	choice := map[string]any{"index": 0, "delta": delta}
	if finish != nil {
		choice["finish_reason"] = *finish
	}
	body := map[string]any{
		"id":      e.id,
		"object":  "chat.completion.chunk",
		"created": 0,
		"model":   e.model,
		"choices": []map[string]any{choice},
	}
	if usage != nil {
		body["usage"] = usage
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return e.w.WriteEvent("", raw)
}

// usageChunk emits the final usage-only chunk (the
// stream_options.include_usage convention: empty choices).
func (e *frontEventEncoder) usageChunk(u ir.Usage) error {
	raw, err := json.Marshal(map[string]any{
		"id":      e.id,
		"object":  "chat.completion.chunk",
		"created": 0,
		"model":   e.model,
		"choices": []any{},
		"usage":   encodeFrontUsage(u),
	})
	if err != nil {
		return err
	}
	return e.w.WriteEvent("", raw)
}
