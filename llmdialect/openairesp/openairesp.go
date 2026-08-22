// Package openairesp implements the OpenAI Responses dialect for
// llmdialect — the wire shape Codex speaks. It ships both codecs, and
// only the stateless subset: requests carrying previous_response_id or
// store:true are rejected, since the translation layer stores nothing.
// Reasoning items cannot be replayed across providers (their content is
// provider-encrypted) and land in the loss report.
//
// The frontend (caller side, openairesp.go) lets Codex point at the
// compat surface. The backend (upstream side, backend.go) drives a
// Responses-native model from another dialect — the path that lets a
// Messages- or Chat-dialect client reach an OpenAI reasoning model,
// which requires the Responses API for function tools.
package openairesp

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"latere.ai/x/pkg/llmdialect/internal/sse"
	"latere.ai/x/pkg/llmdialect/ir"
)

// DialectName identifies this dialect.
const DialectName = ir.DialectOpenAIResponses

// Frontend is the caller-side Responses codec.
type Frontend struct{}

// NewFrontend returns the Responses frontend codec.
func NewFrontend() *Frontend { return &Frontend{} }

// Name returns the dialect name.
func (*Frontend) Name() ir.Dialect { return DialectName }

// requestKeys are the top-level Responses request fields the decoder
// understands. Anything else lands in the loss report.
var requestKeys = map[string]bool{
	"model": true, "input": true, "instructions": true,
	"max_output_tokens": true, "temperature": true, "top_p": true,
	"stream": true, "tools": true, "tool_choice": true,
	"parallel_tool_calls": true, "reasoning": true, "text": true,
	"store": true, "previous_response_id": true, "user": true,
	"metadata": true, "include": true,
}

// DecodeRequest parses a stateless Responses API request into the IR.
func (*Frontend) DecodeRequest(body []byte) (*ir.Request, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("openairesp: invalid request JSON: %w", err)
	}
	req := &ir.Request{}
	for k := range top {
		if !requestKeys[k] {
			req.Loss.Add(ir.LossRequestFieldOf(k))
		}
	}

	var wire struct {
		Model             string          `json:"model"`
		Input             json.RawMessage `json:"input"`
		Instructions      string          `json:"instructions"`
		MaxOutputTokens   *int64          `json:"max_output_tokens"`
		Temperature       *float64        `json:"temperature"`
		TopP              *float64        `json:"top_p"`
		Stream            bool            `json:"stream"`
		Tools             []respTool      `json:"tools"`
		ToolChoice        json.RawMessage `json:"tool_choice"`
		ParallelToolCalls *bool           `json:"parallel_tool_calls"`
		Reasoning         *struct {
			Effort  string          `json:"effort"`
			Summary json.RawMessage `json:"summary"`
		} `json:"reasoning"`
		Text *struct {
			Format *struct {
				Type        string          `json:"type"`
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Schema      json.RawMessage `json:"schema"`
				Strict      bool            `json:"strict"`
			} `json:"format"`
			Verbosity string `json:"verbosity"`
		} `json:"text"`
		Store              *bool           `json:"store"`
		PreviousResponseID string          `json:"previous_response_id"`
		User               string          `json:"user"`
		Include            json.RawMessage `json:"include"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("openairesp: malformed request: %w", err)
	}
	if wire.Model == "" {
		return nil, fmt.Errorf("openairesp: model is required")
	}
	if wire.PreviousResponseID != "" {
		return nil, fmt.Errorf("openairesp: previous_response_id is not supported on this surface (stateless only)")
	}
	if wire.Store != nil && *wire.Store {
		return nil, fmt.Errorf("openairesp: store:true is not supported on this surface (stateless only)")
	}
	if len(wire.Include) > 0 {
		req.Loss.Add(ir.LossInclude)
	}

	req.Model = wire.Model
	req.MaxTokens = wire.MaxOutputTokens
	req.Temperature = wire.Temperature
	req.TopP = wire.TopP
	req.Stream = wire.Stream
	req.UserID = wire.User
	if wire.Instructions != "" {
		req.System = append(req.System, ir.Block{Type: ir.BlockText, Text: wire.Instructions})
	}
	if err := decodeInput(req, wire.Input); err != nil {
		return nil, err
	}
	if len(req.Messages) == 0 {
		return nil, fmt.Errorf("openairesp: input is required")
	}
	for _, t := range wire.Tools {
		if t.Type != "" && t.Type != "function" {
			req.Loss.Add(ir.LossToolTypeOf(t.Type))
			continue
		}
		if t.Strict {
			req.Loss.Add(ir.LossToolStrict)
		}
		req.Tools = append(req.Tools, ir.Tool{Name: t.Name, Description: t.Description, InputSchema: t.Parameters})
	}
	if len(wire.ToolChoice) > 0 {
		tc, err := decodeToolChoice(wire.ToolChoice)
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
	if wire.Reasoning != nil {
		if wire.Reasoning.Effort != "" {
			req.Reasoning = &ir.Reasoning{Effort: ir.Effort(wire.Reasoning.Effort)}
		}
		if len(wire.Reasoning.Summary) > 0 {
			req.Loss.Add(ir.LossReasoningSummary)
		}
	}
	if wire.Text != nil {
		if wire.Text.Verbosity != "" {
			req.Loss.Add(ir.LossTextVerbosity)
		}
		if f := wire.Text.Format; f != nil {
			switch f.Type {
			case "", "text":
			case "json_schema":
				req.Schema = &ir.ResponseSchema{Name: f.Name, Description: f.Description, Schema: f.Schema, Strict: f.Strict}
			default:
				req.Loss.Add(ir.LossTextFormatOf(f.Type))
			}
		}
	}
	return req, nil
}

type respTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
	Strict      bool            `json:"strict"`
}

type respItem struct {
	Type    string          `json:"type"`
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
	// function_call / function_call_output fields.
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
	Output    string `json:"output"`
}

// decodeInput accepts the string form (one user message) and the item
// list. Consecutive function_call items fold into one assistant turn
// and consecutive function_call_output items into one user turn (the
// Anthropic layout the IR uses).
func decodeInput(req *ir.Request, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		req.Messages = append(req.Messages, ir.Message{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: s}}})
		return nil
	}
	var items []respItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("openairesp: input must be a string or item array")
	}

	var pending *ir.Message
	flush := func() {
		if pending != nil && len(pending.Blocks) > 0 {
			req.Messages = append(req.Messages, *pending)
		}
		pending = nil
	}
	appendBlock := func(role ir.Role, blk ir.Block) {
		if pending == nil || pending.Role != role {
			flush()
			pending = &ir.Message{Role: role}
		}
		pending.Blocks = append(pending.Blocks, blk)
	}

	for i, item := range items {
		switch item.Type {
		case "", "message":
			role, blocks, err := decodeMessageItem(item, req)
			if err != nil {
				return fmt.Errorf("openairesp: input[%d]: %w", i, err)
			}
			if role == "" { // system/developer folded into System
				continue
			}
			for _, blk := range blocks {
				appendBlock(role, blk)
			}
		case "function_call":
			appendBlock(ir.RoleAssistant, ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{
				ID: item.CallID, Name: item.Name, Args: json.RawMessage(item.Arguments),
			}})
		case "function_call_output":
			appendBlock(ir.RoleUser, ir.Block{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{
				ToolUseID: item.CallID,
				Blocks:    []ir.Block{{Type: ir.BlockText, Text: item.Output}},
			}})
		case "reasoning":
			// Provider-encrypted; cannot be replayed across providers.
			req.Loss.Add(ir.LossReasoningItems)
		default:
			req.Loss.Add(ir.LossInputTypeOf(item.Type))
		}
	}
	flush()
	return nil
}

// decodeMessageItem returns the IR role and blocks for a message item.
// System/developer content folds into req.System and returns role "".
func decodeMessageItem(item respItem, req *ir.Request) (ir.Role, []ir.Block, error) {
	blocks, err := decodeItemContent(item.Content, req)
	if err != nil {
		return "", nil, err
	}
	switch item.Role {
	case "system", "developer":
		req.System = append(req.System, blocks...)
		return "", nil, nil
	case "user":
		return ir.RoleUser, blocks, nil
	case "assistant":
		return ir.RoleAssistant, blocks, nil
	default:
		return "", nil, fmt.Errorf("unknown role %q", item.Role)
	}
}

func decodeItemContent(raw json.RawMessage, req *ir.Request) ([]ir.Block, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []ir.Block{{Type: ir.BlockText, Text: s}}, nil
	}
	var parts []struct {
		Type     string `json:"type"`
		Text     string `json:"text"`
		ImageURL string `json:"image_url"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, fmt.Errorf("content must be a string or content parts")
	}
	var out []ir.Block
	for _, p := range parts {
		switch p.Type {
		case "input_text", "output_text", "text":
			out = append(out, ir.Block{Type: ir.BlockText, Text: p.Text})
		case "input_image":
			img, err := decodeImageURL(p.ImageURL)
			if err != nil {
				return nil, err
			}
			out = append(out, ir.Block{Type: ir.BlockImage, Image: img})
		default:
			req.Loss.Add(ir.LossContentTypeOf(p.Type))
		}
	}
	return out, nil
}

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

func decodeToolChoice(raw json.RawMessage) (*ir.ToolChoice, error) {
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
			return nil, fmt.Errorf("openairesp: unknown tool_choice %q", s)
		}
	}
	var named struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &named); err != nil || named.Name == "" {
		return nil, fmt.Errorf("openairesp: malformed tool_choice")
	}
	return &ir.ToolChoice{Mode: ir.ToolChoiceTool, Name: named.Name}, nil
}

// ── response encoding ───────────────────────────────────────────────

// buildOutput renders IR blocks as Responses output items. Text blocks
// coalesce into a single message item; thinking becomes a reasoning
// item with a summary; tool calls become function_call items.
func buildOutput(id string, blocks []ir.Block) []map[string]any {
	var output []map[string]any
	var texts []string
	itemID := func(prefix string) string {
		return fmt.Sprintf("%s_%s_%d", prefix, id, len(output))
	}
	flushText := func() {
		if len(texts) == 0 {
			return
		}
		output = append(output, map[string]any{
			"type": "message", "id": itemID("msg"), "status": "completed", "role": "assistant",
			"content": []map[string]any{{
				"type": "output_text", "text": strings.Join(texts, "\n\n"), "annotations": []any{},
			}},
		})
		texts = nil
	}
	for _, b := range blocks {
		switch b.Type {
		case ir.BlockText:
			texts = append(texts, b.Text)
		case ir.BlockThinking:
			flushText()
			output = append(output, map[string]any{
				"type": "reasoning", "id": itemID("rs"),
				"summary": []map[string]any{{"type": "summary_text", "text": b.Text}},
			})
		case ir.BlockToolUse:
			flushText()
			args := string(b.ToolUse.Args)
			if args == "" {
				args = "{}"
			}
			output = append(output, map[string]any{
				"type": "function_call", "id": itemID("fc"), "status": "completed",
				"call_id": b.ToolUse.ID, "name": b.ToolUse.Name, "arguments": args,
			})
		}
	}
	flushText()
	if output == nil {
		output = []map[string]any{}
	}
	return output
}

func encodeUsage(u ir.Usage) map[string]any {
	in := u.InputTokens + u.CacheReadInputTokens
	return map[string]any{
		"input_tokens":  in,
		"output_tokens": u.OutputTokens,
		"total_tokens":  in + u.OutputTokens,
		"input_tokens_details": map[string]any{
			"cached_tokens": u.CacheReadInputTokens,
		},
		"output_tokens_details": map[string]any{
			"reasoning_tokens": u.ReasoningTokens,
		},
	}
}

func responseEnvelope(resp *ir.Response) map[string]any {
	status := "completed"
	var incomplete any
	if resp.StopReason == ir.StopMaxTokens {
		status = "incomplete"
		incomplete = map[string]any{"reason": "max_output_tokens"}
	}
	return map[string]any{
		"id":                 "resp_" + resp.ID,
		"object":             "response",
		"created_at":         0,
		"status":             status,
		"model":              resp.Model,
		"output":             buildOutput(resp.ID, resp.Blocks),
		"incomplete_details": incomplete,
		"usage":              encodeUsage(resp.Usage),
	}
}

// EncodeResponse renders an IR response as a Responses API body.
func (*Frontend) EncodeResponse(resp *ir.Response) ([]byte, error) {
	return json.Marshal(responseEnvelope(resp))
}

// ── streaming ───────────────────────────────────────────────────────

// NewEventEncoder returns an encoder writing Responses SSE events to
// w. The Responses protocol requires complete items in its .done and
// response.completed payloads, so the encoder accumulates the output
// as it streams (bounded by the response size).
func (*Frontend) NewEventEncoder(w io.Writer) ir.EventEncoder {
	return &eventEncoder{w: sse.NewWriter(w)}
}

type eventEncoder struct {
	w     *sse.Writer
	seq   int
	id    string
	model string

	outputIndex int
	openKind    ir.BlockType
	itemID      string
	textAcc     strings.Builder
	argsAcc     strings.Builder
	toolID      string
	toolName    string
	done        []map[string]any // completed output items, in order
}

// Encode writes the SSE event(s) for one IR event.
func (e *eventEncoder) Encode(ev ir.Event) error {
	switch ev.Type {
	case ir.EventMessageStart:
		e.id = "resp_" + ev.ID
		e.model = ev.Model
		envelope := map[string]any{
			"id": e.id, "object": "response", "created_at": 0,
			"status": "in_progress", "model": e.model, "output": []any{},
		}
		if err := e.write("response.created", map[string]any{"response": envelope}); err != nil {
			return err
		}
		return e.write("response.in_progress", map[string]any{"response": envelope})
	case ir.EventBlockStart:
		if ev.Block == nil {
			return fmt.Errorf("openairesp: block_start event missing block header")
		}
		e.openKind = ev.Block.Type
		e.textAcc.Reset()
		e.argsAcc.Reset()
		switch ev.Block.Type {
		case ir.BlockText:
			e.itemID = fmt.Sprintf("msg_%d", e.outputIndex)
			if err := e.write("response.output_item.added", map[string]any{
				"output_index": e.outputIndex,
				"item":         map[string]any{"type": "message", "id": e.itemID, "status": "in_progress", "role": "assistant", "content": []any{}},
			}); err != nil {
				return err
			}
			return e.write("response.content_part.added", map[string]any{
				"item_id": e.itemID, "output_index": e.outputIndex, "content_index": 0,
				"part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
			})
		case ir.BlockToolUse:
			e.itemID = fmt.Sprintf("fc_%d", e.outputIndex)
			e.toolID = ev.Block.ToolUse.ID
			e.toolName = ev.Block.ToolUse.Name
			return e.write("response.output_item.added", map[string]any{
				"output_index": e.outputIndex,
				"item": map[string]any{"type": "function_call", "id": e.itemID, "status": "in_progress",
					"call_id": e.toolID, "name": e.toolName, "arguments": ""},
			})
		case ir.BlockThinking:
			e.itemID = fmt.Sprintf("rs_%d", e.outputIndex)
			return e.write("response.output_item.added", map[string]any{
				"output_index": e.outputIndex,
				"item":         map[string]any{"type": "reasoning", "id": e.itemID, "summary": []any{}},
			})
		default:
			return fmt.Errorf("openairesp: block type %q not streamable", ev.Block.Type)
		}
	case ir.EventTextDelta:
		e.textAcc.WriteString(ev.Delta)
		return e.write("response.output_text.delta", map[string]any{
			"item_id": e.itemID, "output_index": e.outputIndex, "content_index": 0, "delta": ev.Delta,
		})
	case ir.EventThinkingDelta:
		e.textAcc.WriteString(ev.Delta)
		return e.write("response.reasoning_summary_text.delta", map[string]any{
			"item_id": e.itemID, "output_index": e.outputIndex, "summary_index": 0, "delta": ev.Delta,
		})
	case ir.EventArgsDelta:
		e.argsAcc.WriteString(ev.Delta)
		return e.write("response.function_call_arguments.delta", map[string]any{
			"item_id": e.itemID, "output_index": e.outputIndex, "delta": ev.Delta,
		})
	case ir.EventSignatureDelta:
		return nil
	case ir.EventBlockStop:
		return e.closeItem()
	case ir.EventMessageDelta:
		status := "completed"
		var incomplete any
		if ev.StopReason == ir.StopMaxTokens {
			status = "incomplete"
			incomplete = map[string]any{"reason": "max_output_tokens"}
		}
		envelope := map[string]any{
			"id": e.id, "object": "response", "created_at": 0,
			"status": status, "model": e.model,
			"output":             e.doneOutput(),
			"incomplete_details": incomplete,
		}
		if ev.Usage != nil {
			envelope["usage"] = encodeUsage(*ev.Usage)
		}
		name := "response.completed"
		if status == "incomplete" {
			name = "response.incomplete"
		}
		return e.write(name, map[string]any{"response": envelope})
	case ir.EventMessageStop:
		return nil
	default:
		return fmt.Errorf("openairesp: unknown event type %q", ev.Type)
	}
}

func (e *eventEncoder) doneOutput() []map[string]any {
	if e.done == nil {
		return []map[string]any{}
	}
	return e.done
}

// closeItem emits the .done events for the open block and records the
// completed item for response.completed.
func (e *eventEncoder) closeItem() error {
	var item map[string]any
	switch e.openKind {
	case ir.BlockText:
		text := e.textAcc.String()
		if err := e.write("response.output_text.done", map[string]any{
			"item_id": e.itemID, "output_index": e.outputIndex, "content_index": 0, "text": text,
		}); err != nil {
			return err
		}
		item = map[string]any{"type": "message", "id": e.itemID, "status": "completed", "role": "assistant",
			"content": []map[string]any{{"type": "output_text", "text": text, "annotations": []any{}}}}
	case ir.BlockToolUse:
		args := e.argsAcc.String()
		if args == "" {
			args = "{}"
		}
		if err := e.write("response.function_call_arguments.done", map[string]any{
			"item_id": e.itemID, "output_index": e.outputIndex, "arguments": args,
		}); err != nil {
			return err
		}
		item = map[string]any{"type": "function_call", "id": e.itemID, "status": "completed",
			"call_id": e.toolID, "name": e.toolName, "arguments": args}
	case ir.BlockThinking:
		item = map[string]any{"type": "reasoning", "id": e.itemID,
			"summary": []map[string]any{{"type": "summary_text", "text": e.textAcc.String()}}}
	default:
		return nil
	}
	if err := e.write("response.output_item.done", map[string]any{
		"output_index": e.outputIndex, "item": item,
	}); err != nil {
		return err
	}
	e.done = append(e.done, item)
	e.outputIndex++
	e.openKind = ""
	return nil
}

func (e *eventEncoder) write(name string, data map[string]any) error {
	data["type"] = name
	data["sequence_number"] = e.seq
	e.seq++
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return e.w.WriteEvent(name, raw)
}
