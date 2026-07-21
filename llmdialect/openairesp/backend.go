// This file carries the backend codec (upstream side) of the OpenAI
// Responses dialect: encoding an IR request as a Responses API body,
// decoding the response, and decoding the Responses SSE stream into
// canonical IR events. It is the inverse of the frontend in
// openairesp.go and, like it, operates statelessly — full history is
// encoded per request, no previous_response_id / store. Its reason to
// exist is that OpenAI reasoning models require the Responses API for
// function tools (Chat Completions rejects tools + reasoning_effort),
// so a Messages- or Chat-dialect client can only drive them through
// this backend.
package openairesp

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"latere.ai/x/pkg/llmdialect/internal/sse"
	"latere.ai/x/pkg/llmdialect/ir"
)

// Backend is the upstream-side Responses codec.
type Backend struct{}

// NewBackend returns a Responses backend codec.
func NewBackend() *Backend { return &Backend{} }

// Name returns the dialect name.
func (*Backend) Name() ir.Dialect { return DialectName }

// Effort banding thresholds for Anthropic-style token budgets (mirrors
// openaichat).
const (
	effortLowMaxBudget    = 2048
	effortMediumMaxBudget = 8192
)

// maxUserLen is the Responses API cap on the `user` field.
const maxUserLen = 64

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

// EncodeRequest renders the IR request as a Responses API body.
func (*Backend) EncodeRequest(req *ir.Request) ([]byte, error) {
	body := map[string]any{"model": req.Model}

	if s := encodeInstructions(req); s != "" {
		body["instructions"] = s
	}
	input := make([]map[string]any, 0, len(req.Messages))
	for i, m := range req.Messages {
		items, err := encodeMessage(m, req)
		if err != nil {
			return nil, fmt.Errorf("openairesp: messages[%d]: %w", i, err)
		}
		input = append(input, items...)
	}
	body["input"] = input

	if len(req.Tools) > 0 {
		tools := make([]map[string]any, 0, len(req.Tools))
		for _, t := range req.Tools {
			schema := t.InputSchema
			if len(schema) == 0 {
				schema = json.RawMessage(`{"type":"object"}`)
			}
			tool := map[string]any{"type": "function", "name": t.Name, "parameters": schema}
			if t.Description != "" {
				tool["description"] = t.Description
			}
			tools = append(tools, tool)
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
			body["tool_choice"] = map[string]any{"type": "function", "name": req.ToolChoice.Name}
		default:
			return nil, fmt.Errorf("openairesp: unknown tool choice mode %q", req.ToolChoice.Mode)
		}
		if req.ToolChoice.DisableParallel {
			body["parallel_tool_calls"] = false
		}
	}

	if req.MaxTokens != nil {
		body["max_output_tokens"] = *req.MaxTokens
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
	if len(req.StopSequences) > 0 {
		req.Loss.Add(ir.LossStopSequences)
	}
	if req.Reasoning != nil {
		body["reasoning"] = map[string]any{"effort": reasoningEffort(req)}
	}
	if req.Schema != nil {
		format := map[string]any{"type": "json_schema", "name": req.Schema.Name, "schema": req.Schema.Schema}
		if req.Schema.Description != "" {
			format["description"] = req.Schema.Description
		}
		if req.Schema.Strict {
			format["strict"] = true
		}
		body["text"] = map[string]any{"format": format}
	}
	if req.UserID != "" {
		// The Responses API caps `user` at 64 chars; harnesses send
		// longer session ids, so truncate rather than 400 upstream.
		user := req.UserID
		if len(user) > maxUserLen {
			user = user[:maxUserLen]
			req.Loss.Add(ir.LossUserTruncated)
		}
		body["user"] = user
	}
	if req.Stream {
		body["stream"] = true
	}
	return json.Marshal(body)
}

// encodeInstructions folds the IR system blocks into the Responses
// `instructions` string.
func encodeInstructions(req *ir.Request) string {
	var parts []string
	for _, blk := range req.System {
		if blk.CacheHint {
			req.Loss.Add(ir.LossCacheControl)
		}
		if blk.Type == ir.BlockText {
			parts = append(parts, blk.Text)
		}
	}
	return strings.Join(parts, "\n\n")
}

// encodeMessage converts one IR message into Responses input items,
// preserving block order: text/image coalesce into a message item;
// tool uses become function_call items; tool results become
// function_call_output items.
func encodeMessage(m ir.Message, req *ir.Request) ([]map[string]any, error) {
	var out []map[string]any
	var content []map[string]any

	role := "user"
	textType := "input_text"
	if m.Role == ir.RoleAssistant {
		role = "assistant"
		textType = "output_text"
	} else if m.Role != ir.RoleUser {
		return nil, fmt.Errorf("unknown role %q", m.Role)
	}

	flush := func() {
		if len(content) > 0 {
			out = append(out, map[string]any{"type": "message", "role": role, "content": content})
			content = nil
		}
	}

	for _, blk := range m.Blocks {
		if blk.CacheHint {
			req.Loss.Add(ir.LossCacheControl)
		}
		switch blk.Type {
		case ir.BlockText:
			content = append(content, map[string]any{"type": textType, "text": blk.Text})
		case ir.BlockImage:
			if m.Role != ir.RoleUser {
				return nil, fmt.Errorf("image not allowed in an assistant message")
			}
			content = append(content, map[string]any{"type": "input_image", "image_url": imageURL(blk.Image)})
		case ir.BlockToolUse:
			flush()
			args := string(blk.ToolUse.Args)
			if args == "" {
				args = "{}"
			}
			out = append(out, map[string]any{
				"type": "function_call", "call_id": blk.ToolUse.ID,
				"name": blk.ToolUse.Name, "arguments": args,
			})
		case ir.BlockToolResult:
			flush()
			out = append(out, encodeToolResult(blk, req))
		case ir.BlockThinking, ir.BlockRedactedThinking:
			// Provider-encrypted; never replayed toward a fresh backend.
			req.Loss.Add(ir.LossThinking)
		default:
			return nil, fmt.Errorf("block type %q not allowed in a message", blk.Type)
		}
	}
	flush()
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
			req.Loss.Add(ir.LossToolResultImage)
		}
	}
	if tr.IsError {
		req.Loss.Add(ir.LossToolResultIsError)
	}
	return map[string]any{
		"type": "function_call_output", "call_id": tr.ToolUseID,
		"output": strings.Join(texts, "\n\n"),
	}
}

func imageURL(img *ir.Image) string {
	if img.URL != "" {
		return img.URL
	}
	return "data:" + img.MediaType + ";base64," + img.Data
}

// ── response decoding ───────────────────────────────────────────────

type respOutputItem struct {
	Type    string          `json:"type"`
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
	CallID  string          `json:"call_id"`
	Name    string          `json:"name"`
	Args    string          `json:"arguments"`
	Summary []struct {
		Text string `json:"text"`
	} `json:"summary"`
}

type respUsage struct {
	InputTokens        int64 `json:"input_tokens"`
	OutputTokens       int64 `json:"output_tokens"`
	InputTokensDetails struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	OutputTokensDetails struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

func (u *respUsage) toUsage() ir.Usage {
	in := u.InputTokens - u.InputTokensDetails.CachedTokens
	if in < 0 {
		in = 0
	}
	return ir.Usage{
		InputTokens:          in,
		OutputTokens:         u.OutputTokens,
		CacheReadInputTokens: u.InputTokensDetails.CachedTokens,
		ReasoningTokens:      u.OutputTokensDetails.ReasoningTokens,
	}
}

type respError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

func (e *respError) Error() string {
	kind := e.Code
	if kind == "" {
		kind = e.Type
	}
	if kind == "" {
		kind = "unknown"
	}
	return fmt.Sprintf("openairesp: upstream error (%s): %s", kind, e.Message)
}

// DecodeResponse parses a non-streaming Responses API response into the IR.
func (*Backend) DecodeResponse(body []byte) (*ir.Response, error) {
	var wire struct {
		ID                string `json:"id"`
		Model             string `json:"model"`
		Status            string `json:"status"`
		IncompleteDetails *struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
		Output []respOutputItem `json:"output"`
		Usage  *respUsage       `json:"usage"`
		Error  *respError       `json:"error"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("openairesp: invalid response JSON: %w", err)
	}
	if wire.Error != nil {
		return nil, wire.Error
	}

	resp := &ir.Response{ID: strings.TrimPrefix(wire.ID, "resp_"), Model: wire.Model}
	sawTool := false
	for _, item := range wire.Output {
		switch item.Type {
		case "reasoning":
			var texts []string
			for _, s := range item.Summary {
				texts = append(texts, s.Text)
			}
			if t := strings.Join(texts, "\n\n"); t != "" {
				resp.Blocks = append(resp.Blocks, ir.Block{Type: ir.BlockThinking, Text: t})
			}
		case "message":
			for _, t := range decodeOutputText(item.Content) {
				resp.Blocks = append(resp.Blocks, ir.Block{Type: ir.BlockText, Text: t})
			}
		case "function_call":
			sawTool = true
			args := item.Args
			if args == "" {
				args = "{}"
			}
			resp.Blocks = append(resp.Blocks, ir.Block{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{
				ID: item.CallID, Name: item.Name, Args: json.RawMessage(args),
			}})
		}
	}

	resp.StopReason = responseStop(wire.Status, incompleteReason(wire.IncompleteDetails), sawTool)
	if wire.Usage != nil {
		resp.Usage = wire.Usage.toUsage()
	}
	return resp, nil
}

func incompleteReason(d *struct {
	Reason string `json:"reason"`
}) string {
	if d == nil {
		return ""
	}
	return d.Reason
}

func responseStop(status, incompleteReason string, sawTool bool) ir.StopReason {
	if status == "incomplete" && incompleteReason == "max_output_tokens" {
		return ir.StopMaxTokens
	}
	if sawTool {
		return ir.StopToolUse
	}
	return ir.StopEndTurn
}

// decodeOutputText pulls the output_text strings out of a message
// item's content (string or content-part array).
func decodeOutputText(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil
	}
	var out []string
	for _, p := range parts {
		if (p.Type == "output_text" || p.Type == "text") && p.Text != "" {
			out = append(out, p.Text)
		}
	}
	return out
}

// ── streaming ───────────────────────────────────────────────────────

// NewEventDecoder returns a decoder for a Responses SSE stream. It
// dispatches on each frame's JSON "type" field (robust to the presence
// or absence of the `event:` line).
func (*Backend) NewEventDecoder(r io.Reader) ir.EventDecoder {
	return &EventDecoder{r: sse.NewReader(r)}
}

// EventDecoder converts Responses SSE frames into canonical IR events.
type EventDecoder struct {
	r *sse.Reader

	pending  []ir.Event
	started  bool
	finished bool
	open     bool
	openIdx  int
	sawTool  bool
	usage    *ir.Usage
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
			d.finished = true
			return ir.Event{}, io.ErrUnexpectedEOF
		}
		if err != nil {
			return ir.Event{}, err
		}
		if err := d.consume(frame.Data); err != nil {
			return ir.Event{}, err
		}
	}
}

func (d *EventDecoder) finish(stop ir.StopReason) {
	d.closeOpen()
	d.pending = append(d.pending,
		ir.Event{Type: ir.EventMessageDelta, StopReason: stop, Usage: d.usage},
		ir.Event{Type: ir.EventMessageStop},
	)
	d.finished = true
}

func (d *EventDecoder) closeOpen() {
	if d.open {
		d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStop, Index: d.openIdx})
		d.open = false
	}
}

func (d *EventDecoder) consume(data []byte) error {
	var ev struct {
		Type     string `json:"type"`
		Code     string `json:"code"`
		Message  string `json:"message"`
		Delta    string `json:"delta"`
		Response struct {
			ID                string `json:"id"`
			Model             string `json:"model"`
			Status            string `json:"status"`
			IncompleteDetails *struct {
				Reason string `json:"reason"`
			} `json:"incomplete_details"`
			Usage *respUsage `json:"usage"`
			Error *respError `json:"error"`
		} `json:"response"`
		Item struct {
			Type   string `json:"type"`
			CallID string `json:"call_id"`
			Name   string `json:"name"`
		} `json:"item"`
		Error *respError `json:"error"`
	}
	if err := json.Unmarshal(data, &ev); err != nil {
		return fmt.Errorf("openairesp: invalid stream frame: %w", err)
	}
	if ev.Error != nil {
		d.finished = true
		return ev.Error
	}
	if ev.Type == "error" {
		d.finished = true
		return &respError{Code: ev.Code, Type: ev.Type, Message: ev.Message}
	}

	switch ev.Type {
	case "response.created":
		if !d.started {
			d.started = true
			d.pending = append(d.pending, ir.Event{
				Type: ir.EventMessageStart, ID: strings.TrimPrefix(ev.Response.ID, "resp_"), Model: ev.Response.Model,
			})
		}
	case "response.output_item.added":
		d.closeOpen()
		switch ev.Item.Type {
		case "message":
			d.open = true
			d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStart, Index: d.openIdx, Block: &ir.Block{Type: ir.BlockText}})
		case "function_call":
			d.open = true
			d.sawTool = true
			d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStart, Index: d.openIdx, Block: &ir.Block{
				Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: ev.Item.CallID, Name: ev.Item.Name},
			}})
		case "reasoning":
			d.open = true
			d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStart, Index: d.openIdx, Block: &ir.Block{Type: ir.BlockThinking}})
		}
	case "response.output_text.delta":
		d.pending = append(d.pending, ir.Event{Type: ir.EventTextDelta, Index: d.openIdx, Delta: ev.Delta})
	case "response.reasoning_summary_text.delta":
		d.pending = append(d.pending, ir.Event{Type: ir.EventThinkingDelta, Index: d.openIdx, Delta: ev.Delta})
	case "response.function_call_arguments.delta":
		d.pending = append(d.pending, ir.Event{Type: ir.EventArgsDelta, Index: d.openIdx, Delta: ev.Delta})
	case "response.output_item.done":
		if d.open {
			d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStop, Index: d.openIdx})
			d.open = false
			d.openIdx++
		}
	case "response.completed", "response.incomplete":
		if ev.Response.Usage != nil {
			u := ev.Response.Usage.toUsage()
			d.usage = &u
		}
		d.finish(responseStop(ev.Response.Status, incompleteReason(ev.Response.IncompleteDetails), d.sawTool))
	case "response.failed":
		d.finished = true
		if ev.Response.Error != nil {
			return ev.Response.Error
		}
		return fmt.Errorf("openairesp: upstream response failed")
	case "response.cancelled":
		d.finished = true
		return fmt.Errorf("openairesp: upstream response cancelled")
	}
	return nil
}
