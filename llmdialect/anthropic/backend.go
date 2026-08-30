package anthropic

// Backend (upstream-side) codec: encodes an IR request as a Messages
// API body, decodes Messages responses, and decodes the Messages SSE
// event stream into canonical IR events — so callers speaking another
// dialect can drive a native Anthropic model.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"latere.ai/x/pkg/llmdialect/internal/servertool"
	"latere.ai/x/pkg/llmdialect/internal/sse"
	"latere.ai/x/pkg/llmdialect/ir"
)

// BackendOptions tune encoding for the Messages API's requirements.
type BackendOptions struct {
	// DefaultMaxTokens is injected when the caller omitted max_tokens
	// (required by the Messages API). Zero means 4096.
	DefaultMaxTokens int64
}

// Backend is the upstream-side Messages codec.
type Backend struct {
	opts BackendOptions
}

// NewBackend returns a Messages backend codec.
func NewBackend(opts BackendOptions) *Backend {
	if opts.DefaultMaxTokens <= 0 {
		opts.DefaultMaxTokens = 4096
	}
	return &Backend{opts: opts}
}

// Name returns the dialect name.
func (*Backend) Name() ir.Dialect { return DialectName }

// EncodeRequest renders the IR request as a Messages API body.
// Unrepresentable fields are recorded in req.Loss.
func (b *Backend) EncodeRequest(req *ir.Request) ([]byte, error) {
	maxTokens := b.opts.DefaultMaxTokens
	if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	}
	body := map[string]any{
		"model":      req.Model,
		"max_tokens": maxTokens,
	}

	if len(req.System) > 0 {
		system := make([]map[string]any, 0, len(req.System))
		for _, blk := range req.System {
			if blk.Type != ir.BlockText {
				continue
			}
			s := map[string]any{"type": "text", "text": blk.Text}
			if blk.CacheHint {
				s["cache_control"] = map[string]any{"type": "ephemeral"}
			}
			system = append(system, s)
		}
		body["system"] = system
	}

	messages := make([]map[string]any, 0, len(req.Messages))
	for i, m := range req.Messages {
		enc, err := encodeBackendMessage(m, req)
		if err != nil {
			return nil, fmt.Errorf("anthropic: messages[%d]: %w", i, err)
		}
		messages = append(messages, enc)
	}
	body["messages"] = messages

	if len(req.Tools) > 0 || len(req.ServerTools) > 0 {
		tools := make([]map[string]any, 0, len(req.Tools)+len(req.ServerTools))
		for _, t := range req.Tools {
			schema := t.InputSchema
			if len(schema) == 0 {
				schema = json.RawMessage(`{"type":"object"}`)
			}
			tool := map[string]any{"name": t.Name, "input_schema": schema}
			if t.Description != "" {
				tool["description"] = t.Description
			}
			tools = append(tools, tool)
		}
		// Anthropic's own server tools live in the same array, keeping the
		// options they arrived with.
		for _, t := range req.ServerTools {
			enc, err := servertool.Encode(t)
			if err != nil {
				return nil, fmt.Errorf("anthropic: %w", err)
			}
			tools = append(tools, enc)
		}
		body["tools"] = tools
	}
	// The Messages API has no request-level web search switch; the
	// capability is a server tool there. Report it rather than silently
	// answering without grounding.
	if req.WebSearch != nil {
		req.Loss.Add(ir.LossWebSearch)
	}
	if req.ToolChoice != nil {
		tc := map[string]any{}
		switch req.ToolChoice.Mode {
		case ir.ToolChoiceAuto:
			tc["type"] = "auto"
		case ir.ToolChoiceAny:
			tc["type"] = "any"
		case ir.ToolChoiceNone:
			tc["type"] = "none"
		case ir.ToolChoiceTool:
			tc["type"] = "tool"
			tc["name"] = req.ToolChoice.Name
		default:
			return nil, fmt.Errorf("anthropic: unknown tool choice mode %q", req.ToolChoice.Mode)
		}
		if req.ToolChoice.DisableParallel {
			tc["disable_parallel_tool_use"] = true
		}
		body["tool_choice"] = tc
	}

	if req.Temperature != nil {
		t := *req.Temperature
		if t > 1 {
			// OpenAI's scale runs to 2; Anthropic's caps at 1.
			t = 1
			req.Loss.Add(ir.LossTemperature)
		}
		body["temperature"] = t
	}
	if req.TopP != nil {
		body["top_p"] = *req.TopP
	}
	if req.TopK != nil {
		body["top_k"] = *req.TopK
	}
	if len(req.StopSequences) > 0 {
		body["stop_sequences"] = req.StopSequences
	}
	// The Messages API has no logprobs member anywhere in its request or
	// its response, so an ask cannot be forwarded and an answer could not
	// be carried back. That is a loss, not an error: the completion is
	// still the one the caller asked for.
	if req.LogProbs {
		req.Loss.Add(ir.LossLogProbs)
	}
	if req.TopLogProbs > 0 {
		req.Loss.Add(ir.LossTopLogProbs)
	}
	if req.Reasoning != nil {
		// Newer Claude models (opus-4.7/4.8, sonnet-5, fable-5) reject the
		// deprecated thinking:{enabled, budget_tokens} and require
		// thinking:{adaptive} + output_config.effort; older models accept
		// adaptive too, so emit it uniformly.
		body["thinking"] = map[string]any{"type": "adaptive"}
		oc, _ := body["output_config"].(map[string]any)
		if oc == nil {
			oc = map[string]any{}
		}
		oc["effort"] = outputConfigEffort(req)
		body["output_config"] = oc
	}
	if req.Schema != nil {
		body["output_format"] = map[string]any{"type": "json_schema", "schema": req.Schema.Schema}
	}
	if req.UserID != "" {
		body["metadata"] = map[string]any{"user_id": req.UserID}
	}
	if req.Stream {
		body["stream"] = true
	}
	return json.Marshal(body)
}

// Budget→effort banding thresholds for Anthropic-style callers, now
// that the adaptive API is effort-based rather than budget-based.
const (
	budgetForEffortLow    = 2048
	budgetForEffortMedium = 8192
)

// outputConfigEffort maps an IR reasoning config to an output_config
// effort value ("low"/"medium"/"high"; the API also accepts "xhigh").
// An OpenAI-style effort passes straight through (lossless); "minimal"
// has no API equivalent and maps to "low" (recorded); an Anthropic-style
// budget bands to an effort (recorded as an approximation); reasoning
// enabled with neither defaults to "high".
func outputConfigEffort(req *ir.Request) string {
	switch req.Reasoning.Effort {
	case ir.EffortLow:
		return "low"
	case ir.EffortMedium:
		return "medium"
	case ir.EffortHigh:
		return "high"
	case "xhigh":
		return "xhigh"
	case ir.EffortMinimal:
		req.Loss.Add(ir.LossReasoningEffort)
		return "low"
	case "":
		if b := req.Reasoning.BudgetTokens; b > 0 {
			req.Loss.Add(ir.LossThinkingBudget)
			switch {
			case b <= budgetForEffortLow:
				return "low"
			case b <= budgetForEffortMedium:
				return "medium"
			default:
				return "high"
			}
		}
		return "high"
	default:
		return "high"
	}
}

func encodeBackendMessage(m ir.Message, req *ir.Request) (map[string]any, error) {
	content := make([]map[string]any, 0, len(m.Blocks))
	for _, blk := range m.Blocks {
		enc, ok, err := encodeBackendBlock(blk, m.Role, req)
		if err != nil {
			return nil, err
		}
		if ok {
			content = append(content, enc)
		}
	}
	role := "user"
	if m.Role == ir.RoleAssistant {
		role = "assistant"
	}
	return map[string]any{"role": role, "content": content}, nil
}

func encodeBackendBlock(blk ir.Block, role ir.Role, req *ir.Request) (map[string]any, bool, error) {
	withCache := func(m map[string]any) map[string]any {
		if blk.CacheHint {
			m["cache_control"] = map[string]any{"type": "ephemeral"}
		}
		return m
	}
	switch blk.Type {
	case ir.BlockText:
		return withCache(map[string]any{"type": "text", "text": blk.Text}), true, nil
	case ir.BlockImage:
		return withCache(map[string]any{"type": "image", "source": encodeImageSource(blk.Image)}), true, nil
	case ir.BlockToolUse:
		args := blk.ToolUse.Args
		if len(args) == 0 {
			args = json.RawMessage("{}")
		}
		return map[string]any{"type": "tool_use", "id": blk.ToolUse.ID, "name": blk.ToolUse.Name, "input": args}, true, nil
	case ir.BlockToolResult:
		if role != ir.RoleUser {
			return nil, false, fmt.Errorf("tool_result outside a user turn")
		}
		inner := make([]map[string]any, 0, len(blk.ToolResult.Blocks))
		for _, ib := range blk.ToolResult.Blocks {
			switch ib.Type {
			case ir.BlockText:
				inner = append(inner, map[string]any{"type": "text", "text": ib.Text})
			case ir.BlockImage:
				inner = append(inner, map[string]any{"type": "image", "source": encodeImageSource(ib.Image)})
			}
		}
		out := map[string]any{"type": "tool_result", "tool_use_id": blk.ToolResult.ToolUseID, "content": inner}
		if blk.ToolResult.IsError {
			out["is_error"] = true
		}
		return out, true, nil
	case ir.BlockThinking:
		// Only provider-signed thinking survives a replay; synthesized
		// blocks (no signature) cannot be sent to the Messages API.
		if blk.Signature == "" {
			req.Loss.Add(ir.LossThinking)
			return nil, false, nil
		}
		return map[string]any{"type": "thinking", "thinking": blk.Text, "signature": blk.Signature}, true, nil
	case ir.BlockRedactedThinking:
		return map[string]any{"type": "redacted_thinking", "data": blk.Redacted}, true, nil
	default:
		return nil, false, fmt.Errorf("block type %q not representable", blk.Type)
	}
}

func encodeImageSource(img *ir.Image) map[string]any {
	if img.URL != "" {
		return map[string]any{"type": "url", "url": img.URL}
	}
	return map[string]any{"type": "base64", "media_type": img.MediaType, "data": img.Data}
}

// backendUsage is the Messages usage object.
type backendUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
}

func (u *backendUsage) toUsage() ir.Usage {
	return ir.Usage{
		InputTokens:           u.InputTokens,
		OutputTokens:          u.OutputTokens,
		CacheReadInputTokens:  u.CacheReadInputTokens,
		CacheWriteInputTokens: u.CacheCreationInputTokens,
	}
}

// DecodeResponse parses a non-streaming Messages response into the IR.
func (*Backend) DecodeResponse(body []byte) (*ir.Response, error) {
	var wire struct {
		Type    string       `json:"type"`
		ID      string       `json:"id"`
		Model   string       `json:"model"`
		Content []wireBlock  `json:"content"`
		Stop    *string      `json:"stop_reason"`
		StopSeq *string      `json:"stop_sequence"`
		Usage   backendUsage `json:"usage"`
		Error   *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("anthropic: invalid response JSON: %w", err)
	}
	if wire.Error != nil {
		return nil, fmt.Errorf("anthropic: upstream error (%s): %s", wire.Error.Type, wire.Error.Message)
	}
	resp := &ir.Response{ID: wire.ID, Model: wire.Model, Usage: wire.Usage.toUsage()}
	var loss ir.Loss // response-side unknown block types are skipped
	for i, wb := range wire.Content {
		blk, ok, err := decodeBlock(wb, &loss, fmt.Sprintf("content[%d]", i))
		if err != nil {
			return nil, fmt.Errorf("anthropic: %w", err)
		}
		if ok {
			resp.Blocks = append(resp.Blocks, blk)
		}
	}
	if wire.Stop != nil {
		resp.StopReason = ir.StopReason(*wire.Stop)
	}
	if wire.StopSeq != nil {
		resp.StopSequence = *wire.StopSeq
	}
	return resp, nil
}

// NewEventDecoder returns a decoder for a Messages SSE stream.
func (*Backend) NewEventDecoder(r io.Reader) ir.EventDecoder {
	return &backendEventDecoder{r: sse.NewReader(r)}
}

// backendEventDecoder converts Messages SSE events into canonical IR
// events. The mapping is nearly 1:1; input-side usage from
// message_start merges into the final MessageDelta usage.
type backendEventDecoder struct {
	r        *sse.Reader
	pending  []ir.Event
	finished bool
	usage    ir.Usage
	stop     ir.StopReason
	stopSeq  string
}

// Next returns the next IR event, or io.EOF after MessageStop.
func (d *backendEventDecoder) Next() (ir.Event, error) {
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
		if errors.Is(err, io.EOF) {
			// Upstream closed early; still emit a well-formed tail.
			d.finish()
			continue
		}
		if err != nil {
			return ir.Event{}, err
		}
		if err := d.consume(frame.Data); err != nil {
			return ir.Event{}, err
		}
	}
}

func (d *backendEventDecoder) finish() {
	usage := d.usage
	d.pending = append(d.pending,
		ir.Event{Type: ir.EventMessageDelta, StopReason: d.stopOrDefault(), StopSequence: d.stopSeq, Usage: &usage},
		ir.Event{Type: ir.EventMessageStop},
	)
	d.finished = true
}

func (d *backendEventDecoder) stopOrDefault() ir.StopReason {
	if d.stop == "" {
		return ir.StopEndTurn
	}
	return d.stop
}

func (d *backendEventDecoder) consume(data []byte) error {
	var frame struct {
		Type    string `json:"type"`
		Index   int    `json:"index"`
		Message *struct {
			ID    string       `json:"id"`
			Model string       `json:"model"`
			Usage backendUsage `json:"usage"`
		} `json:"message"`
		ContentBlock *wireBlock `json:"content_block"`
		Delta        *struct {
			Type        string  `json:"type"`
			Text        string  `json:"text"`
			PartialJSON string  `json:"partial_json"`
			Thinking    string  `json:"thinking"`
			Signature   string  `json:"signature"`
			StopReason  *string `json:"stop_reason"`
			StopSeq     *string `json:"stop_sequence"`
		} `json:"delta"`
		Usage *backendUsage `json:"usage"`
		Error *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &frame); err != nil {
		return fmt.Errorf("anthropic: invalid stream event: %w", err)
	}
	switch frame.Type {
	case "message_start":
		if frame.Message == nil {
			return fmt.Errorf("anthropic: message_start missing message")
		}
		d.usage = frame.Message.Usage.toUsage()
		usage := d.usage
		d.pending = append(d.pending, ir.Event{
			Type: ir.EventMessageStart, ID: frame.Message.ID, Model: frame.Message.Model, Usage: &usage,
		})
	case "content_block_start":
		if frame.ContentBlock == nil {
			return fmt.Errorf("anthropic: content_block_start missing content_block")
		}
		var loss ir.Loss
		blk, ok, err := decodeBlock(*frame.ContentBlock, &loss, "content_block")
		if err != nil {
			return fmt.Errorf("anthropic: %w", err)
		}
		if !ok {
			blk = ir.Block{Type: ir.BlockText}
		}
		d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStart, Index: frame.Index, Block: &blk})
	case "content_block_delta":
		if frame.Delta == nil {
			return nil
		}
		switch frame.Delta.Type {
		case "text_delta":
			d.pending = append(d.pending, ir.Event{Type: ir.EventTextDelta, Index: frame.Index, Delta: frame.Delta.Text})
		case "input_json_delta":
			d.pending = append(d.pending, ir.Event{Type: ir.EventArgsDelta, Index: frame.Index, Delta: frame.Delta.PartialJSON})
		case "thinking_delta":
			d.pending = append(d.pending, ir.Event{Type: ir.EventThinkingDelta, Index: frame.Index, Delta: frame.Delta.Thinking})
		case "signature_delta":
			d.pending = append(d.pending, ir.Event{Type: ir.EventSignatureDelta, Index: frame.Index, Delta: frame.Delta.Signature})
		}
	case "content_block_stop":
		d.pending = append(d.pending, ir.Event{Type: ir.EventBlockStop, Index: frame.Index})
	case "message_delta":
		if frame.Delta != nil {
			if frame.Delta.StopReason != nil {
				d.stop = ir.StopReason(*frame.Delta.StopReason)
			}
			if frame.Delta.StopSeq != nil {
				d.stopSeq = *frame.Delta.StopSeq
			}
		}
		if frame.Usage != nil {
			// Output tokens are cumulative here; input-side counts came
			// on message_start.
			d.usage.OutputTokens = frame.Usage.OutputTokens
			if frame.Usage.InputTokens > 0 {
				d.usage.InputTokens = frame.Usage.InputTokens
			}
			if frame.Usage.CacheReadInputTokens > 0 {
				d.usage.CacheReadInputTokens = frame.Usage.CacheReadInputTokens
			}
		}
	case "message_stop":
		d.finish()
	case "ping":
	case "error":
		if frame.Error != nil {
			return fmt.Errorf("anthropic: upstream error (%s): %s", frame.Error.Type, frame.Error.Message)
		}
		return fmt.Errorf("anthropic: upstream error")
	}
	return nil
}
