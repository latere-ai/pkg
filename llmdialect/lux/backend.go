package lux

// The backend codec (upstream side): encoding an IR request as a lux
// body and decoding lux responses and SSE streams back into the IR.
// This is what luxsdk rides — an SDK call is exactly "encode toward a
// lux upstream" — and what a future lux-to-lux chaining hop would use.

import (
	"encoding/json"
	"fmt"
	"io"

	"latere.ai/x/pkg/llmdialect/internal/sse"
	"latere.ai/x/pkg/llmdialect/ir"
)

// Backend is the upstream-side lux codec.
type Backend struct{}

// NewBackend returns the lux backend codec.
func NewBackend() *Backend { return &Backend{} }

// Name returns the dialect name.
func (*Backend) Name() ir.Dialect { return DialectName }

// EncodeRequest renders an IR request as a lux request body. The lux
// dialect is the IR, so encoding is lossless.
func (*Backend) EncodeRequest(req *ir.Request) ([]byte, error) {
	wire := Request{
		Model:         req.Model,
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		TopK:          req.TopK,
		StopSequences: req.StopSequences,
		Stream:        req.Stream,
		UserID:        req.UserID,
	}
	for _, b := range req.System {
		blk, err := blockFromIR(b)
		if err != nil {
			return nil, err
		}
		wire.System = append(wire.System, blk)
	}
	for _, m := range req.Messages {
		msg := Message{Role: m.Role}
		for _, b := range m.Blocks {
			blk, err := blockFromIR(b)
			if err != nil {
				return nil, err
			}
			msg.Blocks = append(msg.Blocks, blk)
		}
		wire.Messages = append(wire.Messages, msg)
	}
	for _, t := range req.Tools {
		wire.Tools = append(wire.Tools, Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	if req.ToolChoice != nil {
		wire.ToolChoice = &ToolChoice{
			Mode:            req.ToolChoice.Mode,
			Name:            req.ToolChoice.Name,
			DisableParallel: req.ToolChoice.DisableParallel,
		}
	}
	if req.Reasoning != nil {
		wire.Reasoning = &Reasoning{Effort: req.Reasoning.Effort, BudgetTokens: req.Reasoning.BudgetTokens}
	}
	if req.Schema != nil {
		wire.Schema = &ResponseSchema{
			Name:        req.Schema.Name,
			Description: req.Schema.Description,
			Schema:      req.Schema.Schema,
			Strict:      req.Schema.Strict,
		}
	}
	return json.Marshal(wire)
}

// DecodeResponse parses a lux non-streaming response into the IR.
func (*Backend) DecodeResponse(body []byte) (*ir.Response, error) {
	var wire Response
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("lux: invalid response JSON: %w", err)
	}
	out := &ir.Response{
		ID:           wire.ID,
		Model:        wire.Model,
		StopReason:   wire.StopReason,
		StopSequence: wire.StopSequence,
		Usage:        usageToIR(wire.Usage),
	}
	var loss ir.Loss
	for _, b := range wire.Blocks {
		blk, ok, err := blockToIR(b, &loss)
		if err != nil {
			return nil, fmt.Errorf("lux: response block: %w", err)
		}
		if ok {
			out.Blocks = append(out.Blocks, blk)
		}
	}
	return out, nil
}

// StreamError is a mid-stream `event: error` frame from a lux
// upstream, carried in the gateway's error envelope.
type StreamError struct {
	Code    string
	Message string
}

// Error implements error.
func (e *StreamError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("lux: stream error: %s", e.Message)
	}
	return fmt.Sprintf("lux: stream error (%s): %s", e.Code, e.Message)
}

// StreamReader yields wire-level lux Events from an SSE stream,
// returning io.EOF at end of stream. Unknown event names are skipped
// (forward compatibility); an `event: error` frame surfaces as a
// *StreamError. luxsdk consumes this directly; the Backend's IR
// decoder wraps it.
type StreamReader struct {
	r *sse.Reader
}

// NewStreamReader returns a wire-level lux SSE reader.
func NewStreamReader(r io.Reader) *StreamReader {
	return &StreamReader{r: sse.NewReader(r)}
}

// Next returns the next lux event.
func (s *StreamReader) Next() (Event, error) {
	for {
		frame, err := s.r.Next()
		if err != nil {
			return Event{}, err
		}
		if frame.Name == "error" {
			return Event{}, decodeStreamError(frame.Data)
		}
		if !validEventTypes[ir.EventType(frame.Name)] {
			continue
		}
		var ev Event
		if err := json.Unmarshal(frame.Data, &ev); err != nil {
			return Event{}, fmt.Errorf("lux: malformed %s event: %w", frame.Name, err)
		}
		if ev.Type == "" {
			ev.Type = ir.EventType(frame.Name)
		}
		return ev, nil
	}
}

// decodeStreamError parses the gateway's error envelope
// ({"type":"error","error":{"type","message"}}); an unparseable body
// degrades to the raw bytes as the message.
func decodeStreamError(data []byte) error {
	var wire struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &wire); err != nil || wire.Error.Message == "" && wire.Error.Type == "" {
		return &StreamError{Message: string(data)}
	}
	return &StreamError{Code: wire.Error.Type, Message: wire.Error.Message}
}

// EventDecoder adapts StreamReader to the IR event stream.
type EventDecoder struct {
	r *StreamReader
}

// NewEventDecoder returns a decoder yielding canonical IR events from
// a lux SSE stream.
func (*Backend) NewEventDecoder(r io.Reader) ir.EventDecoder {
	return &EventDecoder{r: NewStreamReader(r)}
}

// Next returns the next canonical event.
func (d *EventDecoder) Next() (ir.Event, error) {
	ev, err := d.r.Next()
	if err != nil {
		return ir.Event{}, err
	}
	return eventToIR(ev)
}
