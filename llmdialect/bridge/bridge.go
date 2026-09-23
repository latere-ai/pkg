// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"errors"
	"io"

	"latere.ai/x/pkg/llmdialect"
	"latere.ai/x/pkg/llmdialect/anthropic"
	"latere.ai/x/pkg/llmdialect/ir"
	"latere.ai/x/pkg/llmdialect/lux"
	"latere.ai/x/pkg/llmdialect/openaichat"
	"latere.ai/x/pkg/llmdialect/openairesp"
)

// Options are the codec options Open sets on the pair it builds. Each
// is a per-target decision the caller owns; the codecs carry no model
// table and neither does this package.
type Options struct {
	// DefaultMaxTokens is anthropic.BackendOptions.DefaultMaxTokens, the
	// max_tokens written when the caller sent none; 0 is the codec's
	// 4096.
	DefaultMaxTokens int64
	// DropSampling is anthropic.BackendOptions.DropSampling: temperature,
	// top_p, and top_k are left out and reported as loss.
	DropSampling bool
	// UseMaxCompletionTokens is
	// openaichat.BackendOptions.UseMaxCompletionTokens: the limit is
	// written as max_completion_tokens rather than max_tokens.
	UseMaxCompletionTokens bool
}

// Bridge is one caller dialect over one upstream dialect. It is
// immutable and safe for concurrent use; build one per call or hold one
// per pair, whichever the caller prefers.
type Bridge struct {
	fe llmdialect.Frontend
	be llmdialect.Backend
}

// New pairs codecs the caller built.
func New(fe llmdialect.Frontend, be llmdialect.Backend) *Bridge { return &Bridge{fe: fe, be: be} }

// Open builds the pair from two dialect names so a program imports this
// package alone: from is the caller's dialect, to the upstream's. A
// dialect with no codec on the side it is asked for is *Error with code
// Unsupported.
func Open(from, to ir.Dialect, o Options) (*Bridge, error) {
	fe := frontendFor(from)
	if fe == nil {
		return nil, &Error{Code: Unsupported, Detail: "no frontend codec for dialect " + quote(string(from))}
	}
	be := backendFor(to, o)
	if be == nil {
		return nil, &Error{Code: Unsupported, Detail: "no backend codec for dialect " + quote(string(to))}
	}
	return New(fe, be), nil
}

// frontendFor is the caller-side codec of a dialect, or nil.
func frontendFor(d ir.Dialect) llmdialect.Frontend {
	switch d {
	case ir.DialectOpenAIChat:
		return openaichat.NewFrontend()
	case ir.DialectOpenAIResponses:
		return openairesp.NewFrontend()
	case ir.DialectAnthropicMessages:
		return anthropic.NewFrontend()
	case ir.DialectLux:
		return lux.NewFrontend()
	}
	return nil
}

// backendFor is the upstream-side codec of a dialect with the options
// that concern it, or nil.
func backendFor(d ir.Dialect, o Options) llmdialect.Backend {
	switch d {
	case ir.DialectOpenAIChat:
		return openaichat.NewBackend(openaichat.BackendOptions{UseMaxCompletionTokens: o.UseMaxCompletionTokens})
	case ir.DialectOpenAIResponses:
		return openairesp.NewBackend()
	case ir.DialectAnthropicMessages:
		return anthropic.NewBackend(anthropic.BackendOptions{DefaultMaxTokens: o.DefaultMaxTokens, DropSampling: o.DropSampling})
	case ir.DialectLux:
		return lux.NewBackend()
	}
	return nil
}

// From is the caller's dialect.
func (b *Bridge) From() ir.Dialect { return b.fe.Name() }

// To is the upstream's dialect.
func (b *Bridge) To() ir.Dialect { return b.be.Name() }

// RequestOptions is what the caller writes between the legs.
type RequestOptions struct {
	// Model goes into ir.Request.Model after the decode: the name the
	// upstream knows the model by. "" keeps what the caller sent.
	Model string
	// Loss is entries the caller adds to the report before the encode,
	// such as a request header the upstream will not receive.
	Loss []string
}

// Request decodes body with the frontend, writes Model, encodes with the
// backend, and returns the accumulated loss report as field paths in
// the codecs' own order, the caller's entries between the two legs,
// deduplicated. loss is nil when nothing was lost, so a caller can test
// the slice rather than its length. A body the frontend cannot read is
// *Error with code DecodeRequest and the codec's refusal scope; a
// request the backend cannot write is EncodeRequest.
func (b *Bridge) Request(body []byte, o RequestOptions) (out []byte, loss []string, err error) {
	req, err := b.fe.DecodeRequest(body)
	if err != nil {
		return nil, nil, wrap(DecodeRequest, err)
	}
	for _, l := range o.Loss {
		req.Loss.Add(ir.LossField(l))
	}
	if o.Model != "" {
		req.Model = o.Model
	}
	out, err = b.be.EncodeRequest(req)
	if err != nil {
		return nil, nil, wrap(EncodeRequest, err)
	}
	return out, req.Loss.Strings(), nil
}

// ResponseOptions is what the caller writes between the legs of a
// response.
type ResponseOptions struct {
	// Model goes into ir.Response.Model after the decode: the name the
	// caller asked for. "" keeps what the upstream wrote.
	Model string
}

// Response decodes the upstream body with the backend, writes Model,
// and encodes it with the frontend. usage is the response's own usage,
// normalized as Usage says. loss is the response leg's report and is
// nil with today's codecs, which report loss on the request leg only;
// the slot exists so a codec that gains one does not change this
// signature. A body the backend cannot read is DecodeResponse; a
// response the frontend cannot write is EncodeResponse.
func (b *Bridge) Response(body []byte, o ResponseOptions) (out []byte, loss []string, usage Usage, err error) {
	resp, err := b.be.DecodeResponse(body)
	if err != nil {
		return nil, nil, Usage{}, wrap(DecodeResponse, err)
	}
	if o.Model != "" {
		resp.Model = o.Model
	}
	out, err = b.fe.EncodeResponse(resp)
	if err != nil {
		return nil, nil, Usage{}, wrap(EncodeResponse, err)
	}
	var p parts
	p.fromIR(&resp.Usage)
	usage, _ = p.usage()
	return out, nil, usage, nil
}

// StreamOptions carries the caller's hooks. Every one is optional.
type StreamOptions struct {
	// Model is written onto message_start. "" keeps the upstream's.
	Model string
	// FirstByte runs once, before the first event is encoded: the
	// caller writes its status line and headers. An error from it is
	// WriteFailed. It never runs for a stream that carried no event.
	FirstByte func() error
	// Flush runs after each encoded event, and after the error frame.
	Flush func()
	// Fail gives the caller's code and sentence for a failure past the
	// first event; false writes no frame, and so does a nil Fail.
	Fail func(error) (Failure, bool)
}

// Stream pumps an SSE stream from r to w, event by event: decoded with
// the backend's EventDecoder, Model written onto message_start, encoded
// with the frontend's EventEncoder, Flush called after each. The usage
// returned is the last value of each member any event carried, member
// by member, so a dialect that reports input on message_start and
// output on message_delta reports both.
//
// A failure of the upstream stream is StreamFailed; one writing to w,
// or from FirstByte, is WriteFailed. On StreamFailed past the first
// event, Fail decides the frame: ErrorFrame for the frontend's wire is
// written and flushed before Stream returns the usage counted so far
// and the *Error. Before the first event nothing has been written to w,
// so the caller answers as it likes.
func (b *Bridge) Stream(w io.Writer, r io.Reader, o StreamOptions) (Usage, error) {
	dec := b.be.NewEventDecoder(r)
	return b.pump(w, dec.Next, o)
}

// StreamResponse re-emits one whole non-streamed body as the event
// sequence the frontend would have written, for an upstream that
// answered a stream request with JSON: message_start, then per block a
// block_start, its deltas, a block_stop, then message_delta with the
// usage and message_stop. The hooks and the usage are Stream's.
func (b *Bridge) StreamResponse(w io.Writer, body []byte, o StreamOptions) (Usage, error) {
	resp, err := b.be.DecodeResponse(body)
	if err != nil {
		return Usage{}, wrap(DecodeResponse, err)
	}
	events := responseEvents(resp)
	next := func() (ir.Event, error) {
		if len(events) == 0 {
			return ir.Event{}, io.EOF
		}
		ev := events[0]
		events = events[1:]
		return ev, nil
	}
	return b.pump(w, next, o)
}

// pump is the event loop under Stream and StreamResponse.
func (b *Bridge) pump(w io.Writer, next func() (ir.Event, error), o StreamOptions) (Usage, error) {
	enc := b.fe.NewEventEncoder(w)
	var p parts
	started := false
	for {
		ev, err := next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			e := wrap(StreamFailed, err)
			if started {
				b.fail(w, o, e)
			}
			usage, _ := p.usage()
			return usage, e
		}
		if !started {
			if o.FirstByte != nil {
				if err := o.FirstByte(); err != nil {
					return Usage{}, wrap(WriteFailed, err)
				}
			}
			started = true
		}
		if ev.Type == ir.EventMessageStart && o.Model != "" {
			ev.Model = o.Model
		}
		p.fromIR(ev.Usage)
		if err := enc.Encode(ev); err != nil {
			usage, _ := p.usage()
			return usage, wrap(WriteFailed, err)
		}
		if o.Flush != nil {
			o.Flush()
		}
	}
	usage, _ := p.usage()
	return usage, nil
}

// fail writes the frontend wire's error frame for e when Fail says so.
func (b *Bridge) fail(w io.Writer, o StreamOptions, e *Error) {
	if o.Fail == nil {
		return
	}
	f, ok := o.Fail(e)
	if !ok {
		return
	}
	frame := ErrorFrame(wireOf(b.fe.Name()), f)
	if frame == nil {
		return
	}
	_, _ = w.Write(frame)
	if o.Flush != nil {
		o.Flush()
	}
}

// responseEvents re-emits a whole response as the event sequence a
// stream would have carried: message_start, one block with its deltas
// per block, message_delta with the usage, message_stop.
func responseEvents(resp *ir.Response) []ir.Event {
	events := []ir.Event{{Type: ir.EventMessageStart, ID: resp.ID, Model: resp.Model}}
	for i, b := range resp.Blocks {
		header := ir.Block{Type: b.Type}
		if b.ToolUse != nil {
			header.ToolUse = &ir.ToolUse{ID: b.ToolUse.ID, Name: b.ToolUse.Name}
		}
		events = append(events, ir.Event{Type: ir.EventBlockStart, Index: i, Block: &header})
		switch b.Type {
		case ir.BlockText:
			events = append(events, ir.Event{Type: ir.EventTextDelta, Index: i, Delta: b.Text, LogProbs: resp.LogProbs})
		case ir.BlockThinking:
			events = append(events, ir.Event{Type: ir.EventThinkingDelta, Index: i, Delta: b.Text})
			if b.Signature != "" {
				events = append(events, ir.Event{Type: ir.EventSignatureDelta, Index: i, Delta: b.Signature})
			}
		case ir.BlockToolUse:
			if len(b.ToolUse.Args) > 0 {
				events = append(events, ir.Event{Type: ir.EventArgsDelta, Index: i, Delta: string(b.ToolUse.Args)})
			}
		case ir.BlockImage, ir.BlockToolResult, ir.BlockRedactedThinking:
			// Not an output block any dialect streams; the header alone
			// is emitted so the block count stays the response's.
		}
		events = append(events, ir.Event{Type: ir.EventBlockStop, Index: i})
	}
	usage := resp.Usage
	events = append(events,
		ir.Event{Type: ir.EventMessageDelta, StopReason: resp.StopReason, StopSequence: resp.StopSequence, Usage: &usage},
		ir.Event{Type: ir.EventMessageStop},
	)
	return events
}
