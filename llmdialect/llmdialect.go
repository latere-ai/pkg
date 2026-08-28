// Package llmdialect translates between LLM inference wire dialects —
// Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, and
// the lux-native dialect (the IR itself as a public wire format) —
// through a neutral intermediate representation (package ir), so a
// caller speaking one dialect can drive a model served behind
// another.
//
// Translation is hub-and-spoke: each dialect implements a Frontend
// (caller side) and/or Backend (upstream side) codec against the IR,
// never a pairwise mapping. The package is wire-level — bytes and SSE
// events in, bytes and SSE events out — and owns no transport, auth,
// or logging; the consumer (e.g. the Lux gateway's /compat surfaces)
// supplies those.
//
// Fields the target dialect cannot represent are collected in the
// request's loss report (ir.Request.Loss) rather than silently
// dropped. Per-token log probabilities are one such field: the two
// OpenAI dialects and the lux dialect serve them, each in its own
// shape, and Anthropic Messages has no member for them in either
// direction, so an ask routed there is reported as loss.
package llmdialect

import (
	"io"
	"net/http"

	"latere.ai/x/pkg/llmdialect/ir"
)

// Dialect names an LLM inference wire dialect, matching the
// spec-18/25 descriptor vocabulary.
type Dialect = ir.Dialect

// Dialects.
const (
	DialectAnthropicMessages = ir.DialectAnthropicMessages
	DialectOpenAIChat        = ir.DialectOpenAIChat
	DialectOpenAIResponses   = ir.DialectOpenAIResponses
	DialectLux               = ir.DialectLux
)

// Frontend is the caller-side codec of a dialect: it decodes what the
// client sent and encodes what the client gets back.
type Frontend interface {
	Name() Dialect
	DecodeRequest(body []byte) (*ir.Request, error)
	EncodeResponse(resp *ir.Response) ([]byte, error)
	NewEventEncoder(w io.Writer) EventEncoder
}

// Backend is the upstream-side codec of a dialect: it encodes what the
// model server receives and decodes what it returned.
type Backend interface {
	Name() Dialect
	EncodeRequest(req *ir.Request) ([]byte, error)
	DecodeResponse(body []byte) (*ir.Response, error)
	NewEventDecoder(r io.Reader) EventDecoder
}

// EventEncoder writes one dialect-native SSE frame set per IR event.
type EventEncoder = ir.EventEncoder

// EventDecoder yields canonical IR events from a dialect-native SSE
// stream, returning io.EOF after the final event.
type EventDecoder = ir.EventDecoder

// Translator pairs a caller-side frontend with an upstream-side
// backend.
type Translator struct {
	Frontend Frontend
	Backend  Backend
}

// Request translates a caller request body into the backend dialect.
// The returned ir.Request carries the accumulated loss report and the
// decoded call shape (model, stream flag) for the transport layer.
func (t *Translator) Request(body []byte) ([]byte, *ir.Request, error) {
	req, err := t.Frontend.DecodeRequest(body)
	if err != nil {
		return nil, nil, err
	}
	out, err := t.Backend.EncodeRequest(req)
	if err != nil {
		return nil, nil, err
	}
	return out, req, nil
}

// Response translates a non-streaming backend response body into the
// frontend dialect.
func (t *Translator) Response(body []byte) ([]byte, error) {
	resp, err := t.Backend.DecodeResponse(body)
	if err != nil {
		return nil, err
	}
	return t.Frontend.EncodeResponse(resp)
}

// Stream pumps a backend SSE stream into dst re-encoded in the
// frontend dialect, flushing after every event when dst is an
// http.Flusher. The transform is incremental; it returns when the
// backend stream ends or either side fails.
func (t *Translator) Stream(dst io.Writer, src io.Reader) error {
	dec := t.Backend.NewEventDecoder(src)
	enc := t.Frontend.NewEventEncoder(dst)
	flusher, _ := dst.(http.Flusher)
	for {
		ev, err := dec.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := enc.Encode(ev); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}
