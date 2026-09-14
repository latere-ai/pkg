// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package bridge translates requests, responses, and streams between
// LLM provider API dialects, and renders the shapes that surround a
// translation, with no server in the way. A program holds bytes in one
// dialect, say a Chat Completions request, and wants them in another,
// say a Messages request an Anthropic-compatible upstream will accept;
// a Bridge is the pair of codecs from llmdialect with the two things
// every such program writes between the legs, the upstream's model
// name into the request and the caller's back into the response, and
// the usage read off whatever came back. Around the pair, the package
// renders the error envelope, the model list, the count answer, and
// the mid-stream error frame in each of four wires, reads the usage
// members off any wire's body or stream, and edits a body's model or
// stream_options member in place without re-encoding it. Everything
// takes bytes and writers; nothing here knows HTTP, and no code, status,
// or sentence but the package's own seven failures is decided here.
//
// # A request, translated
//
// Open names the caller's dialect and the upstream's. Request decodes,
// writes the upstream's model name, encodes, and reports what the
// upstream dialect could not carry:
//
//	b, err := bridge.Open(ir.DialectOpenAIChat, ir.DialectAnthropicMessages, bridge.Options{})
//	out, loss, err := b.Request(body, bridge.RequestOptions{Model: "claude-3-5-sonnet"})
//	// out is a Messages request; loss is nil or ["top_logprobs", ...]
//
// # A response, translated back
//
// Response decodes the upstream's body, writes the name the caller asked
// for, encodes in the caller's dialect, and returns the usage normalised
// so input never counts cache reads:
//
//	out, _, usage, err := b.Response(upstreamBody, bridge.ResponseOptions{Model: "my-model"})
//
// # A stream, relayed event by event
//
// Stream decodes each upstream event and encodes it for the caller as it
// arrives. FirstByte runs once before anything is written, for the
// status line and headers; Flush runs after each event; Fail turns a
// failure past the first event into the caller's error frame:
//
//	usage, err := b.Stream(w, upstream.Body, bridge.StreamOptions{
//		Model:     "my-model",
//		FirstByte: func() error { w.WriteHeader(200); return nil },
//		Flush:     flusher.Flush,
//		Fail:      func(err error) (bridge.Failure, bool) { return bridge.Failure{Code: "upstream_error", Message: "The provider returned an error."}, true },
//	})
//
// StreamResponse does the same for an upstream that answered a stream
// request with one JSON body, re-emitting it as the caller's events.
//
// # Errors
//
// Every failure is an *Error with one of seven Codes, the codec's words
// in Detail, and the codec's error under Unwrap. A DecodeRequest carries
// its RefusalScope; Scope classifies any error the package returns:
//
//	var e *bridge.Error
//	if errors.As(err, &e) && e.Code == bridge.DecodeRequest && bridge.Scope(err) == llmdialect.ScopeSurface { ... }
//
// # Envelopes, frames, lists, counts
//
// Envelope renders a Failure in a wire's error shape, ParseEnvelope
// reads one back, and ErrorFrame is the frame that ends a stream which
// failed after its first byte:
//
//	body := bridge.Envelope(bridge.WireOpenAI, bridge.Failure{Code: "rate_limited", Message: "Too many requests; wait and retry."})
//	f, ok := bridge.ParseEnvelope(bridge.WireOpenAI, body)
//	frame := bridge.ErrorFrame(bridge.WireAnthropic, f)
//
// ModelList and ModelEntry render a wire's model list and one entry;
// CountTokens estimates a request's input tokens for a wire whose
// upstream cannot count, and CountBody renders the answer:
//
//	list := bridge.ModelList(bridge.WireAnthropic, []bridge.Model{{Name: "my-model"}})
//	n, estimated, err := bridge.CountTokens(bridge.WireAnthropic, body)
//	answer := bridge.CountBody(bridge.WireAnthropic, n)
//
// # Usage
//
// UsageOf reads the usage members off a whole body, and a UsageScanner
// reads them off a stream as it is relayed, the last value of each
// member winning:
//
//	usage, ok := bridge.UsageOf(bridge.WireGoogle, body)
//	scanner := bridge.NewUsageScanner(bridge.WireOpenAI, bridge.FramingSSE)
//	io.Copy(io.MultiWriter(w, scanner), upstream.Body)
//	scanner.Close()
//	usage, ok = scanner.Usage()
//
// # Byte edits
//
// Probe reads the model, stream, and output-limit members of any
// dialect's request. SetModel, SetModelInFrame, SetIncludeUsage, and
// RemoveMember change one member of a body and no other byte, so a body
// passed through arrives as the caller wrote it:
//
//	call, err := bridge.Probe(body)
//	body = bridge.SetModel(body, "upstream-name")
//	body = bridge.SetIncludeUsage(body)
//	body = bridge.RemoveMember(body, "max_tokens")
package bridge
