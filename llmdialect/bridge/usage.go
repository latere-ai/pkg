// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"
	"encoding/json"

	"latere.ai/x/pkg/llmdialect/ir"
)

// Usage is one dialect's usage members, normalised: Input never counts
// cache reads, which OpenAI and Google fold into their prompt total and
// Anthropic reports beside it, so the five numbers add up the same way
// whatever answered. Every member is floored at zero.
type Usage struct {
	Input, Output, CachedInput, CacheWrite, Reasoning int64
}

// parts is the usage members of one dialect as they appear on the wire,
// each a pointer so a member that was present is told from one that was
// not: a stream's usage is the last value of each member, and only a
// member that appeared can be a last value.
type parts struct {
	prompt, completion, cached, cacheWrite, reasoning *int64
	subtractCached                                    bool // openai and google report a prompt total that includes cache reads
}

// wireUsage is every dialect's usage object in one struct, so one decode
// reads whichever members the frame carries.
type wireUsage struct {
	PromptTokens        *int64 `json:"prompt_tokens"`
	CompletionTokens    *int64 `json:"completion_tokens"`
	PromptTokensDetails *struct {
		CachedTokens *int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionTokensDetails *struct {
		ReasoningTokens *int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`

	InputTokens              *int64 `json:"input_tokens"`
	OutputTokens             *int64 `json:"output_tokens"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
	CacheWriteInputTokens    *int64 `json:"cache_write_input_tokens"`
	ReasoningTokens          *int64 `json:"reasoning_tokens"`

	PromptTokenCount        *int64 `json:"promptTokenCount"`
	CandidatesTokenCount    *int64 `json:"candidatesTokenCount"`
	CachedContentTokenCount *int64 `json:"cachedContentTokenCount"`
	ThoughtsTokenCount      *int64 `json:"thoughtsTokenCount"`
}

// wireEnvelope is where a usage object sits: usage on a body or a frame,
// message.usage on an Anthropic message_start, usageMetadata on Google.
type wireEnvelope struct {
	Usage         *wireUsage `json:"usage"`
	UsageMetadata *wireUsage `json:"usageMetadata"`
	Message       *struct {
		Usage *wireUsage `json:"usage"`
	} `json:"message"`
}

// merge takes every member present in data into p, so a later frame's
// value replaces an earlier one member by member. Data that is not a
// JSON object contributes nothing.
func (p *parts) merge(w Wire, data []byte) {
	var env wireEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}
	for _, u := range []*wireUsage{env.Usage, env.UsageMetadata} {
		if u != nil {
			p.mergeUsage(w, u)
		}
	}
	if env.Message != nil && env.Message.Usage != nil {
		p.mergeUsage(w, env.Message.Usage)
	}
}

func set(dst **int64, src *int64) {
	if src != nil {
		*dst = src
	}
}

func (p *parts) mergeUsage(w Wire, u *wireUsage) {
	switch w {
	case WireOpenAI:
		p.subtractCached = true
		set(&p.prompt, u.PromptTokens)
		set(&p.completion, u.CompletionTokens)
		if u.PromptTokensDetails != nil {
			set(&p.cached, u.PromptTokensDetails.CachedTokens)
		}
		if u.CompletionTokensDetails != nil {
			set(&p.reasoning, u.CompletionTokensDetails.ReasoningTokens)
		}
	case WireAnthropic:
		set(&p.prompt, u.InputTokens)
		set(&p.completion, u.OutputTokens)
		set(&p.cached, u.CacheReadInputTokens)
		set(&p.cacheWrite, u.CacheCreationInputTokens)
	case WireGoogle:
		p.subtractCached = true
		set(&p.prompt, u.PromptTokenCount)
		set(&p.completion, u.CandidatesTokenCount)
		set(&p.cached, u.CachedContentTokenCount)
		set(&p.reasoning, u.ThoughtsTokenCount)
	case WireLux:
		set(&p.prompt, u.InputTokens)
		set(&p.completion, u.OutputTokens)
		set(&p.cached, u.CacheReadInputTokens)
		set(&p.cacheWrite, u.CacheWriteInputTokens)
		set(&p.reasoning, u.ReasoningTokens)
	}
}

// deref is the member's value floored at zero, and zero for one that
// never appeared.
func deref(p *int64) int64 {
	if p == nil || *p < 0 {
		return 0
	}
	return *p
}

// usage folds the parts into a Usage: input excludes cached input on the
// wires that fold it in, floored at zero. ok is false when no usage
// member appeared at all.
func (p parts) usage() (Usage, bool) {
	if p.prompt == nil && p.completion == nil && p.cached == nil && p.cacheWrite == nil && p.reasoning == nil {
		return Usage{}, false
	}
	u := Usage{
		Input:       deref(p.prompt),
		Output:      deref(p.completion),
		CachedInput: deref(p.cached),
		CacheWrite:  deref(p.cacheWrite),
		Reasoning:   deref(p.reasoning),
	}
	if p.subtractCached {
		u.Input = max(u.Input-u.CachedInput, 0)
	}
	return u, true
}

// fromIR merges an IR usage member by member: a translated stream
// reports usage on message_start and on message_delta, and a nonzero
// member reported later replaces one reported earlier, while a zero
// never erases a value already reported. A cache count the IR has none
// of counts as zero here: Usage is the floored total a meter wants,
// not the report.
func (p *parts) fromIR(u *ir.Usage) {
	if u == nil {
		return
	}
	in, out, cached, write, reasoning := u.InputTokens, u.OutputTokens, deref(u.CacheReadInputTokens), deref(u.CacheWriteInputTokens), u.ReasoningTokens
	if in > 0 || p.prompt == nil {
		p.prompt = &in
	}
	if out > 0 || p.completion == nil {
		p.completion = &out
	}
	if cached > 0 || p.cached == nil {
		p.cached = &cached
	}
	if write > 0 || p.cacheWrite == nil {
		p.cacheWrite = &write
	}
	if reasoning > 0 || p.reasoning == nil {
		p.reasoning = &reasoning
	}
}

// UsageOf reads the usage members off one whole body of the wire:
// usage, usageMetadata, or message.usage, wherever that wire puts them.
// ok is false when the body carries none of the wire's members.
func UsageOf(w Wire, body []byte) (Usage, bool) {
	var p parts
	p.merge(w, body)
	return p.usage()
}

// Framing is how a stream is framed: SSE frames, or a JSON array whose
// elements are read one at a time as each closes.
type Framing int

// The two framings.
const (
	FramingSSE Framing = iota
	FramingJSON
)

// UsageScanner reads usage off a stream as it is relayed, without
// holding it: the last value of each member wins. It is an io.Writer so
// it can sit beside a relay, and it never fails.
type UsageScanner struct {
	w       Wire
	framing Framing
	parts   parts
	buf     []byte

	// The JSON scanner's state: the nesting depth inside the current
	// element, whether the cursor is inside a string or after a
	// backslash, whether the top-level value has begun, and whether an
	// element is being collected.
	depth            int
	inString, escape bool
	started, inElem  bool
}

// NewUsageScanner reads the wire's usage members off a stream framed as
// f.
func NewUsageScanner(w Wire, f Framing) *UsageScanner {
	return &UsageScanner{w: w, framing: f}
}

// Write consumes p and reads every frame or element it completes. It
// never returns an error.
func (s *UsageScanner) Write(p []byte) (int, error) {
	if s.framing == FramingJSON {
		s.writeJSON(p)
	} else {
		s.writeSSE(p)
	}
	return len(p), nil
}

// Close reads a final SSE frame the stream ended without terminating.
// A JSON element the stream cut short is not read.
func (s *UsageScanner) Close() {
	if s.framing == FramingSSE && len(bytes.TrimSpace(s.buf)) > 0 {
		s.frame(s.buf)
		s.buf = nil
	}
}

// Usage is the last value of each member across the stream so far, and
// false when no member has appeared.
func (s *UsageScanner) Usage() (Usage, bool) { return s.parts.usage() }

func (s *UsageScanner) writeSSE(p []byte) {
	s.buf = append(s.buf, p...)
	for {
		end, size := frameEnd(s.buf)
		if end < 0 {
			return
		}
		s.frame(s.buf[:end])
		s.buf = s.buf[end+size:]
	}
}

// frameEnd finds the first blank line in b: the index where the frame
// ends and the size of the separator, or -1.
func frameEnd(b []byte) (int, int) {
	lf := bytes.Index(b, []byte("\n\n"))
	crlf := bytes.Index(b, []byte("\r\n\r\n"))
	switch {
	case lf < 0 && crlf < 0:
		return -1, 0
	case crlf >= 0 && (lf < 0 || crlf < lf):
		return crlf, 4
	default:
		return lf, 2
	}
}

func (s *UsageScanner) frame(frame []byte) {
	if data := frameData(frame); len(data) > 0 {
		s.parts.merge(s.w, data)
	}
}

// frameData joins the data lines of one SSE frame with \n, as the SSE
// rule says.
func frameData(frame []byte) []byte {
	var data [][]byte
	for line := range bytes.SplitSeq(frame, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if rest, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			data = append(data, bytes.TrimPrefix(rest, []byte(" ")))
		}
	}
	return bytes.Join(data, []byte("\n"))
}

// writeJSON reads a JSON body relayed in chunks: one object, or an array
// whose elements are read one at a time as each closes, so the body is
// never held whole.
func (s *UsageScanner) writeJSON(p []byte) {
	for _, c := range p {
		if !s.started {
			switch c {
			case '[':
				s.started = true
				continue
			case '{':
				s.started = true
			default:
				continue
			}
		}
		if s.inElem {
			s.buf = append(s.buf, c)
		}
		if s.inString {
			switch {
			case s.escape:
				s.escape = false
			case c == '\\':
				s.escape = true
			case c == '"':
				s.inString = false
			}
			continue
		}
		switch c {
		case '"':
			if s.inElem {
				s.inString = true
			}
		case '{', '[':
			if !s.inElem {
				s.inElem = true
				s.buf = append(s.buf[:0], c)
			}
			s.depth++
		case '}', ']':
			if s.inElem {
				s.depth--
				if s.depth == 0 {
					s.parts.merge(s.w, s.buf)
					s.inElem = false
				}
			}
		}
	}
}
