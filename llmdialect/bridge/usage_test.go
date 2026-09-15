// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func i64(v int64) *int64 { return &v }

// TestUsageMembersPerWire reads each wire's usage members off one body,
// with input excluding cached input on every wire and every member
// floored at zero.
func TestUsageMembersPerWire(t *testing.T) {
	cases := []struct {
		w    Wire
		body string
		want Usage
		ok   bool
	}{
		{WireOpenAI, string(fixture(t, "fixtures/openai-chat.response.json")), Usage{Input: 10, Output: 3, CachedInput: 2}, true},
		{WireOpenAI, `{"usage":{"prompt_tokens":1,"prompt_tokens_details":{"cached_tokens":5},"completion_tokens_details":{"reasoning_tokens":2}}}`, Usage{Input: 0, CachedInput: 5, Reasoning: 2}, true},
		{WireAnthropic, string(fixture(t, "fixtures/anthropic-messages.response.json")), Usage{Input: 10, Output: 4, CachedInput: 1, CacheWrite: 5}, true},
		{WireGoogle, string(fixture(t, "fixtures/google.response.json")), Usage{Input: 6, Output: 2, CachedInput: 3}, true},
		{WireGoogle, `{"usageMetadata":{"promptTokenCount":9,"thoughtsTokenCount":4}}`, Usage{Input: 9, Reasoning: 4}, true},
		{WireLux, string(fixture(t, "fixtures/lux.response.json")), Usage{Input: 7, Output: 1, Reasoning: 1}, true},
		{WireLux, `{"usage":{"input_tokens":1,"output_tokens":2,"cache_read_input_tokens":3,"cache_write_input_tokens":4}}`, Usage{Input: 1, Output: 2, CachedInput: 3, CacheWrite: 4}, true},
		{WireLux, `{"usage":{"input_tokens":-1,"output_tokens":-2}}`, Usage{}, true},
		{WireOpenAI, `{"choices":[]}`, Usage{}, false},
		{WireOpenAI, `not json`, Usage{}, false},
		{WireAnthropic, `{"usage":{"prompt_tokens":5}}`, Usage{}, false},
		{"", `{"usage":{"input_tokens":5}}`, Usage{}, false},
	}
	for _, c := range cases {
		got, ok := UsageOf(c.w, []byte(c.body))
		if ok != c.ok || got != c.want {
			t.Errorf("%s %s: %+v %v, want %+v %v", c.w, c.body, got, ok, c.want, c.ok)
		}
	}
}

// TestUsageIsTheLastValue feeds an SSE stream in awkward chunks and
// reads the last value of each member, with a final frame the stream
// did not terminate.
func TestUsageIsTheLastValue(t *testing.T) {
	s := NewUsageScanner(WireOpenAI, FramingSSE)
	stream := "data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":1}}\r\n\r\n: comment\n\ndata: {\"usage\":\ndata: {\"completion_tokens\":4}}\n\ndata: [DONE]\n\ndata: {\"usage\":{\"completion_tokens\":9}}"
	for i := 0; i < len(stream); i += 7 {
		end := min(i+7, len(stream))
		if n, err := s.Write([]byte(stream[i:end])); err != nil || n != end-i {
			t.Fatal(n, err)
		}
	}
	s.Close()
	s.Close() // idempotent
	got, ok := s.Usage()
	if !ok || got != (Usage{Input: 10, Output: 9}) {
		t.Errorf("%+v %v", got, ok)
	}
	empty := NewUsageScanner(WireAnthropic, FramingSSE)
	_, _ = empty.Write([]byte("event: ping\ndata: {}\n\n"))
	empty.Close()
	if _, ok := empty.Usage(); ok {
		t.Error("a stream without usage reported some")
	}
	if end, size := frameEnd([]byte("a\r\n\r\nb\n\n")); end != 1 || size != 4 {
		t.Errorf("frameEnd crlf: %d %d", end, size)
	}
	if end, size := frameEnd([]byte("a\n\nb\r\n\r\n")); end != 1 || size != 2 {
		t.Errorf("frameEnd lf: %d %d", end, size)
	}
	// The anthropic stream: input on message_start, output on
	// message_delta, the cache read kept.
	a := NewUsageScanner(WireAnthropic, FramingSSE)
	_, _ = a.Write(fixture(t, "fixtures/anthropic-messages.stream.sse"))
	a.Close()
	if got, ok := a.Usage(); !ok || got != (Usage{Input: 11, Output: 6, CachedInput: 2}) {
		t.Errorf("anthropic stream %+v %v", got, ok)
	}
	// A later chunk's usage over an earlier one's, member by member.
	o := NewUsageScanner(WireOpenAI, FramingSSE)
	_, _ = o.Write([]byte("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":1,\"prompt_tokens_details\":{\"cached_tokens\":50}}}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":7}}\n\ndata: [DONE]\n\n"))
	if got, _ := o.Usage(); got != (Usage{Input: 50, Output: 7, CachedInput: 50}) {
		t.Errorf("openai last value %+v", got)
	}
}

// TestJSONScanner reads a Google array element by element across chunk
// boundaries, strings with brackets and escapes included, one object
// that is not an array, and a cut element that is not read.
func TestJSONScanner(t *testing.T) {
	s := NewUsageScanner(WireGoogle, FramingJSON)
	array := "  [ {\"text\":\"a [ } \\\" ] {\",\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":1}}\n, {\"nested\":[{\"x\":[1,2]}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":5}} , {\"usageMetadata\":{\"cachedContentTokenCount\":2}}]"
	for i := 0; i < len(array); i += 5 {
		end := min(i+5, len(array))
		_, _ = s.Write([]byte(array[i:end]))
	}
	s.Close()
	got, ok := s.Usage()
	if !ok || got != (Usage{Input: 1, Output: 5, CachedInput: 2}) {
		t.Errorf("%+v %v", got, ok)
	}
	whole := NewUsageScanner(WireGoogle, FramingJSON)
	_, _ = whole.Write(fixture(t, "fixtures/google.stream.json"))
	if got, ok := whole.Usage(); !ok || got != (Usage{Input: 4, Output: 2, CachedInput: 1}) {
		t.Errorf("the fixture array: %+v %v", got, ok)
	}
	one := NewUsageScanner(WireGoogle, FramingJSON)
	_, _ = one.Write(fixture(t, "fixtures/google.response.json"))
	if got, ok := one.Usage(); !ok || got != (Usage{Input: 6, Output: 2, CachedInput: 3}) {
		t.Errorf("one object: %+v %v", got, ok)
	}
	cut := NewUsageScanner(WireGoogle, FramingJSON)
	_, _ = cut.Write([]byte(`[{"usageMetadata":{"promptTokenCount":3}},{"usageMetadata":{"promptTokenCount":9}`))
	cut.Close()
	if got, _ := cut.Usage(); got.Input != 3 {
		t.Errorf("a cut element was read: %+v", got)
	}
	none := NewUsageScanner(WireGoogle, FramingJSON)
	_, _ = none.Write([]byte(`  "just a string"`))
	if _, ok := none.Usage(); ok {
		t.Error("a scalar body reported usage")
	}
}

// TestUsageFromIR merges IR usage member by member: a later event's
// nonzero member replaces an earlier one, a zero never erases a value
// already reported, and an all-zero usage is still a report.
func TestUsageFromIR(t *testing.T) {
	var p parts
	p.fromIR(nil)
	if _, ok := p.usage(); ok {
		t.Error("nil usage reported something")
	}
	p.fromIR(&ir.Usage{InputTokens: 10, CacheReadInputTokens: i64(2)})
	p.fromIR(&ir.Usage{OutputTokens: 5})
	p.fromIR(&ir.Usage{OutputTokens: 7, CacheWriteInputTokens: i64(1), ReasoningTokens: 3})
	got, ok := p.usage()
	if !ok || got != (Usage{Input: 10, Output: 7, CachedInput: 2, CacheWrite: 1, Reasoning: 3}) {
		t.Errorf("%+v %v", got, ok)
	}
	var zero parts
	zero.fromIR(&ir.Usage{})
	if got, ok := zero.usage(); !ok || got != (Usage{}) {
		t.Errorf("an all-zero usage is still a report: %+v %v", got, ok)
	}
}

func FuzzUsageScanner(f *testing.F) {
	f.Add(uint8(0), uint8(0), []byte("data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":1}}\n\ndata: {\"usage\":{\"completion_tokens\":4}}\n\n"))
	f.Add(uint8(2), uint8(1), []byte(`[{"usageMetadata":{"promptTokenCount":3}},{"usageMetadata":{"candidatesTokenCount":9}}]`))
	f.Add(uint8(1), uint8(0), []byte("event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":4}}}\n\n"))
	f.Add(uint8(3), uint8(1), []byte(`"a \" ] } string"`))
	wires := []Wire{WireOpenAI, WireAnthropic, WireGoogle, WireLux}
	f.Fuzz(func(t *testing.T, wire, framing uint8, stream []byte) {
		w, fr := wires[int(wire)%4], Framing(int(framing)%2)
		whole := NewUsageScanner(w, fr)
		_, _ = whole.Write(stream)
		whole.Close()
		want, wantOK := whole.Usage()
		chunked := NewUsageScanner(w, fr)
		for i := 0; i < len(stream); i += 3 {
			_, _ = chunked.Write(stream[i:min(i+3, len(stream))])
		}
		chunked.Close()
		if got, ok := chunked.Usage(); got != want || ok != wantOK {
			t.Fatalf("chunking changed the answer: %+v %v, whole %+v %v", got, ok, want, wantOK)
		}
		// One SSE frame's data reads as UsageOf reads the same bytes.
		if fr == FramingSSE && bytes.Count(stream, []byte("\n\n")) == 0 && bytes.Count(stream, []byte("\r\n\r\n")) == 0 {
			if got, ok := UsageOf(w, frameData(stream)); got != want || ok != wantOK {
				t.Fatalf("one frame: %+v %v, UsageOf %+v %v", want, wantOK, got, ok)
			}
		}
		if want.Input < 0 || want.Output < 0 || want.CachedInput < 0 || want.CacheWrite < 0 || want.Reasoning < 0 {
			t.Fatalf("a negative member: %+v", want)
		}
	})
}
