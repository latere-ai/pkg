// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect"
	"latere.ai/x/pkg/llmdialect/ir"
)

// The four codec dialects, and the one wire that has none.
var (
	codecDialects = []ir.Dialect{ir.DialectOpenAIChat, ir.DialectOpenAIResponses, ir.DialectAnthropicMessages, ir.DialectLux}
	geminiDialect = ir.Dialect("gemini")
)

// open builds a pair or fails the test.
func open(t *testing.T, from, to ir.Dialect) *Bridge {
	t.Helper()
	b, err := Open(from, to, Options{})
	if err != nil {
		t.Fatalf("Open(%s, %s): %v", from, to, err)
	}
	return b
}

// TestOpenPairs: every pair with codecs on both sides opens and reports
// its two dialects; a dialect with no codec on either side is
// Unsupported.
func TestOpenPairs(t *testing.T) {
	all := append(append([]ir.Dialect{}, codecDialects...), geminiDialect)
	for _, from := range all {
		for _, to := range all {
			b, err := Open(from, to, Options{})
			want := from != geminiDialect && to != geminiDialect
			if (err == nil) != want {
				t.Errorf("Open(%s, %s): err %v, want supported %v", from, to, err, want)
				continue
			}
			if !want {
				var e *Error
				if !errors.As(err, &e) || e.Code != Unsupported || e.Message() == "" {
					t.Errorf("Open(%s, %s): %v is not Unsupported", from, to, err)
				}
				continue
			}
			if b.From() != from || b.To() != to {
				t.Errorf("Open(%s, %s) reports %s -> %s", from, to, b.From(), b.To())
			}
		}
	}
	// New takes codecs the caller built.
	b := New(frontendFor(ir.DialectLux), backendFor(ir.DialectLux, Options{}))
	if b.From() != ir.DialectLux || b.To() != ir.DialectLux {
		t.Error("New")
	}
	if wireOf(geminiDialect) != "" {
		t.Error("a wire for a dialect that is none")
	}
}

// TestOptionsReachTheCodecs: DefaultMaxTokens and DropSampling reach the
// anthropic backend, UseMaxCompletionTokens the openai one.
func TestOptionsReachTheCodecs(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"x"}],"temperature":0.5}`)
	b, _ := Open(ir.DialectOpenAIChat, ir.DialectAnthropicMessages, Options{DefaultMaxTokens: 256, DropSampling: true})
	out, loss, err := b.Request(body, RequestOptions{})
	if err != nil || !strings.Contains(string(out), `"max_tokens":256`) || strings.Contains(string(out), "temperature") || strings.Join(loss, ",") != "temperature" {
		t.Errorf("anthropic options: %s %v %v", out, loss, err)
	}
	b, _ = Open(ir.DialectOpenAIChat, ir.DialectAnthropicMessages, Options{})
	if out, _, _ = b.Request(body, RequestOptions{}); !strings.Contains(string(out), `"max_tokens":4096`) {
		t.Errorf("no DefaultMaxTokens is not the codec's 4096: %s", out)
	}
	limited := []byte(`{"model":"m","max_tokens":9,"messages":[{"role":"user","content":"x"}]}`)
	b, _ = Open(ir.DialectAnthropicMessages, ir.DialectOpenAIChat, Options{UseMaxCompletionTokens: true})
	if out, _, _ = b.Request(limited, RequestOptions{}); !strings.Contains(string(out), `"max_completion_tokens":9`) {
		t.Errorf("UseMaxCompletionTokens: %s", out)
	}
	b, _ = Open(ir.DialectAnthropicMessages, ir.DialectOpenAIChat, Options{})
	if out, _, _ = b.Request(limited, RequestOptions{}); !strings.Contains(string(out), `"max_tokens":9`) {
		t.Errorf("max_tokens: %s", out)
	}
}

// TestRequestWritesTheModel: the upstream name is written between the
// legs, and "" keeps the caller's.
func TestRequestWritesTheModel(t *testing.T) {
	b := open(t, ir.DialectOpenAIChat, ir.DialectAnthropicMessages)
	body := fixture(t, "fixtures/openai-chat.request.json")
	out, _, err := b.Request(body, RequestOptions{Model: "claude-3"})
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	if err := json.Unmarshal(out, &sent); err != nil {
		t.Fatal(err)
	}
	if sent["model"] != "claude-3" || sent["max_tokens"] != float64(4096) {
		t.Errorf("sent %s", out)
	}
	if out, _, _ = b.Request(body, RequestOptions{}); !strings.Contains(string(out), `"model":"claude"`) {
		t.Errorf("an empty Model did not keep the caller's: %s", out)
	}
	// A body the frontend cannot read is DecodeRequest with a scope.
	_, _, err = b.Request([]byte(`{"model":"m"}`), RequestOptions{})
	var e *Error
	if !errors.As(err, &e) || e.Code != DecodeRequest || e.Scope == llmdialect.ScopeNone || e.Detail == "" || e.Unwrap() == nil {
		t.Errorf("undecodable: %+v", err)
	}
	if Scope(err) != e.Scope {
		t.Errorf("Scope(err) %s, Error.Scope %s", Scope(err), e.Scope)
	}
}

// TestRequestLossReport: the codecs' entries and the caller's, in order,
// deduplicated, nil when nothing was lost.
func TestRequestLossReport(t *testing.T) {
	b := open(t, ir.DialectAnthropicMessages, ir.DialectOpenAIChat)
	body := fixture(t, "fixtures/anthropic-messages.request.json")
	_, loss, err := b.Request(body, RequestOptions{Model: "gpt-4.1", Loss: []string{"header.anthropic-beta", "top_k"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(loss, ","); got != "header.anthropic-beta,top_k" {
		t.Errorf("loss %q", got)
	}
	_, loss, err = b.Request(body, RequestOptions{})
	if err != nil || strings.Join(loss, ",") != "top_k" {
		t.Errorf("codec loss alone: %v %v", loss, err)
	}
	lossless := open(t, ir.DialectOpenAIChat, ir.DialectAnthropicMessages)
	if _, loss, err = lossless.Request(fixture(t, "fixtures/openai-chat.request.json"), RequestOptions{}); err != nil || loss != nil {
		t.Errorf("a lossless translation reports %v %v", loss, err)
	}
}

// TestResponseWritesTheModel: the caller-facing name is written back,
// "" keeps the upstream's, and the response's usage is normalized.
func TestResponseWritesTheModel(t *testing.T) {
	b := open(t, ir.DialectAnthropicMessages, ir.DialectOpenAIChat)
	body := fixture(t, "fixtures/openai-chat.response.json")
	out, loss, usage, err := b.Response(body, ResponseOptions{Model: "gpt"})
	if err != nil || loss != nil {
		t.Fatal(err, loss)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["type"] != "message" || got["model"] != "gpt" {
		t.Errorf("the caller received %s", out)
	}
	if usage != (Usage{Input: 10, Output: 3, CachedInput: 2}) {
		t.Errorf("usage %+v", usage)
	}
	if out, _, _, _ = b.Response(body, ResponseOptions{}); !strings.Contains(string(out), `"model":"gpt-4.1"`) {
		t.Errorf("an empty Model did not keep the upstream's: %s", out)
	}
	_, _, _, err = b.Response([]byte(`{`), ResponseOptions{})
	var e *Error
	if !errors.As(err, &e) || e.Code != DecodeResponse || e.Scope != llmdialect.ScopeNone {
		t.Errorf("undecodable response: %+v", err)
	}
}

// TestResponseUsage reads each backend's usage members through the IR.
func TestResponseUsage(t *testing.T) {
	cases := []struct {
		be   ir.Dialect
		want Usage
	}{
		{ir.DialectOpenAIChat, Usage{Input: 10, Output: 3, CachedInput: 2}},
		{ir.DialectOpenAIResponses, Usage{Input: 90, Output: 20, CachedInput: 10, Reasoning: 8}},
		{ir.DialectAnthropicMessages, Usage{Input: 10, Output: 4, CachedInput: 1, CacheWrite: 5}},
		{ir.DialectLux, Usage{Input: 7, Output: 1, Reasoning: 1}},
	}
	for _, c := range cases {
		b := open(t, ir.DialectLux, c.be)
		_, _, usage, err := b.Response(fixture(t, "fixtures/"+string(c.be)+".response.json"), ResponseOptions{Model: "m"})
		if err != nil || usage != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.be, usage, err, c.want)
		}
	}
}

// recorder is a writer that notes the order of hook calls against its
// writes and can fail on demand.
type recorder struct {
	bytes.Buffer
	events  []string
	failAt  int // fail the nth write, 1-based; 0 never
	writes  int
	flushed int
}

func (r *recorder) Write(p []byte) (int, error) {
	r.writes++
	if r.failAt > 0 && r.writes >= r.failAt {
		return 0, errors.New("pipe closed")
	}
	r.events = append(r.events, "write")
	return r.Buffer.Write(p)
}

func (r *recorder) firstByte() error {
	r.events = append(r.events, "first")
	return nil
}

func (r *recorder) flush() {
	r.flushed++
	r.events = append(r.events, "flush")
}

// TestStreamReencodes: an anthropic stream comes out as Chat Completions
// chunks with the caller's model name and [DONE], and the usage is the
// last value of each member.
func TestStreamReencodes(t *testing.T) {
	b := open(t, ir.DialectOpenAIChat, ir.DialectAnthropicMessages)
	var w bytes.Buffer
	usage, err := b.Stream(&w, bytes.NewReader(fixture(t, "fixtures/anthropic-messages.stream.sse")), StreamOptions{Model: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	body := w.String()
	if !strings.Contains(body, `"object":"chat.completion.chunk"`) || !strings.Contains(body, `"model":"claude"`) || !strings.Contains(body, `"content":"hi"`) || !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Errorf("translated stream %s", body)
	}
	if strings.Contains(body, "claude-3") {
		t.Error("the upstream name reached the caller")
	}
	if usage != (Usage{Input: 11, Output: 6, CachedInput: 2}) {
		t.Errorf("usage %+v", usage)
	}
	// An empty Model keeps the upstream's.
	w.Reset()
	if _, err := b.Stream(&w, bytes.NewReader(fixture(t, "fixtures/anthropic-messages.stream.sse")), StreamOptions{}); err != nil || !strings.Contains(w.String(), `"model":"claude-3"`) {
		t.Errorf("empty Model: %v %s", err, w.String())
	}
}

// TestStreamHooks: FirstByte runs once before the first write, Flush
// after each event, and neither runs for a stream with no event.
func TestStreamHooks(t *testing.T) {
	b := open(t, ir.DialectAnthropicMessages, ir.DialectOpenAIChat)
	r := &recorder{}
	if _, err := b.Stream(r, bytes.NewReader(fixture(t, "fixtures/openai-chat.stream.sse")), StreamOptions{Model: "gpt", FirstByte: r.firstByte, Flush: r.flush}); err != nil {
		t.Fatal(err)
	}
	if r.events[0] != "first" || strings.Count(strings.Join(r.events, " "), "first") != 1 {
		t.Errorf("FirstByte did not run exactly once before the first write: %v", r.events)
	}
	if !strings.HasPrefix(r.String(), "event: message_start") || !strings.Contains(r.String(), `"model":"gpt"`) {
		t.Errorf("anthropic stream: %s", r.String())
	}
	// Every event is followed by a flush, and the last hook is a flush.
	for i, ev := range r.events {
		if ev == "write" && (i+1 >= len(r.events) || r.events[i+1] != "flush") {
			// An event may take several writes; only the run's end must
			// be followed by a flush.
			if i+1 < len(r.events) && r.events[i+1] == "write" {
				continue
			}
			t.Errorf("write %d not followed by a flush: %v", i, r.events)
		}
	}
	if r.events[len(r.events)-1] != "flush" || r.flushed == 0 {
		t.Errorf("hooks %v", r.events)
	}
	// No event: no FirstByte, no Flush, nothing written. The stub
	// backend's decoder ends at once; a codec's may synthesize events for
	// an empty stream.
	empty := &recorder{}
	none := New(frontendFor(ir.DialectAnthropicMessages), stubBackend{})
	if usage, err := none.Stream(empty, strings.NewReader(""), StreamOptions{FirstByte: empty.firstByte, Flush: empty.flush}); err != nil || usage != (Usage{}) || len(empty.events) != 0 {
		t.Errorf("empty stream: %v %+v %v", err, usage, empty.events)
	}
	// FirstByte's error is WriteFailed and nothing is written.
	failing := &recorder{}
	_, err := b.Stream(failing, bytes.NewReader(fixture(t, "fixtures/openai-chat.stream.sse")), StreamOptions{FirstByte: func() error { return errors.New("gone") }})
	var e *Error
	if !errors.As(err, &e) || e.Code != WriteFailed || failing.Len() != 0 {
		t.Errorf("FirstByte error: %v, wrote %q", err, failing.String())
	}
	// A write that fails is WriteFailed with the usage so far and no
	// frame.
	cut := &recorder{failAt: 2}
	usage, err := b.Stream(cut, bytes.NewReader(fixture(t, "fixtures/openai-chat.stream.sse")), StreamOptions{Fail: func(error) (Failure, bool) { return Failure{Code: "x"}, true }})
	if !errors.As(err, &e) || e.Code != WriteFailed || strings.Contains(cut.String(), "event: error") {
		t.Errorf("write failure: %v %s", err, cut.String())
	}
	_ = usage
}

// TestStreamUsageIsTheLastValue: input on message_start and output on
// message_delta, each member's last value winning, on every backend.
func TestStreamUsageIsTheLastValue(t *testing.T) {
	cases := []struct {
		be   ir.Dialect
		want Usage
	}{
		{ir.DialectAnthropicMessages, Usage{Input: 11, Output: 6, CachedInput: 2}},
		{ir.DialectOpenAIChat, Usage{Input: 9, Output: 1}},
		{ir.DialectOpenAIResponses, Usage{Input: 5, Output: 7}},
		{ir.DialectLux, Usage{Input: 4, Output: 9, Reasoning: 2}},
	}
	for _, c := range cases {
		b := open(t, ir.DialectLux, c.be)
		var w bytes.Buffer
		usage, err := b.Stream(&w, bytes.NewReader(fixture(t, "fixtures/"+string(c.be)+".stream.sse")), StreamOptions{Model: "m"})
		if err != nil || usage != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.be, usage, err, c.want)
		}
	}
}

// stubBackend is a backend that can write nothing and whose stream
// carries no event, so the encode failures and the hooks of a stream
// with nothing in it can be observed; the codecs refuse very little.
type stubBackend struct{}

func (stubBackend) Name() ir.Dialect { return "stub" }
func (stubBackend) EncodeRequest(*ir.Request) ([]byte, error) {
	return nil, errors.New("stub cannot write")
}
func (stubBackend) DecodeResponse([]byte) (*ir.Response, error)       { return &ir.Response{}, nil }
func (stubBackend) NewEventDecoder(io.Reader) llmdialect.EventDecoder { return eofDecoder{} }

type eofDecoder struct{}

func (eofDecoder) Next() (ir.Event, error) { return ir.Event{}, io.EOF }

// stubFrontend is a frontend that can write nothing and belongs to no
// wire.
type stubFrontend struct{}

func (stubFrontend) Name() ir.Dialect                          { return "stub" }
func (stubFrontend) DecodeRequest([]byte) (*ir.Request, error) { return &ir.Request{}, nil }
func (stubFrontend) EncodeResponse(*ir.Response) ([]byte, error) {
	return nil, errors.New("stub cannot write")
}
func (stubFrontend) NewEventEncoder(io.Writer) llmdialect.EventEncoder { return nopEncoder{} }

type nopEncoder struct{}

func (nopEncoder) Encode(ir.Event) error { return nil }

// TestEncodeFailures: a request the backend cannot write is
// EncodeRequest, a response the frontend cannot write is EncodeResponse,
// and a frontend of no wire writes no error frame.
func TestEncodeFailures(t *testing.T) {
	var e *Error
	_, _, err := New(frontendFor(ir.DialectLux), stubBackend{}).Request(fixture(t, "fixtures/lux.request.json"), RequestOptions{})
	if !errors.As(err, &e) || e.Code != EncodeRequest || e.Scope != llmdialect.ScopeNone || e.Detail != "stub cannot write" {
		t.Errorf("EncodeRequest: %+v", err)
	}
	_, _, _, err = New(stubFrontend{}, backendFor(ir.DialectLux, Options{})).Response(fixture(t, "fixtures/lux.response.json"), ResponseOptions{})
	if !errors.As(err, &e) || e.Code != EncodeResponse {
		t.Errorf("EncodeResponse: %+v", err)
	}
	// A failure past the first event on a frontend of no wire: Fail is
	// asked and no frame is written.
	first := strings.SplitAfter(string(fixture(t, "fixtures/lux.stream.sse")), "\n\n")[0]
	var w bytes.Buffer
	asked := false
	_, err = New(stubFrontend{}, backendFor(ir.DialectLux, Options{})).Stream(&w, &errReader{r: strings.NewReader(first), err: errors.New("cut")}, StreamOptions{Fail: func(error) (Failure, bool) { asked = true; return Failure{Code: "x"}, true }})
	if !errors.As(err, &e) || e.Code != StreamFailed || !asked || w.Len() != 0 {
		t.Errorf("no wire: %v asked %v wrote %q", err, asked, w.String())
	}
}

// errReader yields its bytes and then an error that is not io.EOF, the
// way a connection cut mid-stream reads.
type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if errors.Is(err, io.EOF) {
		return n, e.err
	}
	return n, err
}

// TestStreamErrorFrame: a failure past the first event writes the
// frontend wire's frame through Fail, nothing when Fail says no or is
// nil, and nothing before the first event; WireGoogle has no frame.
func TestStreamErrorFrame(t *testing.T) {
	first := strings.SplitAfter(string(fixture(t, "fixtures/anthropic-messages.stream.sse")), "\n\n")[0]
	cut := func() io.Reader { return &errReader{r: strings.NewReader(first), err: errors.New("connection reset")} }
	failure := Failure{Code: "upstream_error", Message: "The provider returned an error.", Detail: "cut", RequestID: "req_1", Status: 502, Domain: "lux"}
	fail := func(err error) (Failure, bool) {
		var e *Error
		if !errors.As(err, &e) || e.Code != StreamFailed {
			t.Errorf("Fail got %v", err)
		}
		return failure, true
	}
	cases := []struct {
		wire  Wire
		fe    ir.Dialect
		frame string
	}{
		{WireOpenAI, ir.DialectOpenAIChat, string(fixture(t, "frames/openai.golden.sse"))},
		{WireAnthropic, ir.DialectAnthropicMessages, string(fixture(t, "frames/anthropic.golden.sse"))},
		{WireLux, ir.DialectLux, string(fixture(t, "frames/lux.golden.sse"))},
		{WireGoogle, "", ""},
	}
	for _, c := range cases {
		if c.wire == WireGoogle {
			if ErrorFrame(c.wire, failure) != nil {
				t.Error("google has an error frame")
			}
			continue
		}
		b := open(t, c.fe, ir.DialectAnthropicMessages)
		r := &recorder{}
		usage, err := b.Stream(r, cut(), StreamOptions{Model: "m", Flush: r.flush, Fail: fail})
		var e *Error
		if !errors.As(err, &e) || e.Code != StreamFailed || !strings.Contains(e.Detail, "connection reset") {
			t.Errorf("%s: %v", c.wire, err)
		}
		if !strings.HasSuffix(r.String(), c.frame) || r.events[len(r.events)-1] != "flush" {
			t.Errorf("%s: body %q lacks the frame %q or the flush", c.wire, r.String(), c.frame)
		}
		if usage != (Usage{Input: 11, Output: 1, CachedInput: 2}) {
			t.Errorf("%s: usage so far %+v", c.wire, usage)
		}
		// Fail nil, and Fail false, write no frame.
		for _, o := range []StreamOptions{{}, {Fail: func(error) (Failure, bool) { return Failure{}, false }}} {
			var w bytes.Buffer
			if _, err := b.Stream(&w, cut(), o); err == nil || strings.Contains(w.String(), "error") {
				t.Errorf("%s: a frame with no Fail: %s", c.wire, w.String())
			}
		}
	}
	// Before the first event nothing is written: the upstream's own error
	// frame as the first thing is the codec's error and no frame.
	b := open(t, ir.DialectOpenAIChat, ir.DialectAnthropicMessages)
	var w bytes.Buffer
	usage, err := b.Stream(&w, strings.NewReader("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}\n\n"), StreamOptions{Fail: fail})
	var e *Error
	if !errors.As(err, &e) || e.Code != StreamFailed || w.Len() != 0 || usage != (Usage{}) {
		t.Errorf("first-event failure: %v, wrote %q", err, w.String())
	}
	// The same frame after message_start ends the stream with the frame.
	w.Reset()
	_, err = b.Stream(&w, strings.NewReader(first+"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}\n\n"), StreamOptions{Fail: fail})
	if !errors.As(err, &e) || e.Code != StreamFailed || !strings.HasSuffix(w.String(), string(fixture(t, "frames/openai.golden.sse"))) {
		t.Errorf("upstream error frame: %v %s", err, w.String())
	}
}

// TestStreamResponseReemits: one JSON body becomes the frontend's full
// event sequence with the usage on message_delta, and an undecodable
// body is DecodeResponse.
func TestStreamResponseReemits(t *testing.T) {
	b := open(t, ir.DialectLux, ir.DialectAnthropicMessages)
	r := &recorder{}
	usage, err := b.StreamResponse(r, fixture(t, "fixtures/anthropic-messages.response.tools.json"), StreamOptions{Model: "claude", FirstByte: r.firstByte, Flush: r.flush})
	if err != nil {
		t.Fatal(err)
	}
	body := r.String()
	for _, want := range []string{"event: message_start", `"model":"claude"`, "event: thinking_delta", "event: signature_delta", "event: text_delta", "event: args_delta", `"stop_reason":"tool_use"`, "event: message_stop"} {
		if !strings.Contains(body, want) {
			t.Errorf("events lack %q:\n%s", want, body)
		}
	}
	if usage != (Usage{Input: 2, Output: 3}) || r.events[0] != "first" {
		t.Errorf("usage %+v events %v", usage, r.events)
	}
	_, err = b.StreamResponse(r, []byte(`{`), StreamOptions{})
	var e *Error
	if !errors.As(err, &e) || e.Code != DecodeResponse {
		t.Errorf("undecodable: %v", err)
	}
}

// TestResponseEvents re-emits a whole response as the event grammar,
// one block each of text, thinking with a signature, a tool use, and a
// block no dialect streams.
func TestResponseEvents(t *testing.T) {
	resp := &ir.Response{
		ID: "r", Model: "m", StopReason: ir.StopToolUse,
		Usage: ir.Usage{InputTokens: 1, OutputTokens: 2},
		Blocks: []ir.Block{
			{Type: ir.BlockText, Text: "hi"},
			{Type: ir.BlockThinking, Text: "hm", Signature: "sig"},
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t", Name: "f", Args: json.RawMessage(`{"a":1}`)}},
			{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t2", Name: "g"}},
			{Type: ir.BlockRedactedThinking, Redacted: "x"},
		},
	}
	events := responseEvents(resp)
	var types []string
	for _, ev := range events {
		types = append(types, string(ev.Type))
	}
	want := "message_start block_start text_delta block_stop block_start thinking_delta signature_delta block_stop block_start args_delta block_stop block_start block_stop block_start block_stop message_delta message_stop"
	if got := strings.Join(types, " "); got != want {
		t.Errorf("events\n got %s\nwant %s", got, want)
	}
	last := events[len(events)-2]
	if last.Usage == nil || *last.Usage != resp.Usage || last.StopReason != ir.StopToolUse {
		t.Errorf("message_delta %+v", last)
	}
	if events[0].ID != "r" || events[0].Model != "m" {
		t.Errorf("message_start %+v", events[0])
	}
}

// TestTranslationGoldens is the byte-equality proof: for every dialect
// pair, the request leg with the upstream name written, the response leg
// with the caller's name written back, the stream leg event by event,
// and a whole response re-emitted as events, each equal to the bytes
// the gateway's own legs produced over the same fixtures, with the same
// loss report and the same usage.
func TestTranslationGoldens(t *testing.T) {
	var wantUsage = func(t *testing.T, rel string) Usage {
		t.Helper()
		var u Usage
		if err := json.Unmarshal(fixture(t, rel), &u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	for _, fe := range codecDialects {
		for _, be := range codecDialects {
			pair := string(fe) + "-" + string(be)
			b := open(t, fe, be)
			for _, variant := range []string{"", ".stream"} {
				body := fixtureIfPresent(t, "fixtures/"+string(fe)+".request"+variant+".json")
				if body == nil {
					continue
				}
				out, loss, err := b.Request(body, RequestOptions{Model: "upstream-model", Loss: []string{"header.anthropic-beta"}})
				if err != nil {
					t.Errorf("%s request%s: %v", pair, variant, err)
					continue
				}
				if want := fixture(t, "translate/"+pair+".request"+variant+".json"); !bytes.Equal(out, want) {
					t.Errorf("%s request%s:\n got %s\nwant %s", pair, variant, out, want)
				}
				if want := string(fixture(t, "translate/"+pair+".request"+variant+".loss")); strings.Join(loss, ",") != want {
					t.Errorf("%s request%s loss: %q, want %q", pair, variant, strings.Join(loss, ","), want)
				}
			}
			resp := fixture(t, "fixtures/"+string(be)+".response.json")
			out, _, usage, err := b.Response(resp, ResponseOptions{Model: "shown-model"})
			if err != nil {
				t.Errorf("%s response: %v", pair, err)
			} else if want := fixture(t, "translate/"+pair+".response.json"); !bytes.Equal(out, want) {
				t.Errorf("%s response:\n got %s\nwant %s", pair, out, want)
			}
			if want := wantUsage(t, "translate/"+pair+".response.usage"); usage != want {
				t.Errorf("%s response usage %+v, want %+v", pair, usage, want)
			}
			var w bytes.Buffer
			usage, err = b.Stream(&w, bytes.NewReader(fixture(t, "fixtures/"+string(be)+".stream.sse")), StreamOptions{Model: "shown-model"})
			if err != nil {
				t.Errorf("%s stream: %v", pair, err)
			} else if want := fixture(t, "translate/"+pair+".stream.sse"); !bytes.Equal(w.Bytes(), want) {
				t.Errorf("%s stream:\n got %s\nwant %s", pair, w.Bytes(), want)
			}
			if want := wantUsage(t, "translate/"+pair+".stream.usage"); usage != want {
				t.Errorf("%s stream usage %+v, want %+v", pair, usage, want)
			}
			w.Reset()
			usage, err = b.StreamResponse(&w, resp, StreamOptions{Model: "shown-model"})
			if err != nil {
				t.Errorf("%s events: %v", pair, err)
			} else if want := fixture(t, "translate/"+pair+".events.sse"); !bytes.Equal(w.Bytes(), want) {
				t.Errorf("%s events:\n got %s\nwant %s", pair, w.Bytes(), want)
			}
			if want := wantUsage(t, "translate/"+pair+".events.usage"); usage != want {
				t.Errorf("%s events usage %+v, want %+v", pair, usage, want)
			}
		}
	}
}

// TestLuxRoundTripIsLossless: the lux dialect is the IR on the wire, so
// a request through it and back loses nothing, and a body translated
// into lux and out again is the request the caller sent.
func TestLuxRoundTripIsLossless(t *testing.T) {
	body := fixture(t, "fixtures/lux.request.json")
	for _, be := range codecDialects {
		b := open(t, ir.DialectLux, be)
		if _, loss, err := b.Request(body, RequestOptions{Model: "up"}); err != nil || loss != nil {
			t.Errorf("lux -> %s: loss %v err %v", be, loss, err)
		}
	}
	// openai-chat -> lux -> openai-chat keeps the model and the message.
	into := open(t, ir.DialectOpenAIChat, ir.DialectLux)
	luxBody, loss, err := into.Request(fixture(t, "fixtures/openai-chat.request.json"), RequestOptions{})
	if err != nil || loss != nil {
		t.Fatal(err, loss)
	}
	back := open(t, ir.DialectLux, ir.DialectOpenAIChat)
	out, loss, err := back.Request(luxBody, RequestOptions{})
	if err != nil || loss != nil {
		t.Fatal(err, loss)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["model"] != "claude" || len(got["messages"].([]any)) != 1 {
		t.Errorf("round trip %s", out)
	}
	// The lux response and stream through a lux pair are the fixtures'
	// own bytes semantically: the same usage on both legs.
	same := open(t, ir.DialectLux, ir.DialectLux)
	_, _, usage, err := same.Response(fixture(t, "fixtures/lux.response.json"), ResponseOptions{})
	if err != nil || usage != (Usage{Input: 7, Output: 1, Reasoning: 1}) {
		t.Errorf("lux response %+v %v", usage, err)
	}
}

// pairOf selects one of the sixteen pairs from a fuzz byte.
func pairOf(n uint8) (ir.Dialect, ir.Dialect) {
	return codecDialects[int(n)%4], codecDialects[int(n)/4%4]
}

func FuzzRequest(f *testing.F) {
	f.Add(uint8(2), []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	f.Add(uint8(8), []byte(`{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`))
	f.Add(uint8(15), []byte(`{"model":"m","messages":[{"role":"user","blocks":[{"type":"text","text":"hi"}]}]}`))
	f.Add(uint8(0), []byte(`{`))
	f.Fuzz(func(t *testing.T, pair uint8, body []byte) {
		fe, be := pairOf(pair)
		b, _ := Open(fe, be, Options{})
		out, loss, err := b.Request(body, RequestOptions{Model: "up", Loss: []string{"x"}})
		checkError(t, err)
		if err == nil && (!json.Valid(out) || len(loss) == 0) {
			t.Fatalf("a success with invalid JSON or no loss entry: %s %v", out, loss)
		}
	})
}

func FuzzResponse(f *testing.F) {
	f.Add(uint8(0), []byte(`{"id":"x","choices":[{"message":{"content":"y"}}]}`))
	f.Add(uint8(9), []byte(`{"id":"m","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}]}`))
	f.Add(uint8(15), []byte(`{"id":"l","blocks":[{"type":"text","text":"hi"}],"stop_reason":"end_turn"}`))
	f.Fuzz(func(t *testing.T, pair uint8, body []byte) {
		fe, be := pairOf(pair)
		b, _ := Open(fe, be, Options{})
		out, _, _, err := b.Response(body, ResponseOptions{Model: "shown"})
		checkError(t, err)
		if err == nil && !json.Valid(out) {
			t.Fatalf("a success with invalid JSON: %s", out)
		}
	})
}

func FuzzStream(f *testing.F) {
	f.Add(uint8(2), []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"x\",\"usage\":{\"input_tokens\":1}}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
	f.Add(uint8(4), []byte("data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\ndata: [DONE]\n\n"))
	f.Add(uint8(15), []byte("event: message_start\ndata: {\"type\":\"message_start\",\"id\":\"l\",\"model\":\"m\"}\n\n"))
	f.Add(uint8(0), []byte("data: {\n\n"))
	f.Fuzz(func(t *testing.T, pair uint8, stream []byte) {
		fe, be := pairOf(pair)
		b, _ := Open(fe, be, Options{})
		var w bytes.Buffer
		_, err := b.Stream(&w, bytes.NewReader(stream), StreamOptions{Model: "m", Fail: func(error) (Failure, bool) { return Failure{Code: "c", Message: "m"}, true }})
		checkError(t, err)
		w.Reset()
		_, err = b.StreamResponse(&w, stream, StreamOptions{Model: "m"})
		checkError(t, err)
	})
}
