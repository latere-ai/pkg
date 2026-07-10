package llmdialect

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/anthropic"
	"latere.ai/x/pkg/llmdialect/openaichat"
)

// Compile-time interface satisfaction for the shipped codecs.
var (
	_ Frontend = (*anthropic.Frontend)(nil)
	_ Backend  = (*openaichat.Backend)(nil)
)

func newTranslator() *Translator {
	return &Translator{
		Frontend: anthropic.NewFrontend(),
		Backend:  openaichat.NewBackend(openaichat.BackendOptions{}),
	}
}

// TestRequestAnthropicToOpenAI is the headline path: a Claude-Code-like
// Messages request driving an openai-compat backend.
func TestRequestAnthropicToOpenAI(t *testing.T) {
	in := `{
		"model": "qwen3-32b",
		"max_tokens": 8192,
		"stream": true,
		"system": [{"type": "text", "text": "You are Claude Code", "cache_control": {"type": "ephemeral"}}],
		"messages": [
			{"role": "user", "content": "list files"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "tu_1", "name": "bash", "input": {"cmd": "ls"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "tu_1", "content": "a.txt"}
			]}
		],
		"tools": [{"name": "bash", "description": "run", "input_schema": {"type": "object"}}]
	}`
	out, req, err := newTranslator().Request([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if !req.Stream || req.Model != "qwen3-32b" {
		t.Fatalf("decoded shape wrong: %+v", req)
	}
	if want := []string{"cache_control"}; !reflect.DeepEqual(req.Loss.Fields(), want) {
		t.Fatalf("loss = %v want %v", req.Loss.Fields(), want)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	msgs := got["messages"].([]any)
	roles := make([]string, len(msgs))
	for i, m := range msgs {
		roles[i] = m.(map[string]any)["role"].(string)
	}
	if !reflect.DeepEqual(roles, []string{"system", "user", "assistant", "tool"}) {
		t.Fatalf("roles = %v", roles)
	}
	if got["stream"] != true || got["max_tokens"].(float64) != 8192 {
		t.Fatalf("params wrong: %v", got)
	}
	if _, ok := got["stream_options"]; !ok {
		t.Fatal("stream_options.include_usage must be injected")
	}
}

func TestRequestDecodeError(t *testing.T) {
	if _, _, err := newTranslator().Request([]byte(`{`)); err == nil {
		t.Fatal("want decode error")
	}
	// Decodes fine but cannot encode: tool_use block in a user turn.
	bad := `{"model":"m","messages":[{"role":"user","content":[{"type":"tool_use","id":"t","name":"f","input":{}}]}]}`
	if _, _, err := newTranslator().Request([]byte(bad)); err == nil {
		t.Fatal("want encode error")
	}
}

func TestResponseOpenAIToAnthropic(t *testing.T) {
	in := `{
		"id": "chatcmpl-9", "model": "qwen3-32b",
		"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
			"content": null,
			"tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "bash", "arguments": "{\"cmd\":\"ls\"}"}}]
		}}],
		"usage": {"prompt_tokens": 42, "completion_tokens": 7}
	}`
	out, err := newTranslator().Response([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["type"] != "message" || got["stop_reason"] != "tool_use" || got["id"] != "chatcmpl-9" {
		t.Fatalf("envelope wrong: %v", got)
	}
	blk := got["content"].([]any)[0].(map[string]any)
	if blk["type"] != "tool_use" || blk["name"] != "bash" ||
		!reflect.DeepEqual(blk["input"], map[string]any{"cmd": "ls"}) {
		t.Fatalf("tool block wrong: %v", blk)
	}
	usage := got["usage"].(map[string]any)
	if usage["input_tokens"].(float64) != 42 || usage["output_tokens"].(float64) != 7 {
		t.Fatalf("usage wrong: %v", usage)
	}
}

func TestResponseDecodeError(t *testing.T) {
	if _, err := newTranslator().Response([]byte(`{"choices":[]}`)); err == nil {
		t.Fatal("want error")
	}
}

func TestStreamOpenAIToAnthropic(t *testing.T) {
	src := strings.NewReader(
		"data: {\"id\":\"c1\",\"model\":\"qwen3\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hel\"}}]}\n\n" +
			"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n" +
			"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
			"data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":2}}\n\n" +
			"data: [DONE]\n\n")

	// httptest.ResponseRecorder implements http.Flusher, covering the
	// per-event flush path a real handler exercises.
	rec := httptest.NewRecorder()
	if err := newTranslator().Stream(rec, src); err != nil {
		t.Fatal(err)
	}
	if !rec.Flushed {
		t.Fatal("stream must flush per event")
	}
	body := rec.Body.String()

	var names []string
	var payloads []map[string]any
	for _, frame := range strings.Split(strings.TrimSpace(body), "\n\n") {
		lines := strings.SplitN(frame, "\n", 2)
		names = append(names, strings.TrimPrefix(lines[0], "event: "))
		var p map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "data: ")), &p); err != nil {
			t.Fatalf("bad frame %q: %v", frame, err)
		}
		payloads = append(payloads, p)
	}
	want := []string{"message_start", "ping", "content_block_start", "content_block_delta",
		"content_block_delta", "content_block_stop", "message_delta", "message_stop"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("events = %v\nwant %v", names, want)
	}
	if payloads[3]["delta"].(map[string]any)["text"] != "hel" {
		t.Fatalf("first delta wrong: %v", payloads[3])
	}
	md := payloads[6]
	if md["delta"].(map[string]any)["stop_reason"] != "end_turn" ||
		md["usage"].(map[string]any)["input_tokens"].(float64) != 12 {
		t.Fatalf("message_delta wrong: %v", md)
	}
}

func TestStreamUpstreamError(t *testing.T) {
	src := strings.NewReader("data: {\"error\":{\"message\":\"boom\",\"type\":\"server_error\"}}\n\n")
	var buf bytes.Buffer
	if err := newTranslator().Stream(&buf, src); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want upstream error, got %v", err)
	}
}

func TestStreamEncodeError(t *testing.T) {
	src := strings.NewReader("data: {\"id\":\"c1\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\ndata: [DONE]\n\n")
	if err := newTranslator().Stream(failWriter{}, src); err == nil {
		t.Fatal("want write error")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) {
	return 0, errWrite
}

var errWrite = &writeError{}

type writeError struct{}

func (*writeError) Error() string { return "sink closed" }

// TestRoundTripConversation drives a full agentic turn shape through
// both directions to guard against drift between the codecs: the
// harness sends history containing prior tool use, the backend answers
// with text.
func TestRoundTripConversation(t *testing.T) {
	reqBody := `{
		"model": "qwen3", "max_tokens": 100,
		"messages": [
			{"role": "user", "content": "hi"},
			{"role": "assistant", "content": [{"type": "text", "text": "hello"}]},
			{"role": "user", "content": "how are you?"}
		]
	}`
	out, _, err := newTranslator().Request([]byte(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	var chat map[string]any
	_ = json.Unmarshal(out, &chat)
	if len(chat["messages"].([]any)) != 3 {
		t.Fatalf("history length wrong: %v", chat["messages"])
	}

	respBody := `{"id":"r1","model":"qwen3","choices":[{"finish_reason":"stop","message":{"content":"good"}}],
		"usage":{"prompt_tokens":9,"completion_tokens":1}}`
	back, err := newTranslator().Response([]byte(respBody))
	if err != nil {
		t.Fatal(err)
	}
	var msg map[string]any
	_ = json.Unmarshal(back, &msg)
	if msg["content"].([]any)[0].(map[string]any)["text"] != "good" || msg["stop_reason"] != "end_turn" {
		t.Fatalf("round trip wrong: %v", msg)
	}
}
