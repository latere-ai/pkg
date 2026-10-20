// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package llmdirect

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"latere.ai/x/sdk-go/llm"
)

// model is the interface a program declares to take either client.
type model interface {
	Generate(ctx context.Context, req *llm.Request) (*llm.Result, error)
	Stream(ctx context.Context, req *llm.Request) (*llm.Stream, error)
}

var (
	_ model = (*Client)(nil)
	_ model = (*llm.Client)(nil)
)

func testServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

type staticTokens struct {
	token string
	err   error
}

func (s staticTokens) Token(context.Context) (string, error) { return s.token, s.err }

func ask(text string) *llm.Request {
	return &llm.Request{Model: "m", Messages: []llm.Message{llm.UserText(text)}}
}

const anthropicSSE = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8","content":[],"usage":{"input_tokens":5,"output_tokens":0}}}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}` + "\n\n" +
	"event: content_block_stop\n" +
	`data: {"type":"content_block_stop","index":0}` + "\n\n" +
	"event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}` + "\n\n" +
	"event: message_stop\n" +
	`data: {"type":"message_stop"}` + "\n\n"

const anthropicEmptyAnswer = `{"id":"m","type":"message","role":"assistant","model":"m","content":[],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`

func TestAnthropicGenerate(t *testing.T) {
	var gotPath, gotKey, gotVersion string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotKey, gotVersion = r.URL.Path, r.Header.Get("x-api-key"), r.Header.Get("anthropic-version")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8",`+
			`"content":[{"type":"text","text":"pong"}],"stop_reason":"end_turn","stop_sequence":null,`+
			`"usage":{"input_tokens":3,"output_tokens":1}}`)
	})
	c, err := New(ProviderAnthropic, "sk-ant-1", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Generate(t.Context(), &llm.Request{Model: "claude-opus-4-8", Messages: []llm.Message{llm.UserText("ping")}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/messages" || gotKey != "sk-ant-1" || gotVersion != anthropicVersion {
		t.Fatalf("upstream call: path %q, key %q, version %q", gotPath, gotKey, gotVersion)
	}
	if res.Text() != "pong" || res.StopReason != llm.StopEndTurn || res.Usage.InputTokens != 3 {
		t.Fatalf("result: %#v", res)
	}
	if len(res.Loss) != 0 {
		t.Fatalf("anthropic represents this request fully, loss = %v", res.Loss)
	}
}

func TestAnthropicStream(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, anthropicSSE)
	})
	c, err := New(ProviderAnthropic, "sk", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Stream(t.Context(), &llm.Request{Model: "claude-opus-4-8", Messages: []llm.Message{llm.UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	}()
	var text strings.Builder
	var sawStop bool
	for ev, err := range st.Events() {
		if err != nil {
			t.Fatal(err)
		}
		switch ev.Type {
		case llm.EventTextDelta:
			text.WriteString(ev.Delta)
		case llm.EventMessageStop:
			sawStop = true
		}
	}
	if text.String() != "hi" || !sawStop {
		t.Fatalf("stream: text %q, stop %v", text.String(), sawStop)
	}
}

// Stopping the loop early closes the provider's connection.
func TestStreamStopsWithTheLoop(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, anthropicSSE)
	})
	c, err := New(ProviderAnthropic, "sk", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Stream(t.Context(), ask("x"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, err := range st.Events() {
		if err != nil {
			t.Fatal(err)
		}
		n++
		break
	}
	if n != 1 {
		t.Fatalf("read %d events", n)
	}
	if err := st.Close(); err != nil {
		t.Errorf("Close after the loop: %v", err)
	}
}

func TestStreamWithABrokenEvent(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\n\n")
	})
	c, err := New(ProviderAnthropic, "sk", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Stream(t.Context(), ask("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var got error
	for _, err := range st.Events() {
		got = err
	}
	if got == nil || !strings.HasPrefix(got.Error(), "llmdirect: ") {
		t.Errorf("err = %v, want the decoder's error", got)
	}
}

func TestAnthropicOAuth(t *testing.T) {
	var gotAuth, gotBeta, gotKey string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotBeta, gotKey = r.Header.Get("Authorization"), r.Header.Get("anthropic-beta"), r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, anthropicEmptyAnswer)
	})
	c, err := New(ProviderAnthropic, "oauth-tok", srv.URL, WithOAuthToken())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Generate(t.Context(), ask("x")); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer oauth-tok" || gotBeta != anthropicBetaOAuth || gotKey != "" {
		t.Fatalf("oauth headers: auth %q, beta %q, key %q", gotAuth, gotBeta, gotKey)
	}
}

const chatSSE = "data: {\"id\":\"cc1\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"}}]}\n\n" +
	"data: {\"id\":\"cc1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
	"data: {\"id\":\"cc1\",\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":1}}\n\n" +
	"data: [DONE]\n\n"

func TestOpenAIChatStreamReportsLoss(t *testing.T) {
	var gotPath, gotAuth string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, chatSSE)
	})
	c, err := New(ProviderOpenAI, "sk-oa", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// top_k has no place in the OpenAI format: it is named in the loss
	// report rather than dropped silently.
	topK := int64(40)
	st, err := c.Stream(t.Context(), &llm.Request{Model: "gpt-4o", TopK: &topK, Messages: []llm.Message{llm.UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if gotPath != "/v1/chat/completions" || gotAuth != "Bearer sk-oa" {
		t.Fatalf("upstream call: path %q, auth %q", gotPath, gotAuth)
	}
	if l := st.Loss(); !strings.Contains(strings.Join(l, ","), "top_k") {
		t.Fatalf("loss = %v, want top_k", l)
	}
	var text strings.Builder
	for ev, err := range st.Events() {
		if err != nil {
			t.Fatal(err)
		}
		if ev.Type == llm.EventTextDelta {
			text.WriteString(ev.Delta)
		}
	}
	if text.String() != "ok" {
		t.Fatalf("text = %q", text.String())
	}
}

func TestOpenAIReasoningModelsUseResponses(t *testing.T) {
	var gotPath string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// A minimal Responses body the openairesp backend can decode.
		_, _ = io.WriteString(w, `{"id":"resp_1","model":"gpt-5.5","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"deep"}]}],"usage":{"input_tokens":2,"output_tokens":1}}`)
	})
	c, err := New(ProviderOpenAI, "sk", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Generate(t.Context(), &llm.Request{Model: "gpt-5.5", Messages: []llm.Message{llm.UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/responses" {
		t.Fatalf("a reasoning model goes to the Responses API, got %q", gotPath)
	}
	if res.Text() != "deep" {
		t.Fatalf("result: %#v", res)
	}
}

func TestIsOpenAIResponsesModel(t *testing.T) {
	for model, want := range map[string]bool{
		"gpt-5.5":          true,
		"openrouter/gpt-5": true,
		"o1-mini":          true,
		"o3":               true,
		"o4-mini":          true,
		"gpt-4o":           false,
		"gpt-4.1":          false,
	} {
		if got := isOpenAIResponsesModel(model); got != want {
			t.Errorf("isOpenAIResponsesModel(%q) = %v, want %v", model, got, want)
		}
	}
}

// Every provider but Anthropic speaks Chat Completions; Gemini and Zhipu
// serve it under paths of their own, and /v1/chat/completions is a 404 on
// Zhipu's API.
func TestChatCompletionsPaths(t *testing.T) {
	for _, tc := range []struct {
		provider Provider
		model    string
		wantPath string
	}{
		{ProviderGemini, "gemini-2.5-pro", "/v1beta/openai/chat/completions"},
		{ProviderOpenRouter, "meta/llama-4", "/v1/chat/completions"},
		{ProviderMoonshot, "kimi-k2.6", "/v1/chat/completions"},
		{ProviderXai, "grok-4.5", "/v1/chat/completions"},
		{ProviderZhipu, "glm-4.6", "/api/paas/v4/chat/completions"},
	} {
		t.Run(string(tc.provider), func(t *testing.T) {
			var gotPath, gotAuth string
			srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"cc1","model":"`+tc.model+`","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
			})
			c, err := New(tc.provider, "sek", srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Generate(t.Context(), &llm.Request{Model: tc.model, Messages: []llm.Message{llm.UserText("x")}}); err != nil {
				t.Fatal(err)
			}
			if gotPath != tc.wantPath || gotAuth != "Bearer sek" {
				t.Fatalf("path %q, auth %q, want %q and a bearer", gotPath, gotAuth, tc.wantPath)
			}
		})
	}
}

func TestOllamaWithNoCredential(t *testing.T) {
	var gotAuth string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"cc1","model":"llama3.1","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"local"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	})
	c, err := New(ProviderOllama, "", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Generate(t.Context(), &llm.Request{Model: "llama3.1", Messages: []llm.Message{llm.UserText("x")}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("a call with no credential sends none, got %q", gotAuth)
	}
}

func TestTokenSource(t *testing.T) {
	var gotAuth string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, anthropicEmptyAnswer)
	})
	c, err := New(ProviderAnthropic, "", srv.URL, WithTokenSource(staticTokens{token: "jwt-9"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Generate(t.Context(), ask("x")); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer jwt-9" {
		t.Fatalf("auth = %q", gotAuth)
	}
	failing, err := New(ProviderAnthropic, "", srv.URL, WithTokenSource(staticTokens{err: errors.New("no token")}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Generate(t.Context(), ask("x")); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("err = %v, want the token source's", err)
	}
}

func TestNewDefaults(t *testing.T) {
	for p := range providerDefaults {
		c, err := New(p, "k", "")
		if err != nil {
			t.Errorf("New(%s): %v", p, err)
			continue
		}
		if c.baseURL != providerDefaults[p] {
			t.Errorf("New(%s) base = %q", p, c.baseURL)
		}
	}
	for _, p := range []Provider{
		ProviderAnthropic, ProviderOpenAI, ProviderGemini, ProviderOpenRouter,
		ProviderOllama, ProviderMoonshot, ProviderXai, ProviderZhipu,
	} {
		if _, ok := providerDefaults[p]; !ok {
			t.Errorf("%s has no default endpoint", p)
		}
	}
	c, err := New(ProviderAnthropic, "k1", "https://proxy.example/")
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://proxy.example" {
		t.Errorf("base = %q, want the trailing slash trimmed", c.baseURL)
	}
	if c.hc == nil || c.hc.Transport == nil {
		t.Errorf("default client %+v carries no tracing transport", c.hc)
	}
	hc := &http.Client{}
	c, err = New(ProviderOpenAI, "positional", "", WithAPIKey("via-option"), WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	if c.apiKey != "via-option" || c.hc != hc {
		t.Errorf("options: key %q, client %p", c.apiKey, c.hc)
	}
	if _, err := New(Provider("cohere"), "k", ""); err == nil {
		t.Error("an unknown provider was accepted")
	}
}

func TestProviderRefusal(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"bad key","request_id":"req_1"}}`)
	})
	c, err := New(ProviderAnthropic, "bad", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Generate(t.Context(), ask("x"))
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != http.StatusUnauthorized || pe.Code != "authentication_error" || pe.RequestID != "req_1" {
		t.Fatalf("err = %v", err)
	}
	if want := "llmdirect: 401 authentication_error: bad key [req_1]"; pe.Error() != want {
		t.Errorf("Error() = %q, want %q", pe.Error(), want)
	}
	if _, err := c.Stream(t.Context(), ask("x")); !errors.As(err, &pe) {
		t.Errorf("stream err = %v, want *Error", err)
	}
}

func TestDecodeProviderError(t *testing.T) {
	for _, tc := range []struct {
		body, code, message string
	}{
		{`{"type":"error","error":{"type":"authentication_error","message":"bad key"}}`, "authentication_error", "bad key"},
		{`{"error":{"message":"Incorrect API key","type":"invalid_request_error","code":"invalid_api_key","param":null}}`, "invalid_request_error", "Incorrect API key"},
		{"upstream fell over\n", "", "upstream fell over"},
	} {
		err := decodeProviderError(&http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(tc.body))})
		var pe *Error
		if !errors.As(err, &pe) || pe.Status != http.StatusUnauthorized || pe.Code != tc.code || pe.Message != tc.message {
			t.Errorf("decodeProviderError(%s) = %v", tc.body, err)
		}
	}
	err := decodeProviderError(&http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(failingReader{})})
	var pe *Error
	if !errors.As(err, &pe) || !strings.Contains(pe.Message, "reading the answer") {
		t.Errorf("an unreadable body: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("reset") }

// A request the lux format refuses, or one that cannot be encoded, fails
// before anything is sent.
func TestRequestsRefusedBeforeSending(t *testing.T) {
	c, err := New(ProviderAnthropic, "k", "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Generate(t.Context(), nil); err == nil {
		t.Error("a nil request was sent")
	}
	if _, err := c.Stream(t.Context(), nil); err == nil {
		t.Error("a nil request was streamed")
	}
	if _, err := c.Generate(t.Context(), &llm.Request{Model: "m"}); err == nil {
		t.Error("a request with no messages was sent")
	}
	bad := &llm.Request{Model: "m", Messages: []llm.Message{{Role: llm.RoleUser, Blocks: []llm.Block{
		{Type: llm.BlockToolUse, ToolUse: &llm.ToolUse{ID: "t", Name: "n", Args: []byte(`{`)}},
	}}}}
	if _, err := c.Generate(t.Context(), bad); err == nil || !strings.Contains(err.Error(), "encoding the request") {
		t.Errorf("err = %v, want an encoding error", err)
	}
}

func TestTransportFailures(t *testing.T) {
	c, err := New(ProviderAnthropic, "k", "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Generate(t.Context(), ask("x")); err == nil {
		t.Error("no error from an address nothing listens on")
	}
	c, err = New(ProviderAnthropic, "k", "http://bad\nurl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Generate(t.Context(), ask("x")); err == nil {
		t.Error("no error from an invalid URL")
	}
}

func TestUnreadableAnswers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"invalid JSON", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{`)
		}},
		{"a body cut short", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			_, _ = io.WriteString(w, `{"id":`)
			w.(http.Flusher).Flush()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(ProviderAnthropic, "k", testServer(t, tc.handler).URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Generate(t.Context(), ask("x")); err == nil {
				t.Error("no error")
			}
		})
	}
}

func TestStreamThatIsNotAnEventStream(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	})
	c, err := New(ProviderAnthropic, "k", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stream(t.Context(), ask("x")); err == nil || !strings.Contains(err.Error(), "not an event stream") {
		t.Errorf("err = %v", err)
	}
}
