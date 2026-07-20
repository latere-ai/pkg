package luxsdk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

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

func TestDirectAnthropicGenerate(t *testing.T) {
	var gotPath, gotKey, gotVersion string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotKey, gotVersion = r.URL.Path, r.Header.Get("x-api-key"), r.Header.Get("anthropic-version")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8",`+
			`"content":[{"type":"text","text":"pong"}],"stop_reason":"end_turn","stop_sequence":null,`+
			`"usage":{"input_tokens":3,"output_tokens":1}}`)
	})
	d, err := NewDirect(ProviderAnthropic, "sk-ant-1", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Generate(context.Background(), &Request{Model: "claude-opus-4-8", Messages: []Message{UserText("ping")}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/messages" || gotKey != "sk-ant-1" || gotVersion == "" {
		t.Fatalf("bad upstream call: path=%q key=%q version=%q", gotPath, gotKey, gotVersion)
	}
	if res.Blocks[0].Text != "pong" || res.StopReason != StopEndTurn || res.Usage.InputTokens != 3 {
		t.Fatalf("bad result: %#v", res)
	}
	if len(res.Loss) != 0 {
		t.Fatalf("anthropic represents this request fully, loss = %v", res.Loss)
	}
}

func TestDirectAnthropicStream(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, anthropicSSE)
	})
	d, err := NewDirect(ProviderAnthropic, "sk", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	st, err := d.Stream(context.Background(), &Request{Model: "claude-opus-4-8", Messages: []Message{UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var text strings.Builder
	var sawStop bool
	for {
		ev, err := st.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch ev.Type {
		case EventTextDelta:
			text.WriteString(ev.Delta)
		case EventMessageStop:
			sawStop = true
		}
	}
	if text.String() != "hi" || !sawStop {
		t.Fatalf("bad stream: text=%q stop=%v", text.String(), sawStop)
	}
}

func TestDirectAnthropicOAuth(t *testing.T) {
	var gotAuth, gotBeta, gotKey string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotBeta, gotKey = r.Header.Get("Authorization"), r.Header.Get("anthropic-beta"), r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"m","type":"message","role":"assistant","model":"m","content":[],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`)
	})
	d, err := NewDirect(ProviderAnthropic, "oauth-tok", srv.URL, WithOAuthToken())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer oauth-tok" || gotBeta != anthropicBetaOAuth || gotKey != "" {
		t.Fatalf("bad oauth headers: auth=%q beta=%q key=%q", gotAuth, gotBeta, gotKey)
	}
}

const chatSSE = "data: {\"id\":\"cc1\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"}}]}\n\n" +
	"data: {\"id\":\"cc1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
	"data: {\"id\":\"cc1\",\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":1}}\n\n" +
	"data: [DONE]\n\n"

func TestDirectOpenAIChat(t *testing.T) {
	var gotPath, gotAuth string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, chatSSE)
	})
	d, err := NewDirect(ProviderOpenAI, "sk-oa", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// top_k is not representable on the OpenAI dialect: it must land
	// in the loss report, not vanish.
	topK := int64(40)
	st, err := d.Stream(context.Background(), &Request{Model: "gpt-4o", TopK: &topK, Messages: []Message{UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if gotPath != "/v1/chat/completions" || gotAuth != "Bearer sk-oa" {
		t.Fatalf("bad upstream call: path=%q auth=%q", gotPath, gotAuth)
	}
	if l := st.Loss(); len(l) == 0 || !strings.Contains(strings.Join(l, ","), "top_k") {
		t.Fatalf("loss = %v, want top_k", l)
	}
	var text strings.Builder
	for {
		ev, err := st.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if ev.Type == EventTextDelta {
			text.WriteString(ev.Delta)
		}
	}
	if text.String() != "ok" {
		t.Fatalf("text = %q", text.String())
	}
}

func TestDirectOpenAIReasoningUsesResponses(t *testing.T) {
	var gotPath string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// A minimal Responses body the openairesp backend can decode.
		_, _ = io.WriteString(w, `{"id":"resp_1","model":"gpt-5.5","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"deep"}]}],"usage":{"input_tokens":2,"output_tokens":1}}`)
	})
	d, err := NewDirect(ProviderOpenAI, "sk", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Generate(context.Background(), &Request{Model: "gpt-5.5", Messages: []Message{UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/responses" {
		t.Fatalf("reasoning model must use the Responses API, got %q", gotPath)
	}
	if res.Blocks[0].Text != "deep" {
		t.Fatalf("bad result: %#v", res)
	}
}

func TestDirectGeminiPath(t *testing.T) {
	var gotPath string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"cc1","model":"gemini-2.5-pro","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"g"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	})
	d, err := NewDirect(ProviderGemini, "key", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Generate(context.Background(), &Request{Model: "gemini-2.5-pro", Messages: []Message{UserText("x")}}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1beta/openai/chat/completions" {
		t.Fatalf("gemini path = %q", gotPath)
	}
}

func TestDirectOllamaNoAuth(t *testing.T) {
	var gotAuth string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"cc1","model":"llama3.1","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"local"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	})
	d, err := NewDirect(ProviderOllama, "", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Generate(context.Background(), &Request{Model: "llama3.1", Messages: []Message{UserText("x")}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("ollama must run unauthenticated, got %q", gotAuth)
	}
}

func TestDirectErrors(t *testing.T) {
	if _, err := NewDirect(Provider("cohere"), "k", ""); err == nil {
		t.Fatal("want error for unknown provider")
	}

	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"bad key"}}`)
	})
	d, err := NewDirect(ProviderAnthropic, "bad", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != 401 || apiErr.Code != "authentication_error" {
		t.Fatalf("bad error: %v", err)
	}

	// Invalid lux request fails before any network call.
	if _, err := d.Generate(context.Background(), &Request{Model: "m"}); err == nil {
		t.Fatal("want decode error for missing messages")
	}

	// A JSON body on a stream call is rejected.
	srvJSON := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	})
	dj, err := NewDirect(ProviderAnthropic, "k", srvJSON.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dj.Stream(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want error for non-SSE stream response")
	}
}

func TestDirectTokenSource(t *testing.T) {
	var gotAuth string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"m","type":"message","role":"assistant","model":"m","content":[],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`)
	})
	d, err := NewDirect(ProviderAnthropic, "", srv.URL, WithTokenSource(staticTokens{token: "jwt-9"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer jwt-9" {
		t.Fatalf("auth = %q", gotAuth)
	}

	dErr, err := NewDirect(ProviderAnthropic, "", srv.URL, WithTokenSource(staticTokens{err: errors.New("no token")}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dErr.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("want token source error, got %v", err)
	}
}

func TestDirectTransportAndURLErrors(t *testing.T) {
	d, err := NewDirect(ProviderAnthropic, "k", "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want transport error")
	}
	dURL, err := NewDirect(ProviderAnthropic, "k", "http://bad\nurl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dURL.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want URL error")
	}
}

func TestNewDirectDefaults(t *testing.T) {
	d, err := NewDirect(ProviderAnthropic, "k1", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.baseURL != "https://api.anthropic.com" {
		t.Fatalf("default base = %q", d.baseURL)
	}
	dk, err := NewDirect(ProviderOpenAI, "positional", "", WithAPIKey("via-option"))
	if err != nil {
		t.Fatal(err)
	}
	if dk.apiKey != "via-option" {
		t.Fatalf("WithAPIKey must win, got %q", dk.apiKey)
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

func TestDirectGenerateBadResponses(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{`)
	})
	d, err := NewDirect(ProviderAnthropic, "k", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want decode error for invalid upstream JSON")
	}
}

func TestDirectGenerateBodyReadError(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = io.WriteString(w, `{"id":`)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server does not support hijacking")
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	})
	d, err := NewDirect(ProviderAnthropic, "k", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want body read error")
	}
}

func TestDirectMarshalError(t *testing.T) {
	d, err := NewDirect(ProviderAnthropic, "k", "http://unused")
	if err != nil {
		t.Fatal(err)
	}
	req := &Request{Model: "m", Messages: []Message{{Role: RoleUser, Blocks: []Block{
		{Type: BlockToolUse, ToolUse: &ToolUse{ID: "t", Name: "n", Args: []byte(`{`)}},
	}}}}
	if _, err := d.Generate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "encoding request") {
		t.Fatalf("want marshal error, got %v", err)
	}
}

// Caller compile-time checks: gateway and direct expose one surface.
var (
	_ Caller = (*Client)(nil)
	_ Caller = (*Direct)(nil)
)

// The A-series openai-chat providers (spec lux 035). Moonshot and xAI are
// plain Bearer + /v1; Zhipu is the exception that motivates a test of its own,
// since /v1/chat/completions is a 404 on its API.
func TestDirectOpenAIChatFamilyPaths(t *testing.T) {
	cases := []struct {
		provider Provider
		model    string
		wantPath string
	}{
		{ProviderMoonshot, "kimi-k2.6", "/v1/chat/completions"},
		{ProviderXai, "grok-4.5", "/v1/chat/completions"},
		{ProviderZhipu, "glm-4.6", "/api/paas/v4/chat/completions"},
	}
	for _, c := range cases {
		t.Run(string(c.provider), func(t *testing.T) {
			var gotPath, gotAuth string
			srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"cc1","model":"`+c.model+`","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
			})
			d, err := NewDirect(c.provider, "sek", srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.Generate(context.Background(), &Request{Model: c.model, Messages: []Message{UserText("x")}}); err != nil {
				t.Fatal(err)
			}
			if gotPath != c.wantPath {
				t.Fatalf("%s path = %q, want %q", c.provider, gotPath, c.wantPath)
			}
			if gotAuth != "Bearer sek" {
				t.Fatalf("%s auth = %q, want Bearer", c.provider, gotAuth)
			}
		})
	}
}

// A provider in the enum but missing from providerDefaults is rejected by
// NewDirect, so an incomplete add fails loudly rather than sending requests to
// an empty base URL.
func TestDirectNewProviderDefaultsAreComplete(t *testing.T) {
	for _, p := range []Provider{
		ProviderAnthropic, ProviderOpenAI, ProviderGemini, ProviderOpenRouter,
		ProviderOllama, ProviderMoonshot, ProviderXai, ProviderZhipu,
	} {
		d, err := NewDirect(p, "k", "")
		if err != nil {
			t.Errorf("NewDirect(%s) = %v; add it to providerDefaults", p, err)
			continue
		}
		if d.baseURL == "" {
			t.Errorf("NewDirect(%s) has an empty base URL", p)
		}
	}
}
