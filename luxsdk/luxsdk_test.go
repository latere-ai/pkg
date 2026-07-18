package luxsdk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestGenerate(t *testing.T) {
	var gotAuth, gotPath, gotBody string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Lux-Compat-Loss", "top_k,thinking")
		_, _ = w.Write([]byte(`{
			"id": "msg_1", "model": "claude-sonnet-5",
			"blocks": [{"type": "text", "text": "hello"}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 3, "output_tokens": 2}
		}`))
	})

	c := New(srv.URL+"/", WithAPIKey("lux_k1"))
	res, err := c.Generate(context.Background(), &Request{
		Model:    "claude-sonnet-5",
		Messages: []Message{UserText("hi")},
		Stream:   true, // must be forced off
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/lux/v1/generate" || gotAuth != "Bearer lux_k1" {
		t.Fatalf("bad request: path=%q auth=%q", gotPath, gotAuth)
	}
	if strings.Contains(gotBody, `"stream":true`) {
		t.Fatalf("Generate must force stream off: %s", gotBody)
	}
	if res.ID != "msg_1" || res.StopReason != StopEndTurn || res.Blocks[0].Text != "hello" {
		t.Fatalf("bad result: %#v", res)
	}
	if res.Usage.InputTokens != 3 || res.Usage.OutputTokens != 2 {
		t.Fatalf("bad usage: %#v", res.Usage)
	}
	if len(res.Loss) != 2 || res.Loss[0] != "top_k" || res.Loss[1] != "thinking" {
		t.Fatalf("bad loss: %#v", res.Loss)
	}
}

func TestGenerateError(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"slow down","request_id":"req_9"}}`))
	})
	_, err := New(srv.URL).Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *Error, got %v", err)
	}
	if apiErr.Status != 429 || apiErr.Code != "rate_limit_error" || apiErr.Message != "slow down" || apiErr.RequestID != "req_9" {
		t.Fatalf("bad error: %#v", apiErr)
	}
	if !strings.Contains(apiErr.Error(), "rate_limit_error") {
		t.Fatalf("bad error string: %s", apiErr.Error())
	}
}

func TestGenerateOpaqueError(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream fell over"))
	})
	_, err := New(srv.URL).Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *Error, got %v", err)
	}
	if apiErr.Status != 502 || apiErr.Message != "upstream fell over" || apiErr.Code != "" {
		t.Fatalf("bad error: %#v", apiErr)
	}
	if !strings.Contains(apiErr.Error(), "502") {
		t.Fatalf("bad error string: %s", apiErr.Error())
	}
}

func TestGenerateInvalidResponse(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{`))
	})
	if _, err := New(srv.URL).Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want error for invalid response JSON")
	}
}

func TestGenerateTransportError(t *testing.T) {
	c := New("http://127.0.0.1:1") // nothing listens here
	if _, err := c.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want transport error")
	}
}

type staticTokens struct {
	token string
	err   error
}

func (s staticTokens) Token(context.Context) (string, error) { return s.token, s.err }

func TestTokenSource(t *testing.T) {
	var gotAuth string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"id":"x","model":"m","blocks":[],"stop_reason":"end_turn","usage":{"input_tokens":0,"output_tokens":0}}`))
	})
	c := New(srv.URL, WithTokenSource(staticTokens{token: "jwt-1"}))
	if _, err := c.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer jwt-1" {
		t.Fatalf("bad auth: %q", gotAuth)
	}
}

func TestTokenSourceError(t *testing.T) {
	c := New("http://unused", WithTokenSource(staticTokens{err: errors.New("no token")}))
	if _, err := c.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("want token source error, got %v", err)
	}
}

const streamBody = "event: message_start\ndata: {\"type\":\"message_start\",\"id\":\"msg_1\",\"model\":\"m\",\"index\":0,\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}\n\n" +
	"event: block_start\ndata: {\"type\":\"block_start\",\"index\":0,\"block\":{\"type\":\"text\"}}\n\n" +
	"event: text_delta\ndata: {\"type\":\"text_delta\",\"index\":0,\"delta\":\"hel\"}\n\n" +
	"event: text_delta\ndata: {\"type\":\"text_delta\",\"index\":0,\"delta\":\"lo\"}\n\n" +
	"event: block_stop\ndata: {\"type\":\"block_stop\",\"index\":0}\n\n" +
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"index\":0,\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\",\"index\":0}\n\n"

func TestStream(t *testing.T) {
	var gotBody string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("X-Lux-Compat-Loss", "top_k")
		_, _ = w.Write([]byte(streamBody))
	})
	st, err := New(srv.URL, WithAPIKey("k")).Stream(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if !strings.Contains(gotBody, `"stream":true`) {
		t.Fatalf("Stream must force stream on: %s", gotBody)
	}
	if l := st.Loss(); len(l) != 1 || l[0] != "top_k" {
		t.Fatalf("bad loss: %#v", l)
	}
	var text strings.Builder
	var types []string
	for {
		ev, err := st.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		types = append(types, string(ev.Type))
		if ev.Type == EventTextDelta {
			text.WriteString(ev.Delta)
		}
	}
	if text.String() != "hello" {
		t.Fatalf("bad text: %q", text.String())
	}
	want := "message_start block_start text_delta text_delta block_stop message_delta message_stop"
	if got := strings.Join(types, " "); got != want {
		t.Fatalf("bad sequence:\ngot  %s\nwant %s", got, want)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamErrorStatus(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"permission_error","message":"nope"}}`))
	})
	_, err := New(srv.URL).Stream(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != 403 || apiErr.Code != "permission_error" {
		t.Fatalf("bad error: %v", err)
	}
}

func TestStreamMidStreamError(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"id\":\"m1\",\"index\":0}\n\n" +
			"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}\n\n"))
	})
	st, err := New(srv.URL).Stream(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Next(); err != nil {
		t.Fatal(err)
	}
	_, err = st.Next()
	var se *StreamError
	if !errors.As(err, &se) || se.Code != "overloaded_error" {
		t.Fatalf("want mid-stream StreamError, got %v", err)
	}
}

func TestStreamRejectsNonSSE(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x"}`))
	})
	if _, err := New(srv.URL).Stream(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want error for non-SSE response")
	}
}

func TestWithHTTPClient(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x","model":"m","blocks":[],"stop_reason":"end_turn","usage":{"input_tokens":0,"output_tokens":0}}`))
	})
	custom := &http.Client{Transport: http.DefaultTransport}
	c := New(srv.URL, WithHTTPClient(custom))
	if _, err := c.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err != nil {
		t.Fatal(err)
	}
}

func TestHelpers(t *testing.T) {
	u := UserText("q")
	a := AssistantText("r")
	if u.Role != RoleUser || u.Blocks[0].Text != "q" || a.Role != RoleAssistant || a.Blocks[0].Text != "r" {
		t.Fatalf("bad helpers: %#v %#v", u, a)
	}
}

func TestStreamTransportError(t *testing.T) {
	if _, err := New("http://127.0.0.1:1").Stream(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want transport error")
	}
}

func TestGenerateBodyReadError(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte(`{"id":`))
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
	if _, err := New(srv.URL).Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want body read error")
	}
}

func TestBadBaseURL(t *testing.T) {
	c := New("http://bad\nurl")
	if _, err := c.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want URL error")
	}
}

func TestMarshalError(t *testing.T) {
	req := &Request{Model: "m", Messages: []Message{{Role: RoleUser, Blocks: []Block{
		{Type: BlockToolUse, ToolUse: &ToolUse{ID: "t", Name: "n", Args: []byte(`{`)}},
	}}}}
	if _, err := New("http://unused").Generate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "encoding request") {
		t.Fatalf("want marshal error, got %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {})
	if _, err := New(srv.URL).Generate(ctx, &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want context error")
	}
}

func TestCountTokens(t *testing.T) {
	var gotPath, gotBody string
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"input_tokens": 42}`))
	})
	tc, err := New(srv.URL, WithAPIKey("k")).CountTokens(context.Background(), &Request{Model: "m", Messages: []Message{UserText("hi")}, Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/lux/v1/count_tokens" {
		t.Fatalf("path = %q", gotPath)
	}
	if strings.Contains(gotBody, `"stream":true`) {
		t.Fatalf("CountTokens must force stream off: %s", gotBody)
	}
	if tc.InputTokens != 42 || tc.Estimated {
		t.Fatalf("bad count: %#v", tc)
	}
}

func TestCountTokensEstimated(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Lux-Compat-Estimated", "true")
		_, _ = w.Write([]byte(`{"input_tokens": 7}`))
	})
	tc, err := New(srv.URL).CountTokens(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if tc.InputTokens != 7 || !tc.Estimated {
		t.Fatalf("bad count: %#v", tc)
	}
}

func TestCountTokensErrors(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"permission_error","message":"no"}}`))
	})
	var apiErr *Error
	if _, err := New(srv.URL).CountTokens(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("want *Error 403, got %v", err)
	}
	srvBad := testServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{`)) })
	if _, err := New(srvBad.URL).CountTokens(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want decode error")
	}
	if _, err := New("http://127.0.0.1:1").CountTokens(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want transport error")
	}
	c := New("http://unused", WithTokenSource(staticTokens{err: errors.New("no token")}))
	if _, err := c.CountTokens(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("want token source error, got %v", err)
	}
	req := &Request{Model: "m", Messages: []Message{{Role: RoleUser, Blocks: []Block{{Type: BlockToolUse, ToolUse: &ToolUse{Args: []byte(`{`)}}}}}}
	if _, err := New("http://unused").CountTokens(context.Background(), req); err == nil {
		t.Fatal("want marshal error")
	}
	if _, err := New("http://bad\nurl").CountTokens(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err == nil {
		t.Fatal("want URL error")
	}
}
