// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package luxsdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/bridge"
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
		w.Header().Set("Lux-Loss", "top_k,thinking")
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

// TestCostTags pins that WithCostTags travels as Lux-Labels, the one
// header the gateway reads request labels from.
func TestCostTags(t *testing.T) {
	var gotTag string
	var tagSet bool
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotTag = r.Header.Get("Lux-Labels")
		_, tagSet = r.Header["Lux-Labels"]
		if b, _ := io.ReadAll(r.Body); strings.Contains(string(b), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(streamBody))
			return
		}
		_, _ = w.Write([]byte(`{"id":"x","model":"m","blocks":[],"stop_reason":"end_turn","usage":{"input_tokens":0,"output_tokens":0}}`))
	})

	// Insertion order (tenant, project) differs from sorted order, so a
	// pass proves the header is sorted, not just echoed.
	c := New(srv.URL, WithCostTags(map[string]string{"tenant": "acme", "project": "web"}))
	if _, err := c.Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err != nil {
		t.Fatal(err)
	}
	if gotTag != "project=web,tenant=acme" {
		t.Fatalf("bad cost tag on Generate: %q", gotTag)
	}

	// Stream carries the same header.
	tagSet, gotTag = false, ""
	st, err := c.Stream(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if gotTag != "project=web,tenant=acme" {
		t.Fatalf("bad cost tag on Stream: %q", gotTag)
	}

	// CountTokens carries the same header.
	tagSet, gotTag = false, ""
	if _, err := c.CountTokens(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err != nil {
		t.Fatal(err)
	}
	if gotTag != "project=web,tenant=acme" {
		t.Fatalf("bad cost tag on CountTokens: %q", gotTag)
	}

	// No option: the header is absent (not merely empty).
	tagSet, gotTag = false, ""
	if _, err := New(srv.URL).Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); err != nil {
		t.Fatal(err)
	}
	if tagSet {
		t.Fatalf("Lux-Labels must be absent when unset, got %q", gotTag)
	}
}

func TestGenerateError(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"rate_limited","message":"Too many requests; wait and retry.","details":{"request_id":"req_9"}}}`))
	})
	_, err := New(srv.URL).Generate(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *Error, got %v", err)
	}
	if apiErr.Status != 429 || apiErr.Code != "rate_limited" || apiErr.Message != "Too many requests; wait and retry." || apiErr.RequestID != "req_9" || apiErr.Detail != "" {
		t.Fatalf("bad error: %#v", apiErr)
	}
	if got, want := apiErr.Error(), "lux: 429 rate_limited: Too many requests; wait and retry. [req_9]"; got != want {
		t.Fatalf("bad error string:\ngot  %s\nwant %s", got, want)
	}
}

// TestDecodeErrorEnvelope feeds decodeError the lux door's envelope as
// production answers it today, and pins that the code, the user
// sentence, the developer detail, and the request id all reach *Error.
func TestDecodeErrorEnvelope(t *testing.T) {
	for _, c := range []struct {
		status                                int
		body                                  string
		code, message, detail, requestID, str string
	}{
		{
			status:    http.StatusUnauthorized,
			body:      `{"error":{"code":"unauthenticated","message":"This request needs a valid credential.","details":{"detail":"no credential: no Authorization header","request_id":"req_01AUTH"}}}`,
			code:      "unauthenticated",
			message:   "This request needs a valid credential.",
			detail:    "no credential: no Authorization header",
			requestID: "req_01AUTH",
			str:       "lux: 401 unauthenticated: This request needs a valid credential. (no credential: no Authorization header) [req_01AUTH]",
		},
		{
			status:    http.StatusNotFound,
			body:      `{"error":{"code":"model_not_found","message":"There is no model of that name.","details":{"detail":"no Model named \"x\"","request_id":"req_01MODEL"}}}` + "\n",
			code:      "model_not_found",
			message:   "There is no model of that name.",
			detail:    `no Model named "x"`,
			requestID: "req_01MODEL",
			str:       `lux: 404 model_not_found: There is no model of that name. (no Model named "x") [req_01MODEL]`,
		},
		{
			// No details at all: the gateway omits the member when it
			// has neither a detail nor a request id.
			status:  http.StatusNotFound,
			body:    `{"error":{"code":"not_found","message":"There is no such object."}}`,
			code:    "not_found",
			message: "There is no such object.",
			str:     "lux: 404 not_found: There is no such object.",
		},
		{
			// A body in another shape is not the lux envelope: it
			// degrades to the raw bytes, with no code.
			status:  http.StatusTooManyRequests,
			body:    `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`,
			message: `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`,
			str:     `lux: 429: {"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`,
		},
	} {
		err := decodeError(&http.Response{StatusCode: c.status, Body: io.NopCloser(strings.NewReader(c.body))})
		var apiErr *Error
		if !errors.As(err, &apiErr) {
			t.Fatalf("want *Error, got %T %v", err, err)
		}
		if apiErr.Status != c.status || apiErr.Code != c.code || apiErr.Message != c.message || apiErr.Detail != c.detail || apiErr.RequestID != c.requestID {
			t.Errorf("decodeError(%s) = %#v", c.body, apiErr)
		}
		if got := apiErr.Error(); got != c.str {
			t.Errorf("Error():\ngot  %s\nwant %s", got, c.str)
		}
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
		w.Header().Set("Lux-Loss", "top_k")
		_, _ = w.Write([]byte(streamBody))
	})
	st, err := New(srv.URL, WithAPIKey("k")).Stream(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
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
		if errors.Is(err, io.EOF) {
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
		_, _ = w.Write([]byte(`{"error":{"code":"model_not_allowed","message":"This key may not use that model.","details":{"detail":"model m is outside the Key's fence","request_id":"req_3"}}}`))
	})
	_, err := New(srv.URL).Stream(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}})
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != 403 || apiErr.Code != "model_not_allowed" || apiErr.Detail != "model m is outside the Key's fence" || apiErr.RequestID != "req_3" {
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
	defer func() { _ = st.Close() }()
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
		_ = conn.Close()
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
		w.Header().Set("Lux-Estimated", "true")
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
		_, _ = w.Write([]byte(`{"error":{"code":"key_disabled","message":"This key is disabled.","details":{"request_id":"req_4"}}}`))
	})
	var apiErr *Error
	if _, err := New(srv.URL).CountTokens(context.Background(), &Request{Model: "m", Messages: []Message{UserText("x")}}); !errors.As(err, &apiErr) || apiErr.Status != 403 || apiErr.Code != "key_disabled" || apiErr.RequestID != "req_4" {
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

// TestGenerateCostUSDMicro pins that the gateway-reported cost reaches
// an SDK caller through the existing Usage surface, and that an
// omitted cost stays nil rather than becoming a free turn.
func TestGenerateCostUSDMicro(t *testing.T) {
	const body = `{"id":"msg_1","model":"m","blocks":[],"stop_reason":"end_turn",
		"usage":{"input_tokens":3,"output_tokens":2,"cost_usd_micro":1200}}`
	srv := testServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	res, err := New(srv.URL, WithAPIKey("k")).Generate(context.Background(), &Request{Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Usage.CostUSDMicro == nil {
		t.Fatal("CostUSDMicro = nil, want 1200")
	}
	if *res.Usage.CostUSDMicro != 1200 {
		t.Fatalf("CostUSDMicro = %d, want 1200", *res.Usage.CostUSDMicro)
	}

	const noCost = `{"id":"msg_1","model":"m","blocks":[],"stop_reason":"end_turn",
		"usage":{"input_tokens":3,"output_tokens":2}}`
	srv2 := testServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(noCost))
	})
	res, err = New(srv2.URL, WithAPIKey("k")).Generate(context.Background(), &Request{Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Usage.CostUSDMicro != nil {
		t.Fatalf("CostUSDMicro = %d, want nil (a gateway that reports no cost is unknown, not free)", *res.Usage.CostUSDMicro)
	}
}

// TestServerToolsReachTheGateway pins the re-exports: a caller asking for a
// grounded answer names these types through luxsdk, and the request must carry
// them to the wire rather than dropping them on the way.
func TestServerToolsReachTheGateway(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "m",
			"content": []map[string]any{{"type": "text", "text": "ok"}},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, WithAPIKey("k"))
	_, err := c.Generate(context.Background(), &Request{
		Model:    "m",
		Messages: []Message{UserText("what changed in Go 1.27")},
		ServerTools: []ServerTool{{
			Type:   "web_fetch_20250910",
			Name:   "web_fetch",
			Config: json.RawMessage(`{"max_uses":5}`),
		}},
		WebSearch: &WebSearch{ContextSize: "medium"},
	})
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	tools, _ := got["server_tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("server_tools = %#v, want one entry", got["server_tools"])
	}
	tool, _ := tools[0].(map[string]any)
	if tool["type"] != "web_fetch_20250910" || tool["name"] != "web_fetch" {
		t.Fatalf("server_tools[0] = %#v", tool)
	}
	search, _ := got["web_search"].(map[string]any)
	if search["context_size"] != "medium" {
		t.Fatalf("web_search = %#v, want context_size medium", got["web_search"])
	}
}

// FuzzDecodeError: any body yields an *Error that keeps the status; a
// body the lux envelope codec accepts keeps its code, message, detail,
// and request id, and any other body becomes the message whole.
func FuzzDecodeError(f *testing.F) {
	f.Add(`{"error":{"code":"model_not_found","message":"There is no model of that name.","details":{"detail":"no Model named \"x\"","request_id":"req_1"}}}`)
	f.Add(`{"error":{"code":"c","message":"m","details":{"detail":7,"request_id":null}}}`)
	f.Add(`{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`)
	f.Add("upstream fell over")
	f.Fuzz(func(t *testing.T, body string) {
		err := decodeError(&http.Response{StatusCode: 418, Body: io.NopCloser(strings.NewReader(body))})
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Status != 418 {
			t.Fatalf("decodeError(%q) = %v", body, err)
		}
		if f, ok := bridge.ParseEnvelope(bridge.WireLux, []byte(body)); ok {
			if apiErr.Code != f.Code || apiErr.Message != f.Message || apiErr.Detail != f.Detail || apiErr.RequestID != f.RequestID {
				t.Fatalf("decodeError(%q) = %#v, envelope %#v", body, apiErr, f)
			}
		} else if apiErr.Code != "" || apiErr.Message != strings.TrimSpace(body) {
			t.Fatalf("decodeError(%q) = %#v, want the body as the message", body, apiErr)
		}
		_ = apiErr.Error()
	})
}
