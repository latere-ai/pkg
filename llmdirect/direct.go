// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package llmdirect calls a model provider directly in the Lux dialect, with
// no Latere service in the path: the request is translated to the
// provider's own wire format on the caller's machine, through the same
// llmdialect backends the Lux gateway uses, and the answer translated back.
// It is for development machines and a caller's own provider keys, a local
// Ollama among them; through the models capability of the Latere API
// (latere.ai/x/sdk-go/llm), Latere holds the provider credentials and
// applies the key's access, limits and records.
//
// A Client speaks the same request, answer and stream types as llm.Client,
// with methods of the same signatures, so a program that declares the
// interface it needs takes either:
//
//	type model interface {
//		Generate(ctx context.Context, req *llm.Request) (*llm.Result, error)
//	}
//
// Fields the provider's format cannot represent are named in Result.Loss and
// Stream.Loss, as through the gateway.
//
// It lives outside llmdialect because it owns what llmdialect leaves to its
// consumer: the transport, the credential and the tracing.
package llmdirect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"latere.ai/x/sdk-go/llm"

	"latere.ai/x/pkg/llmdialect"
	"latere.ai/x/pkg/llmdialect/anthropic"
	"latere.ai/x/pkg/llmdialect/ir"
	"latere.ai/x/pkg/llmdialect/lux"
	"latere.ai/x/pkg/llmdialect/openaichat"
	"latere.ai/x/pkg/llmdialect/openairesp"
	"latere.ai/x/pkg/otel"
)

// Provider is a provider family a Client can call.
type Provider string

// The providers.
const (
	ProviderAnthropic  Provider = "anthropic"
	ProviderOpenAI     Provider = "openai"
	ProviderGemini     Provider = "gemini"
	ProviderOpenRouter Provider = "openrouter"
	ProviderOllama     Provider = "ollama"
	ProviderMoonshot   Provider = "moonshot"
	ProviderXai        Provider = "xai"
	ProviderZhipu      Provider = "zhipu"
)

// providerDefaults is each provider's public endpoint, host only: the path
// is backendFor's.
var providerDefaults = map[Provider]string{
	ProviderAnthropic:  "https://api.anthropic.com",
	ProviderOpenAI:     "https://api.openai.com",
	ProviderGemini:     "https://generativelanguage.googleapis.com",
	ProviderOpenRouter: "https://openrouter.ai/api",
	ProviderOllama:     "http://localhost:11434",
	ProviderMoonshot:   "https://api.moonshot.ai",
	ProviderXai:        "https://api.x.ai",
	// Zhipu is the one provider whose OpenAI-compatible surface is not at
	// /v1, so the difference lives in backendFor's path.
	ProviderZhipu: "https://api.z.ai",
}

const (
	anthropicVersion = "2023-06-01"

	// anthropicBetaOAuth authorizes an OAuth access token, rather than an
	// API key, on the Messages API.
	anthropicBetaOAuth = "oauth-2025-04-20"
)

// TokenSource supplies the provider credential per call, for a credential
// that rotates.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Option configures a Client.
type Option func(*settings)

// settings is the option state of a Client.
type settings struct {
	apiKey string
	tokens TokenSource
	hc     *http.Client
	oauth  bool
}

// WithAPIKey authenticates with the provider's API key, overriding the key
// New was given.
func WithAPIKey(key string) Option {
	return func(s *settings) { s.apiKey = key }
}

// WithTokenSource authenticates each call with a credential from ts.
func WithTokenSource(ts TokenSource) Option {
	return func(s *settings) { s.tokens = ts }
}

// WithHTTPClient sends requests with hc instead of the default client, which
// traces each call through latere.ai/x/pkg/otel.
func WithHTTPClient(hc *http.Client) Option {
	return func(s *settings) { s.hc = hc }
}

// WithOAuthToken marks the credential as an OAuth access token, for
// ProviderAnthropic only: it travels as "Authorization: Bearer" with the
// OAuth beta header instead of as x-api-key.
func WithOAuthToken() Option {
	return func(s *settings) { s.oauth = true }
}

// Client calls one provider endpoint in the Lux dialect. It is safe for
// concurrent use.
type Client struct {
	provider Provider
	baseURL  string
	apiKey   string
	tokens   TokenSource
	hc       *http.Client
	oauth    bool
	frontend *lux.Frontend
}

// New returns a Client for provider at baseURL, or at the provider's public
// endpoint when baseURL is empty. apiKey is the provider's own credential,
// empty for an endpoint that takes none, such as a local Ollama.
func New(provider Provider, apiKey, baseURL string, opts ...Option) (*Client, error) {
	def, ok := providerDefaults[provider]
	if !ok {
		return nil, fmt.Errorf("llmdirect: unknown provider %q", provider)
	}
	if baseURL == "" {
		baseURL = def
	}
	s := settings{hc: otel.HTTPClient()}
	for _, o := range opts {
		o(&s)
	}
	if s.apiKey != "" {
		apiKey = s.apiKey
	}
	return &Client{
		provider: provider,
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   apiKey,
		tokens:   s.tokens,
		hc:       s.hc,
		oauth:    s.oauth,
		frontend: lux.NewFrontend(),
	}, nil
}

// Error is a provider's answer that is not a success.
type Error struct {
	// Status is the HTTP status.
	Status int
	// Code is the provider's error.type, such as "rate_limit_error".
	Code string
	// Message is the provider's error.message, or, for a body that is not
	// the provider's error shape, the body itself.
	Message string
	// RequestID is the provider's request id, when it sent one.
	RequestID string
}

// Error returns the status, code, message and request id on one line.
func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "llmdirect: %d", e.Status)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	b.WriteString(": " + e.Message)
	if e.RequestID != "" {
		b.WriteString(" [" + e.RequestID + "]")
	}
	return b.String()
}

// backendFor picks the dialect backend and upstream path, as the gateway
// routes: Anthropic speaks Messages; Gemini is reached through its
// OpenAI-compatible prefix; Zhipu serves Chat Completions under
// /api/paas/v4; OpenAI's reasoning models need the Responses API for tool
// use; everything else is Chat Completions.
func (c *Client) backendFor(model string) (llmdialect.Backend, string) {
	switch c.provider {
	case ProviderAnthropic:
		return anthropic.NewBackend(anthropic.BackendOptions{}), "/v1/messages"
	case ProviderGemini:
		return openaichat.NewBackend(openaichat.BackendOptions{}), "/v1beta/openai/chat/completions"
	case ProviderZhipu:
		return openaichat.NewBackend(openaichat.BackendOptions{}), "/api/paas/v4/chat/completions"
	case ProviderOpenAI:
		if isOpenAIResponsesModel(model) {
			return openairesp.NewBackend(), "/v1/responses"
		}
	}
	return openaichat.NewBackend(openaichat.BackendOptions{
		UseMaxCompletionTokens: c.provider == ProviderOpenAI,
	}), "/v1/chat/completions"
}

// isOpenAIResponsesModel reports whether an OpenAI model must be driven
// through the Responses API: the gpt-5 and o-series reasoning families
// refuse function tools alongside reasoning_effort on Chat Completions.
func isOpenAIResponsesModel(model string) bool {
	m := strings.ToLower(model)
	if i := strings.LastIndex(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	return strings.HasPrefix(m, "gpt-5") ||
		strings.HasPrefix(m, "o1") ||
		strings.HasPrefix(m, "o3") ||
		strings.HasPrefix(m, "o4")
}

// Generate sends req to the provider and waits for the whole answer. It
// sets req's Stream to false on the copy it sends.
func (c *Client) Generate(ctx context.Context, req *llm.Request) (*llm.Result, error) {
	ireq, backend, resp, err := c.call(ctx, req, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("llmdirect: reading the answer: %w", err)
	}
	iresp, err := backend.DecodeResponse(body)
	if err != nil {
		return nil, fmt.Errorf("llmdirect: %w", err)
	}
	// Re-encoded through the lux frontend, so the caller reads the same
	// vocabulary as through the gateway.
	out, err := c.frontend.EncodeResponse(iresp)
	if err != nil {
		return nil, fmt.Errorf("llmdirect: %w", err)
	}
	res := &llm.Result{Loss: ireq.Loss.Strings()}
	if err := json.Unmarshal(out, &res.Response); err != nil {
		return nil, fmt.Errorf("llmdirect: decoding the answer: %w", err)
	}
	return res, nil
}

// Stream sends req to the provider and returns its answer as a Stream of
// Lux dialect events. It sets req's Stream to true on the copy it sends.
// Close the Stream, or range over its Events to the end.
func (c *Client) Stream(ctx context.Context, req *llm.Request) (*llm.Stream, error) {
	ireq, backend, resp, err := c.call(ctx, req, true)
	if err != nil {
		return nil, err
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/event-stream" {
		defer func() { _ = resp.Body.Close() }()
		return nil, fmt.Errorf("llmdirect: the answer is %q, not an event stream", resp.Header.Get("Content-Type"))
	}
	dec := backend.NewEventDecoder(resp.Body)
	events := func(yield func(llm.Event, error) bool) {
		for {
			iev, err := dec.Next()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				yield(llm.Event{}, fmt.Errorf("llmdirect: %w", err))
				return
			}
			ev, err := lux.EventFromIR(iev)
			if !yield(ev, err) || err != nil {
				return
			}
		}
	}
	return llm.NewStream(events, ireq.Loss.Strings(), "", resp.Body.Close), nil
}

// call decodes the lux request into the IR, encodes it for the provider,
// and performs the exchange. An answer that is not 200 is an *Error.
func (c *Client) call(ctx context.Context, req *llm.Request, stream bool) (*ir.Request, llmdialect.Backend, *http.Response, error) {
	if req == nil {
		return nil, nil, nil, errors.New("llmdirect: the request is nil")
	}
	wire := *req
	wire.Stream = stream
	body, err := json.Marshal(&wire)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("llmdirect: encoding the request: %w", err)
	}
	ireq, err := c.frontend.DecodeRequest(body)
	if err != nil {
		return nil, nil, nil, err
	}
	backend, path := c.backendFor(ireq.Model)
	out, err := backend.EncodeRequest(ireq)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("llmdirect: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(out))
	if err != nil {
		return nil, nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := c.authorize(ctx, httpReq); err != nil {
		return nil, nil, nil, err
	}
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("llmdirect: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return nil, nil, nil, decodeProviderError(resp)
	}
	return ireq, backend, resp, nil
}

// authorize sets the provider's credential: x-api-key and
// anthropic-version for an Anthropic API key, "Authorization: Bearer"
// everywhere else, with the OAuth beta header for an Anthropic OAuth token.
// A provider called with no credential, such as a local Ollama, gets none.
func (c *Client) authorize(ctx context.Context, httpReq *http.Request) error {
	credential := c.apiKey
	if c.tokens != nil {
		t, err := c.tokens.Token(ctx)
		if err != nil {
			return fmt.Errorf("llmdirect: the token source: %w", err)
		}
		credential = t
	}
	if c.provider == ProviderAnthropic {
		httpReq.Header.Set("anthropic-version", anthropicVersion)
		if c.oauth || c.tokens != nil {
			httpReq.Header.Set("Authorization", "Bearer "+credential)
			if c.oauth {
				httpReq.Header.Set("anthropic-beta", anthropicBetaOAuth)
			}
			return nil
		}
		httpReq.Header.Set("x-api-key", credential)
		return nil
	}
	if credential != "" {
		httpReq.Header.Set("Authorization", "Bearer "+credential)
	}
	return nil
}

// decodeProviderError reads a provider's answer that is not a success:
// error.type and error.message, the members the Anthropic and OpenAI shapes
// share, or the body as the message when it is neither.
func decodeProviderError(resp *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := &Error{Status: resp.StatusCode}
	if err != nil {
		out.Message = fmt.Sprintf("reading the answer: %v", err)
		return out
	}
	var wire struct {
		Error struct {
			Type      string `json:"type"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &wire) != nil || (wire.Error.Type == "" && wire.Error.Message == "") {
		out.Message = strings.TrimSpace(string(body))
		return out
	}
	out.Code = wire.Error.Type
	out.Message = wire.Error.Message
	out.RequestID = wire.Error.RequestID
	return out
}
