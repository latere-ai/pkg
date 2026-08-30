package luxsdk

// Direct mode: the same lux-format call surface, but against a
// provider endpoint instead of a Lux deployment. The request is
// down-converted client-side through the identical llmdialect
// backends the gateway uses, so a caller can swap New for NewDirect
// (BYO key, no gateway) without changing a line of call-site code.
// Fields the provider dialect cannot represent land in Result.Loss /
// Stream.Loss, exactly as in gateway mode.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"latere.ai/x/pkg/llmdialect"
	"latere.ai/x/pkg/llmdialect/anthropic"
	"latere.ai/x/pkg/llmdialect/ir"
	"latere.ai/x/pkg/llmdialect/lux"
	"latere.ai/x/pkg/llmdialect/openaichat"
	"latere.ai/x/pkg/llmdialect/openairesp"
)

// Provider is a directly-reachable upstream family.
type Provider string

// Providers.
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

// Per-provider defaults.
var providerDefaults = map[Provider]string{
	ProviderAnthropic:  "https://api.anthropic.com",
	ProviderOpenAI:     "https://api.openai.com",
	ProviderGemini:     "https://generativelanguage.googleapis.com",
	ProviderOpenRouter: "https://openrouter.ai/api",
	ProviderOllama:     "http://localhost:11434",
	ProviderMoonshot:   "https://api.moonshot.ai",
	ProviderXai:        "https://api.x.ai",
	// Host-only, like the rest. Zhipu is the one provider that does not
	// serve its OpenAI-compatible surface at /v1, so the difference lives
	// in backendFor's path rather than in this URL.
	ProviderZhipu: "https://api.z.ai",
}

const (
	anthropicVersion = "2023-06-01"

	// anthropicBetaOAuth authorizes an OAuth access token (rather
	// than an API key) on the Messages API.
	anthropicBetaOAuth = "oauth-2025-04-20"
)

// Direct calls one provider endpoint in the lux format, translating
// through the provider's dialect backend client-side.
type Direct struct {
	provider Provider
	baseURL  string
	apiKey   string
	tokens   TokenSource
	hc       *http.Client
	oauth    bool
	frontend *lux.Frontend
}

// NewDirect returns a caller for provider at baseURL (empty for the
// provider's public endpoint). apiKey is the provider's own
// credential; pass options for OAuth or per-call tokens.
func NewDirect(provider Provider, apiKey, baseURL string, opts ...Option) (*Direct, error) {
	def, ok := providerDefaults[provider]
	if !ok {
		return nil, fmt.Errorf("lux: unknown provider %q", provider)
	}
	if baseURL == "" {
		baseURL = def
	}
	s := applyOptions(opts)
	if s.apiKey != "" {
		apiKey = s.apiKey
	}
	return &Direct{
		provider: provider,
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   apiKey,
		tokens:   s.tokens,
		hc:       s.hc,
		oauth:    s.oauth,
		frontend: lux.NewFrontend(),
	}, nil
}

// backendFor picks the dialect backend and upstream path, mirroring
// the gateway's routing: Anthropic speaks Messages; Gemini is reached
// through its openai-compat prefix; Zhipu serves Chat Completions under
// /api/paas/v4 rather than /v1; OpenAI reasoning models require the
// Responses API for tool use; everything else is Chat Completions.
func (d *Direct) backendFor(model string) (llmdialect.Backend, string) {
	switch d.provider {
	case ProviderAnthropic:
		return anthropic.NewBackend(anthropic.BackendOptions{}), "/v1/messages"
	case ProviderGemini:
		return openaichat.NewBackend(openaichat.BackendOptions{}), "/v1beta/openai/chat/completions"
	case ProviderZhipu:
		// Zhipu serves chat completions at /api/paas/v4, not /v1, which
		// is a 404 there. Same shape otherwise, so only the path differs.
		return openaichat.NewBackend(openaichat.BackendOptions{}), "/api/paas/v4/chat/completions"
	case ProviderOpenAI:
		if isOpenAIResponsesModel(model) {
			return openairesp.NewBackend(), "/v1/responses"
		}
	}
	return openaichat.NewBackend(openaichat.BackendOptions{
		UseMaxCompletionTokens: d.provider == ProviderOpenAI,
	}), "/v1/chat/completions"
}

// isOpenAIResponsesModel reports whether an OpenAI model must be
// driven through the Responses API: the gpt-5 and o-series reasoning
// families reject function tools alongside reasoning_effort on Chat
// Completions.
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

// Generate performs a non-streaming call. The request's Stream flag
// is overridden to false.
func (d *Direct) Generate(ctx context.Context, req *Request) (*Result, error) {
	ireq, backend, resp, err := d.call(ctx, req, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("lux: reading response: %w", err)
	}
	iresp, err := backend.DecodeResponse(body)
	if err != nil {
		return nil, fmt.Errorf("lux: %w", err)
	}
	// Re-encode through the lux frontend so the caller sees the same
	// wire vocabulary as in gateway mode.
	out, err := d.frontend.EncodeResponse(iresp)
	if err != nil {
		return nil, fmt.Errorf("lux: %w", err)
	}
	res := &Result{Loss: ireq.Loss.Strings()}
	if err := json.Unmarshal(out, &res.Response); err != nil {
		return nil, fmt.Errorf("lux: invalid response JSON: %w", err)
	}
	return res, nil
}

// Stream performs a streaming call. The request's Stream flag is
// overridden to true. The caller must Close the returned stream.
func (d *Direct) Stream(ctx context.Context, req *Request) (*Stream, error) {
	ireq, backend, resp, err := d.call(ctx, req, true)
	if err != nil {
		return nil, err
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/event-stream" {
		defer func() { _ = resp.Body.Close() }()
		return nil, fmt.Errorf("lux: expected an event stream, got %q", resp.Header.Get("Content-Type"))
	}
	dec := backend.NewEventDecoder(resp.Body)
	return &Stream{
		next: func() (Event, error) {
			iev, err := dec.Next()
			if err != nil {
				return Event{}, err
			}
			return lux.EventFromIR(iev)
		},
		closer: resp.Body.Close,
		loss:   ireq.Loss.Strings(),
	}, nil
}

// call decodes the lux request into the IR, encodes it for the
// provider, and performs the HTTP exchange. Non-2xx statuses are
// decoded into *Error.
func (d *Direct) call(ctx context.Context, req *Request, stream bool) (*ir.Request, llmdialect.Backend, *http.Response, error) {
	wire := *req
	wire.Stream = stream
	body, err := json.Marshal(&wire)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("lux: encoding request: %w", err)
	}
	ireq, err := d.frontend.DecodeRequest(body)
	if err != nil {
		return nil, nil, nil, err
	}
	backend, path := d.backendFor(ireq.Model)
	out, err := backend.EncodeRequest(ireq)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("lux: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+path, bytes.NewReader(out))
	if err != nil {
		return nil, nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := d.authorize(ctx, httpReq); err != nil {
		return nil, nil, nil, err
	}
	resp, err := d.hc.Do(httpReq)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("lux: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return nil, nil, nil, decodeError(resp)
	}
	return ireq, backend, resp, nil
}

// authorize sets the provider's auth headers: x-api-key +
// anthropic-version for Anthropic API keys, "Authorization: Bearer"
// everywhere else (and for Anthropic OAuth tokens, with the OAuth
// beta header). Ollama runs unauthenticated when no key is set.
func (d *Direct) authorize(ctx context.Context, httpReq *http.Request) error {
	credential := d.apiKey
	if d.tokens != nil {
		t, err := d.tokens.Token(ctx)
		if err != nil {
			return fmt.Errorf("lux: token source: %w", err)
		}
		credential = t
	}
	if d.provider == ProviderAnthropic {
		httpReq.Header.Set("anthropic-version", anthropicVersion)
		if d.oauth || d.tokens != nil {
			httpReq.Header.Set("Authorization", "Bearer "+credential)
			if d.oauth {
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
