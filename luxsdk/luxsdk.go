// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package luxsdk is the first-party Go client for the Latere Lux
// gateway's native dialect: one typed request /
// response / streaming shape, POST /lux/v1/generate, any provider Lux
// routes to. Authenticate with a Lux Key, which travels as
// Authorization: Bearer. The gateway matches that value by its hash and
// decodes nothing, so a Latere Auth identity or actor token is refused
// unless a platform registered that exact token as a Key's value.
//
//	c := luxsdk.New("https://api.latere.ai/v1/models", luxsdk.WithAPIKey(key))
//	res, err := c.Generate(ctx, &luxsdk.Request{
//		Model:    "claude-sonnet-5",
//		Messages: []luxsdk.Message{luxsdk.UserText("hello")},
//	})
//
// Both arguments fall back to the environment when omitted, so a
// script configured by `eval "$(latere lux env lux)"` needs neither:
//
//	c := luxsdk.New("") // LUX_BASE_URL + LUX_API_KEY
//
// The wire vocabulary is defined once in pkg/llmdialect/lux and
// re-exported here, so the SDK and the gateway codec cannot drift.
package luxsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"os"
	"slices"
	"strings"

	"latere.ai/x/pkg/otel"

	"latere.ai/x/pkg/llmdialect/bridge"
	"latere.ai/x/pkg/llmdialect/ir"
	"latere.ai/x/pkg/llmdialect/lux"
)

// Wire vocabulary, re-exported from the lux dialect codec.
type (
	Request        = lux.Request
	Response       = lux.Response
	Message        = lux.Message
	Block          = lux.Block
	Image          = lux.Image
	ToolUse        = lux.ToolUse
	ToolResult     = lux.ToolResult
	Opaque         = lux.Opaque
	Tool           = lux.Tool
	ServerTool     = lux.ServerTool
	WebSearch      = lux.WebSearch
	ToolChoice     = lux.ToolChoice
	Reasoning      = lux.Reasoning
	Effort         = ir.Effort
	ResponseSchema = lux.ResponseSchema
	Usage          = lux.Usage
	Event          = lux.Event
	TokenLogProb   = lux.TokenLogProb
	// StreamError is a mid-stream error frame from the gateway.
	StreamError = lux.StreamError
)

// Closed vocabularies, re-exported from the IR.
const (
	RoleUser      = ir.RoleUser
	RoleAssistant = ir.RoleAssistant

	BlockText             = ir.BlockText
	BlockImage            = ir.BlockImage
	BlockToolUse          = ir.BlockToolUse
	BlockToolResult       = ir.BlockToolResult
	BlockThinking         = ir.BlockThinking
	BlockRedactedThinking = ir.BlockRedactedThinking
	BlockOpaque           = ir.BlockOpaque

	ToolChoiceAuto = ir.ToolChoiceAuto
	ToolChoiceAny  = ir.ToolChoiceAny
	ToolChoiceNone = ir.ToolChoiceNone
	ToolChoiceTool = ir.ToolChoiceTool

	EffortMinimal = ir.EffortMinimal
	EffortLow     = ir.EffortLow
	EffortMedium  = ir.EffortMedium
	EffortHigh    = ir.EffortHigh

	StopEndTurn      = ir.StopEndTurn
	StopToolUse      = ir.StopToolUse
	StopMaxTokens    = ir.StopMaxTokens
	StopStopSequence = ir.StopStopSequence
	StopRefusal      = ir.StopRefusal

	EventMessageStart   = ir.EventMessageStart
	EventBlockStart     = ir.EventBlockStart
	EventTextDelta      = ir.EventTextDelta
	EventArgsDelta      = ir.EventArgsDelta
	EventThinkingDelta  = ir.EventThinkingDelta
	EventSignatureDelta = ir.EventSignatureDelta
	EventBlockStop      = ir.EventBlockStop
	EventMessageDelta   = ir.EventMessageDelta
	EventMessageStop    = ir.EventMessageStop
)

// UserText is a one-block user turn.
func UserText(text string) Message {
	return Message{Role: RoleUser, Blocks: []Block{{Type: BlockText, Text: text}}}
}

// AssistantText is a one-block assistant turn.
func AssistantText(text string) Message {
	return Message{Role: RoleAssistant, Blocks: []Block{{Type: BlockText, Text: text}}}
}

// generatePath is the gateway's native inference surface.
const generatePath = "/lux/v1/generate"

// countTokensPath is the gateway's native token-counting surface.
const countTokensPath = "/lux/v1/count_tokens"

// The gateway's header names, as lux/gateway/errors.go declares them.
const (
	// lossHeader carries the backend-leg translation loss report,
	// comma separated.
	lossHeader = "Lux-Loss"

	// estimatedHeader is "true" on a count_tokens answer that is a
	// heuristic estimate (the target has no native counting endpoint)
	// rather than an exact tokenizer count.
	estimatedHeader = "Lux-Estimated"

	// labelsHeader carries the request's own labels, which the gateway
	// records for reporting and nothing else.
	labelsHeader = "Lux-Labels"
)

// TokenSource supplies a fresh bearer per call: a Key value on
// [Client], whatever the endpoint takes on [Direct]. It is for a
// credential that rotates; it does not make a Latere Auth token one the
// gateway accepts.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Option configures a [Client] or a [Direct] caller.
type Option func(*settings)

// settings is the option state shared by both caller kinds.
type settings struct {
	apiKey   string
	tokens   TokenSource
	hc       *http.Client
	oauth    bool
	costTags map[string]string
}

func applyOptions(opts []Option) settings {
	s := settings{hc: otel.HTTPClient()}
	for _, o := range opts {
		o(&s)
	}
	return s
}

// WithAPIKey authenticates with a static credential: a Lux virtual
// key on [Client], the provider's API key on [Direct].
func WithAPIKey(key string) Option {
	return func(s *settings) { s.apiKey = key }
}

// WithTokenSource authenticates each call with a token from ts.
func WithTokenSource(ts TokenSource) Option {
	return func(s *settings) { s.tokens = ts }
}

// WithHTTPClient overrides the underlying HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(s *settings) { s.hc = hc }
}

// WithCostTags labels every call (e.g. {"tenant": "acme", "project":
// "web"}), sent as the Lux-Labels header on Generate, Stream, and
// CountTokens. The gateway records the pairs as the request's own
// labels, readable in its request history (GET /v1/requests) and for
// reporting only: they are never an aggregate dimension of usage,
// never split a budget or a bill, and never change what the Key can
// reach. Gateway [Client] only; a nil or empty map sends no header.
//
// The gateway keeps a pair whose key is 1 to 64 characters of
// [A-Za-z0-9._-] and whose value is 1 to 128 characters of
// [A-Za-z0-9._:/-], up to 8 pairs: the first 8 such pairs in sorted key
// order. It drops every other pair and still serves the request, so a
// bad pair costs its label, never the call. A key or value holding ','
// or '=' breaks the wire form: the gateway reads it as other pairs or
// drops it.
func WithCostTags(tags map[string]string) Option {
	return func(s *settings) { s.costTags = tags }
}

// WithOAuthToken marks the credential as an OAuth access token
// ([Direct] with [ProviderAnthropic] only): it travels as
// "Authorization: Bearer" with the OAuth beta header instead of
// x-api-key.
func WithOAuthToken() Option {
	return func(s *settings) { s.oauth = true }
}

// Caller is the call surface shared by the gateway [Client] and the
// provider-direct [Direct].
type Caller interface {
	Generate(ctx context.Context, req *Request) (*Result, error)
	Stream(ctx context.Context, req *Request) (*Stream, error)
}

// Client calls one Lux deployment.
type Client struct {
	baseURL  string
	apiKey   string
	tokens   TokenSource
	hc       *http.Client
	costTags map[string]string
}

// Environment fallbacks for the two values a native-dialect call needs.
// They apply only to what the caller left unset, so an explicit
// argument can never be overridden by the process environment.
const (
	// EnvBaseURL names the gateway, e.g. https://api.latere.ai/v1/models. It is
	// deliberately not LUX_API_URL: that is the latere CLI's own target,
	// and one variable steering both would let `eval "$(latere lux env
	// lux)"` silently retarget the CLI from a subshell.
	EnvBaseURL = "LUX_BASE_URL"
	// EnvAPIKey carries exactly what Authorization: Bearer carries: a
	// Key value, a minted lux_* key or one a platform registered.
	EnvAPIKey = "LUX_API_KEY"
)

// DefaultBaseURL is Latere's Lux deployment, served under the platform
// origin's /v1/models, used when neither an explicit baseURL nor
// [EnvBaseURL] is set. The native dialect's routes are paths under it.
const DefaultBaseURL = "https://api.latere.ai/v1/models"

// New returns a client for the Lux deployment at baseURL.
//
// An empty baseURL resolves from [EnvBaseURL], then [DefaultBaseURL].
// Omitting both [WithAPIKey] and [WithTokenSource] resolves the
// credential from [EnvAPIKey]. An unset credential stays unset rather
// than defaulting to unauthenticated, so a misspelled variable name
// fails at the gateway instead of silently becoming an anonymous call.
func New(baseURL string, opts ...Option) *Client {
	s := applyOptions(opts)
	if baseURL == "" {
		baseURL = os.Getenv(EnvBaseURL)
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if s.apiKey == "" && s.tokens == nil {
		s.apiKey = os.Getenv(EnvAPIKey)
	}
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   s.apiKey,
		tokens:   s.tokens,
		hc:       s.hc,
		costTags: s.costTags,
	}
}

// Error is a non-2xx answer. From [Client] it is decoded from the
// gateway's error envelope
// {"error":{"code","message","details":{"detail","request_id"}}}; from
// [Direct], from the provider's error.type and error.message.
type Error struct {
	Status int    // HTTP status
	Code   string // error.code, e.g. rate_limited or model_not_found
	// Message is error.message, the code's one fixed user sentence; for
	// a body that is not the envelope, the body itself.
	Message string
	// RequestID is error.details.request_id, the id to quote when
	// asking about the request.
	RequestID string
	// Detail is error.details.detail, the developer's account of this
	// one failure, e.g. `no Model named "x"`; empty when the gateway
	// sent none.
	Detail string
}

// Error implements error. It is a developer line: the status, the
// code, the message, and the detail and request id when present.
func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "lux: %d", e.Status)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	b.WriteString(": " + e.Message)
	if e.Detail != "" {
		b.WriteString(" (" + e.Detail + ")")
	}
	if e.RequestID != "" {
		b.WriteString(" [" + e.RequestID + "]")
	}
	return b.String()
}

// Result is a completed non-streaming call.
type Result struct {
	Response
	// Loss lists request fields the backend dialect could not
	// represent (empty when the target speaks the full IR).
	Loss []string
}

// Generate performs a non-streaming call. The request's Stream flag
// is overridden to false.
func (c *Client) Generate(ctx context.Context, req *Request) (*Result, error) {
	resp, err := c.post(ctx, req, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("lux: reading response: %w", err)
	}
	out := &Result{Loss: parseLoss(resp.Header)}
	if err := json.Unmarshal(body, &out.Response); err != nil {
		return nil, fmt.Errorf("lux: invalid response JSON: %w", err)
	}
	return out, nil
}

// TokenCount is a count_tokens answer. Estimated marks a heuristic
// (order-of-magnitude) count for targets with no native counting
// endpoint; exact counts come from the provider's tokenizer.
type TokenCount struct {
	InputTokens int64 `json:"input_tokens"`
	Estimated   bool  `json:"-"`
}

// CountTokens returns the input token count for req without spending
// output tokens. Counting runs no spend gates.
func (c *Client) CountTokens(ctx context.Context, req *Request) (*TokenCount, error) {
	wire := *req
	wire.Stream = false
	body, err := json.Marshal(&wire)
	if err != nil {
		return nil, fmt.Errorf("lux: encoding request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+countTokensPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	bearer := c.apiKey
	if c.tokens != nil {
		if bearer, err = c.tokens.Token(ctx); err != nil {
			return nil, fmt.Errorf("lux: token source: %w", err)
		}
	}
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}
	if tags := formatCostTags(c.costTags); tags != "" {
		httpReq.Header.Set(labelsHeader, tags)
	}
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("lux: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp)
	}
	out := &TokenCount{Estimated: resp.Header.Get(estimatedHeader) == "true"}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, fmt.Errorf("lux: invalid response JSON: %w", err)
	}
	return out, nil
}

// Stream performs a streaming call. The request's Stream flag is
// overridden to true. The caller must Close the returned stream.
func (c *Client) Stream(ctx context.Context, req *Request) (*Stream, error) {
	resp, err := c.post(ctx, req, true)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return nil, decodeError(resp)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/event-stream" {
		defer func() { _ = resp.Body.Close() }()
		return nil, fmt.Errorf("lux: expected an event stream, got %q", resp.Header.Get("Content-Type"))
	}
	r := lux.NewStreamReader(resp.Body)
	return &Stream{
		next:   r.Next,
		closer: resp.Body.Close,
		loss:   parseLoss(resp.Header),
	}, nil
}

func (c *Client) post(ctx context.Context, req *Request, stream bool) (*http.Response, error) {
	wire := *req
	wire.Stream = stream
	body, err := json.Marshal(&wire)
	if err != nil {
		return nil, fmt.Errorf("lux: encoding request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+generatePath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	bearer := c.apiKey
	if c.tokens != nil {
		bearer, err = c.tokens.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("lux: token source: %w", err)
		}
	}
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}
	if tags := formatCostTags(c.costTags); tags != "" {
		httpReq.Header.Set(labelsHeader, tags)
	}
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("lux: %w", err)
	}
	return resp, nil
}

// formatCostTags serializes tags to the Lux-Labels wire form: sorted
// key=value pairs joined by commas, no spaces. A nil or empty map
// yields "".
func formatCostTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	var b strings.Builder
	for i, k := range slices.Sorted(maps.Keys(tags)) {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(tags[k])
	}
	return b.String()
}

// decodeError reads a gateway answer that is not 2xx: the lux door's
// envelope {"error":{"code","message","details":{"detail","request_id"}}},
// parsed with the same bridge codec the gateway writes it with.
func decodeError(resp *http.Response) error {
	return readError(resp, func(body []byte) (bridge.Failure, bool) {
		return bridge.ParseEnvelope(bridge.WireLux, body)
	})
}

// decodeProviderError reads a provider's answer that is not 2xx, for
// [Direct]: error.type and error.message, the members the Anthropic and
// OpenAI shapes share.
func decodeProviderError(resp *http.Response) error {
	return readError(resp, func(body []byte) (bridge.Failure, bool) {
		var wire struct {
			Error struct {
				Type      string `json:"type"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &wire) != nil || (wire.Error.Type == "" && wire.Error.Message == "") {
			return bridge.Failure{}, false
		}
		return bridge.Failure{Code: wire.Error.Type, Message: wire.Error.Message, RequestID: wire.Error.RequestID}, true
	})
}

// readError decodes the body of resp into *Error with parse; a body
// parse does not recognize degrades to the raw bytes as the message.
func readError(resp *http.Response, parse func([]byte) (bridge.Failure, bool)) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := &Error{Status: resp.StatusCode}
	f, ok := parse(body)
	if !ok {
		out.Message = strings.TrimSpace(string(body))
		return out
	}
	out.Code = f.Code
	out.Message = f.Message
	out.RequestID = f.RequestID
	out.Detail = f.Detail
	return out
}

func parseLoss(h http.Header) []string {
	v := h.Get(lossHeader)
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

// Stream is a live event stream. Next returns io.EOF after the final
// event, and io.ErrUnexpectedEOF if the stream ends before message_stop;
// a mid-stream gateway failure surfaces as *StreamError.
type Stream struct {
	next   func() (Event, error)
	closer func() error
	loss   []string
}

// Next returns the next event.
func (s *Stream) Next() (Event, error) { return s.next() }

// Loss lists request fields the backend dialect could not represent.
func (s *Stream) Loss() []string { return s.loss }

// Close releases the underlying connection.
func (s *Stream) Close() error { return s.closer() }
