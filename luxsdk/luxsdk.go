// Package luxsdk is the first-party Go client for the Latere Lux
// gateway's native dialect (spec lux/33): one typed request /
// response / streaming shape, POST /lux/v1/generate, any provider Lux
// routes to. Authenticate with a Lux virtual key or a Latere Auth
// bearer; both travel as Authorization: Bearer.
//
//	c := luxsdk.New("https://lux.latere.ai", luxsdk.WithAPIKey(key))
//	res, err := c.Generate(ctx, &luxsdk.Request{
//		Model:    "claude-sonnet-5",
//		Messages: []luxsdk.Message{luxsdk.UserText("hello")},
//	})
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
	"mime"
	"net/http"
	"sort"
	"strings"

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
	Tool           = lux.Tool
	ToolChoice     = lux.ToolChoice
	Reasoning      = lux.Reasoning
	ResponseSchema = lux.ResponseSchema
	Usage          = lux.Usage
	Event          = lux.Event
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

// lossHeader carries the backend-leg translation loss report.
const lossHeader = "X-Lux-Compat-Loss"

// estimatedHeader marks a count_tokens answer as a heuristic estimate
// (the target has no native counting endpoint) rather than an exact
// tokenizer count.
const estimatedHeader = "X-Lux-Compat-Estimated"

// costTagHeader carries cost-attribution tags: a call's cost is split
// across named dimensions within the caller's own spend.
const costTagHeader = "Lux-Cost-Tag"

// TokenSource supplies a fresh bearer per call (Latere Auth JWTs).
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
	s := settings{hc: http.DefaultClient}
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

// WithCostTags attributes every call's cost to named dimensions within
// the caller's own spend (e.g. {"tenant": "acme", "project": "web"}),
// sent as the Lux-Cost-Tag header. It never changes the billing owner
// or what the key can reach. Gateway [Client] only; a nil or empty map
// sends no header. The gateway validates the value.
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

// New returns a client for the Lux deployment at baseURL.
func New(baseURL string, opts ...Option) *Client {
	s := applyOptions(opts)
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   s.apiKey,
		tokens:   s.tokens,
		hc:       s.hc,
		costTags: s.costTags,
	}
}

// Error is a non-2xx gateway response, decoded from the error
// envelope.
type Error struct {
	Status    int    // HTTP status
	Code      string // envelope error type, e.g. rate_limit_error
	Message   string
	RequestID string
}

// Error implements error.
func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("lux: %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("lux: %d %s: %s", e.Status, e.Code, e.Message)
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
	defer resp.Body.Close()
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
		httpReq.Header.Set(costTagHeader, tags)
	}
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("lux: %w", err)
	}
	defer resp.Body.Close()
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
		defer resp.Body.Close()
		return nil, decodeError(resp)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/event-stream" {
		defer resp.Body.Close()
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
		httpReq.Header.Set(costTagHeader, tags)
	}
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("lux: %w", err)
	}
	return resp, nil
}

// formatCostTags serializes tags to the Lux-Cost-Tag wire form: sorted
// key=value pairs joined by commas, no spaces. A nil or empty map
// yields "".
func formatCostTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(tags[k])
	}
	return b.String()
}

// decodeError parses the gateway error envelope
// ({"type":"error","error":{"type","message","request_id"}}); an
// unparseable body degrades to the raw bytes as the message.
func decodeError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := &Error{Status: resp.StatusCode}
	var wire struct {
		Error struct {
			Type      string `json:"type"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || (wire.Error.Type == "" && wire.Error.Message == "") {
		out.Message = strings.TrimSpace(string(body))
		return out
	}
	out.Code = wire.Error.Type
	out.Message = wire.Error.Message
	out.RequestID = wire.Error.RequestID
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
// event; a mid-stream gateway failure surfaces as *StreamError.
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
