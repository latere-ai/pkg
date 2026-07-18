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

// lossHeader carries the backend-leg translation loss report.
const lossHeader = "X-Lux-Compat-Loss"

// TokenSource supplies a fresh bearer per call (Latere Auth JWTs).
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey authenticates with a static bearer (a Lux virtual key).
func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = key }
}

// WithTokenSource authenticates each call with a token from ts.
func WithTokenSource(ts TokenSource) Option {
	return func(c *Client) { c.tokens = ts }
}

// WithHTTPClient overrides the underlying HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.hc = hc }
}

// Client calls one Lux deployment.
type Client struct {
	baseURL string
	apiKey  string
	tokens  TokenSource
	hc      *http.Client
}

// New returns a client for the Lux deployment at baseURL.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		hc:      http.DefaultClient,
	}
	for _, o := range opts {
		o(c)
	}
	return c
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
	return &Stream{
		body: resp.Body,
		r:    lux.NewStreamReader(resp.Body),
		loss: parseLoss(resp.Header),
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
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("lux: %w", err)
	}
	return resp, nil
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
	body io.ReadCloser
	r    *lux.StreamReader
	loss []string
}

// Next returns the next event.
func (s *Stream) Next() (Event, error) { return s.r.Next() }

// Loss lists request fields the backend dialect could not represent.
func (s *Stream) Loss() []string { return s.loss }

// Close releases the underlying connection.
func (s *Stream) Close() error { return s.body.Close() }
