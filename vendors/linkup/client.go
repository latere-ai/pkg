// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package linkup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"latere.ai/x/pkg/otel"
)

// The client's defaults, each replaced by an Option.
const (
	// DefaultBaseURL is the API root requests go to.
	DefaultBaseURL = "https://api.linkup.so"
	// DefaultTimeout bounds one search, from sending the request to reading
	// the last byte of the answer. Linkup gives a deep search up to 30
	// seconds; the default leaves room above that.
	DefaultTimeout = 60 * time.Second
)

// searchPath is the search endpoint under the API root.
const searchPath = "/v1/search"

// The most bytes read of an answer. A success body is the caller's data and
// may hold the text of many pages; a failure body is untrusted in size, and a
// gateway in front of the API can answer with a whole HTML page.
const (
	maxResponseBody = 32 << 20
	maxErrorBody    = 64 << 10
)

// Client is a connection to the Linkup API with one API key. It is safe for
// concurrent use: every field is set by New and only read afterwards. The
// zero Client is not usable; build one with New.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
	timeout time.Duration
}

// Option changes one setting of a Client.
type Option func(*Client)

// WithBaseURL sends requests to a different API root, such as a test server.
// A trailing slash is trimmed. An empty or whitespace-only value is ignored.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		if value := strings.TrimSpace(baseURL); value != "" {
			c.baseURL = value
		}
	}
}

// WithHTTPClient sends requests through the given HTTP client, which is where
// a proxy or a custom transport is configured. A nil client is ignored; the
// default is otel.HTTPClient, whose transport carries the trace context.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.http = httpClient
		}
	}
}

// WithTimeout bounds one search, replacing DefaultTimeout. A non-positive
// duration removes the bound and leaves the caller's context as the only
// deadline.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) { c.timeout = timeout }
}

// New builds a client with the given API key. A key that is empty or
// whitespace-only is an error, because every search needs one.
func New(apiKey string, opts ...Option) (*Client, error) {
	c := &Client{
		baseURL: DefaultBaseURL,
		apiKey:  strings.TrimSpace(apiKey),
		http:    otel.HTTPClient(),
		timeout: DefaultTimeout,
	}
	if c.apiKey == "" {
		return nil, errors.New("linkup: no API key")
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	c.baseURL = strings.TrimRight(c.baseURL, "/")
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("linkup: base URL %q: %w", c.baseURL, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("linkup: base URL %q needs a scheme and a host", c.baseURL)
	}
	return c, nil
}

// Search runs one search and returns the answer its OutputType shapes.
//
// A request missing a required field is refused before it is sent, matching
// ErrBadRequest. A status other than 200 is an *Error. A 200 whose body is
// not the documented shape for the output type matches ErrUpstream. A
// transport failure or an ended context is returned wrapped.
func (c *Client) Search(ctx context.Context, req Request) (Response, error) {
	body, err := req.encode()
	if err != nil {
		return Response{}, err
	}
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+searchPath, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("linkup: building the search request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("linkup: search: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		apiErr := newError(resp.StatusCode, resp.Header, raw, c.apiKey)
		if readErr != nil {
			return Response{}, fmt.Errorf("%w; reading its body: %w", apiErr, contextCause(ctx, readErr))
		}
		return Response{}, apiErr
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return Response{}, fmt.Errorf("linkup: reading the search response: %w", contextCause(ctx, err))
	}
	if len(raw) > maxResponseBody {
		return Response{}, fmt.Errorf("%w: the search response passed %d bytes", ErrUpstream, maxResponseBody)
	}
	return decodeResponse(raw, req)
}

// contextCause adds the context's own error to a failed body read when the
// context ended, so errors.Is reaches context.Canceled or
// context.DeadlineExceeded whatever the transport reported for the read.
func contextCause(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	return err
}
