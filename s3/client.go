// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"latere.ai/x/pkg/retry"
	"latere.ai/x/pkg/s3/internal/sigv4"
)

// Client addresses one bucket at one endpoint with one credential. It is
// safe for concurrent use.
type Client struct {
	endpoint  *url.URL
	bucket    string
	signer    sigv4.Signer
	pathStyle bool
	client    *http.Client
	policy    retry.Policy
	now       func() time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithPathStyle addresses the bucket as the first path segment
// (endpoint/bucket/key) rather than as a host label (bucket.endpoint).
// MinIO and any endpoint reached by IP address need it.
func WithPathStyle() Option {
	return func(c *Client) { c.pathStyle = true }
}

// WithHTTPClient sends every request through hc, which is how a service
// passes its instrumented client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.client = hc }
}

// WithRetry sets the policy for a 5xx, a 429, or a transport failure.
// The default is three attempts from 50ms.
func WithRetry(p retry.Policy) Option {
	return func(c *Client) { c.policy = p }
}

// DefaultRetry is the policy without WithRetry.
var DefaultRetry = retry.Policy{MaxAttempts: 3, Base: 50 * time.Millisecond, Max: 2 * time.Second}

// New validates the parameters and returns the client. It sends nothing.
func New(endpoint, region, bucket, key, secret string, opts ...Option) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("s3: endpoint %q is not an absolute URL", endpoint)
	}
	if bucket == "" || region == "" || key == "" || secret == "" {
		return nil, errors.New("s3: bucket, region, key, and secret are required")
	}
	c := &Client{
		endpoint: u, bucket: bucket,
		signer: sigv4.Signer{Key: key, Secret: secret, Region: region},
		policy: DefaultRetry, now: time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	if c.client == nil {
		c.client = &http.Client{Transport: defaultTransport()}
	}
	return c, nil
}

// defaultTransport is a clone of the process default, so a consumer that
// tunes http.DefaultTransport before New gets its settings and one that
// tunes it after does not reach into this client.
func defaultTransport() http.RoundTripper {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}
	return http.DefaultTransport
}

// objectURL builds the request URL for key. The path is escaped the way
// the signature expects, so the request line and the canonical URI agree.
// An empty key addresses the bucket, which a listing does.
func (c *Client) objectURL(key string, query url.Values) *url.URL {
	u := *c.endpoint
	segments := []string{}
	if c.pathStyle {
		segments = append(segments, c.bucket)
	} else {
		u.Host = c.bucket + "." + u.Host
	}
	if key != "" {
		segments = append(segments, strings.Split(key, "/")...)
	}
	escaped := make([]string, len(segments))
	for i, seg := range segments {
		escaped[i] = sigv4.Escape(seg)
	}
	u.Path = "/" + strings.Join(segments, "/")
	u.RawPath = "/" + strings.Join(escaped, "/")
	if key == "" && len(segments) > 0 {
		u.Path += "/"
		u.RawPath += "/"
	}
	u.RawQuery = sigv4.CanonicalQuery(query)
	return &u
}

// request is one attempt-independent description of a call.
type request struct {
	method  string
	key     string
	query   url.Values
	headers map[string]string
	body    *Body
}

// do sends the request under the retry policy. The response is returned
// with its body open when its status is one of accept; any other status
// is an *Error. A 5xx, a 429, or a transport failure is retried, a 4xx
// is returned at once.
func (c *Client) do(ctx context.Context, r request, accept ...int) (*http.Response, error) {
	var resp *http.Response
	attempts := 0
	err := retry.Do(ctx, c.policy, func(ctx context.Context) error {
		attempts++
		var err error
		resp, err = c.once(ctx, r) //nolint:bodyclose // an accepted response is returned open for the caller; a refused one is closed below
		if err != nil {
			return err
		}
		if slices.Contains(accept, resp.StatusCode) {
			return nil
		}
		rerr := responseError(resp)
		_ = resp.Body.Close()
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return retry.Stop(rerr)
		}
		return rerr
	})
	if err == nil {
		return resp, nil
	}
	if attempts >= c.policy.Attempts() && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("s3: %s %s failed after %d attempts: %w", r.method, r.key, attempts, err)
	}
	return nil, err
}

func (c *Client) once(ctx context.Context, r request) (*http.Response, error) {
	var body io.Reader
	payloadHash := sigv4.EmptyPayloadHash
	var size int64
	if r.body != nil {
		rc, err := r.body.Open()
		if err != nil {
			return nil, retry.Stop(err)
		}
		defer func() { _ = rc.Close() }()
		body = rc
		size = r.body.Size
		payloadHash = r.body.SHA256
		if payloadHash == "" {
			payloadHash = sigv4.UnsignedPayload
		}
	}
	req, err := http.NewRequestWithContext(ctx, r.method, c.objectURL(r.key, r.query).String(), body)
	if err != nil {
		return nil, retry.Stop(err)
	}
	if r.body != nil {
		req.ContentLength = size
		if r.body.MD5 != "" {
			req.Header.Set("Content-MD5", r.body.MD5)
		}
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	c.signer.Sign(req, payloadHash, c.now())
	return c.client.Do(req)
}
