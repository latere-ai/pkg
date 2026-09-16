// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"latere.ai/x/pkg/cache"
)

// Unavailable is a call that produced no decision: the authorizer timed
// out, refused the connection after the retry, answered another status
// than 200, or sent a body that does not parse. A core fails closed on it.
type Unavailable struct {
	URL    string
	Status int
	Err    error
}

func (u *Unavailable) Error() string {
	if u.Err != nil {
		return "authz: authorizer unavailable: " + u.Err.Error()
	}
	return fmt.Sprintf("authz: authorizer answered %d", u.Status)
}

func (u *Unavailable) Unwrap() error { return u.Err }

// The bounds of one answer body: a decision is a few short fields, and a
// core's own answer shape, a directory page, fits well under a megabyte.
const (
	maxDecisionBytes = 64 << 10
	maxAnswerBytes   = 1 << 20
	attempts         = 2
)

// Options configures a Client.
type Options struct {
	// URL is the authorizer endpoint and Token the bearer it requires.
	URL   string
	Token string
	// HTTP sends the calls. Required; a core passes its instrumented
	// client.
	HTTP *http.Client
	// Timeout bounds one call, the retry included. Timeout when zero.
	Timeout time.Duration
	// Now is the clock the cache runs on.
	Now func() time.Time
	// Observe receives every call's result, allow, deny, or error, and
	// its duration in seconds, for the core's metric. Optional.
	Observe func(result string, seconds float64)
	// Vocabulary is the core's action table. When it names an action,
	// Authorize refuses one outside it before the wire, so a typo is
	// caught by a core's own tests rather than by a round trip in
	// production. Optional: the zero vocabulary validates nothing, which
	// is how a client with no table declared behaves.
	Vocabulary Vocabulary
}

// UnknownAction is a request whose action the client's vocabulary does
// not name. It is a mistake in the core, not an outage at the endpoint:
// it is no *Unavailable, [Retryable] reports false for it, and no call
// was made.
type UnknownAction struct {
	Core   string
	Action string
}

func (e *UnknownAction) Error() string {
	return fmt.Sprintf("authz: %q is not one of %s's actions", e.Action, e.Core)
}

// Client is the authorizer client: one call per decision, one retry when
// the connection failed before a response line arrived, and a cache per
// (subject, action, resource id).
type Client struct {
	url     string
	token   string
	http    *http.Client
	timeout time.Duration
	now     func() time.Time
	observe func(string, float64)
	vocab   Vocabulary
	cache   *cache.TTLCache[cacheKey, cached]
}

type cacheKey struct {
	subject, action, resource string
}

type cached struct {
	decision Decision
	until    time.Time
}

// NewClient builds the client. It sends nothing.
func NewClient(o Options) (*Client, error) {
	if o.HTTP == nil {
		return nil, errors.New("authz: the client needs an HTTP client")
	}
	if o.URL == "" {
		return nil, errors.New("authz: the client needs a URL")
	}
	c := &Client{url: o.URL, token: o.Token, http: o.HTTP, timeout: o.Timeout, now: o.Now, observe: o.Observe, vocab: o.Vocabulary}
	if c.timeout == 0 {
		c.timeout = Timeout
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.observe == nil {
		c.observe = func(string, float64) {}
	}
	c.cache = cache.New[cacheKey, cached](MaxTTL, cache.WithMaxSize[cacheKey, cached](CacheEntries), cache.WithClock[cacheKey, cached](c.now))
	return c, nil
}

// URL is the endpoint the client asks.
func (c *Client) URL() string { return c.url }

// Authorize answers from the cache or asks the authorizer. An allow is
// cached for its ttl, a deny for DenyTTL, an unavailable answer never. An
// answer about a resource with no id is never cached: it is a creation or
// an unresolved name, and neither names a key to remember it by.
//
// An action outside the configured vocabulary is an *UnknownAction before
// anything is sent, read from the cache, or observed. [Client.Ask] does
// not validate: it carries the actions whose answer is the core's own,
// and a core that wants them checked names them in the vocabulary and
// asks through Authorize.
func (c *Client) Authorize(ctx context.Context, req Request) (Decision, error) {
	if len(c.vocab.Actions) > 0 && !c.vocab.Known(req.Action) {
		return Decision{}, &UnknownAction{Core: c.vocab.Core, Action: req.Action}
	}
	key := cacheKey{req.Subject, req.Action, req.Resource.ID}
	now := c.now()
	if req.Resource.ID != "" {
		if e, ok := c.cache.Get(key); ok && now.Before(e.until) {
			return e.decision, nil
		}
	}
	start := time.Now()
	raw, err := c.Ask(ctx, req)
	var d Decision
	if err == nil {
		d, err = c.decision(raw)
	}
	result := "allow"
	switch {
	case err != nil:
		result = "error"
	case !d.Allow:
		result = "deny"
	}
	c.observe(result, time.Since(start).Seconds())
	if err != nil {
		return Decision{}, err
	}
	if req.Resource.ID != "" {
		ttl := DenyTTL
		if d.Allow {
			ttl = d.TTL
		}
		c.cache.Set(key, cached{decision: d, until: now.Add(ttl)})
	}
	return d, nil
}

// Ask posts the envelope and returns the bytes of a 200, uncached, under
// the same timeout, retry, and failure rules as Authorize. It is for an
// action whose answer has a shape of the core's own, such as a directory
// page; every other outcome than a 200 is an *Unavailable.
func (c *Client) Ask(ctx context.Context, req Request) ([]byte, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, &Unavailable{URL: c.url, Err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var last error
	for range attempts {
		raw, err := c.once(ctx, body)
		if err == nil {
			return raw, nil
		}
		last = err
		if !Retryable(err) {
			break
		}
	}
	return nil, last
}

func (c *Client) once(ctx context.Context, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, &Unavailable{URL: c.url, Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &Unavailable{URL: c.url, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &Unavailable{URL: c.url, Status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err != nil {
		return nil, &Unavailable{URL: c.url, Status: resp.StatusCode, Err: err}
	}
	return raw, nil
}

// decision parses a 200 body as a decision. A body over the decision
// bound or with no allow field is no answer.
func (c *Client) decision(raw []byte) (Decision, error) {
	if len(raw) > maxDecisionBytes {
		return Decision{}, &Unavailable{URL: c.url, Status: http.StatusOK, Err: errors.New("body: over the decision bound")}
	}
	d, err := ParseDecision(raw)
	if err != nil {
		return Decision{}, &Unavailable{URL: c.url, Status: http.StatusOK, Err: err}
	}
	return d, nil
}

// CacheLen reports the cache's size, for a test.
func (c *Client) CacheLen() int { return c.cache.Len() }

// serverClosedIdle is the text of net/http's errServerClosedIdle: the
// peer's FIN was seen before the request was registered on the
// connection. The sentinel is unexported and undecorated, so the string
// is the only handle.
const serverClosedIdle = "http: server closed idle connection"

// Retryable reports whether a call failed before a response line
// arrived: a refused or reset connection, a dial timeout, or a connection
// closed without a response. A timeout after the request was sent, a
// non-200, and a body that does not parse are not, and are never retried.
func Retryable(err error) bool {
	var u *Unavailable
	if !errors.As(err, &u) || u.Err == nil || u.Status != 0 {
		return false
	}
	var op *net.OpError
	if errors.As(u.Err, &op) && op.Op == "dial" {
		return true
	}
	if errors.Is(u.Err, context.DeadlineExceeded) || errors.Is(u.Err, context.Canceled) {
		return false
	}
	return errors.Is(u.Err, syscall.ECONNRESET) || errors.Is(u.Err, syscall.ECONNREFUSED) ||
		errors.Is(u.Err, io.EOF) || errors.Is(u.Err, io.ErrUnexpectedEOF) || isServerClosedIdle(u.Err)
}

func isServerClosedIdle(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if e.Error() == serverClosedIdle {
			return true
		}
	}
	return false
}
