// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/stub"
)

const (
	repoA = "0f5c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f"
	alice = "https://iss|alice"
)

// clock is a fake clock the cache runs on.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: time.Unix(1_700_000_000, 0)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// results records what Observe was told.
type results struct {
	mu   sync.Mutex
	seen []string
}

func (r *results) observe(result string, _ float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, result)
}

func newClient(t *testing.T, url, token string, transport http.RoundTripper, clk *clock, obs *results) *authz.Client {
	t.Helper()
	o := authz.Options{URL: url, Token: token, HTTP: &http.Client{Transport: transport}, Timeout: 500 * time.Millisecond, Now: clk.Now}
	if obs != nil {
		o.Observe = obs.observe
	}
	c, err := authz.NewClient(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func request(subject, action, id string) authz.Request {
	iss, sub, _ := authz.SplitSubject(subject)
	return authz.Request{Subject: subject, Issuer: iss, Sub: sub, Claims: map[string]any{"sub": sub}, Action: action,
		Resource: authz.NewResource("Repository", id, nil), Request: authz.Caller{ID: "req-1", IP: "203.0.113.4", UserAgent: "test"}}
}

func TestClientAnswersAndCaches(t *testing.T) {
	clk := newClock()
	s := stub.New(t)
	obs := &results{}
	c := newClient(t, s.URL(), s.Token(), &http.Transport{}, clk, obs)
	ctx := context.Background()
	s.Allow(stub.Rule{Subject: alice, Resource: repoA, Action: "repo.read", TTL: 30, Limits: map[string]any{"replicas": 3, "quota_bytes": 1024}})
	s.Allow(stub.Rule{Subject: alice, Resource: repoA, Action: "repo.write", TTL: 9000})
	s.Deny(stub.Rule{Subject: "https://iss|eve"}, "not welcome")

	d, err := c.Authorize(ctx, request(alice, "repo.read", repoA))
	if err != nil || !d.Allow || d.TTL != 30*time.Second {
		t.Fatalf("allow with a ttl: %+v, %v", d, err)
	}
	var limits struct {
		Replicas   int   `json:"replicas"`
		QuotaBytes int64 `json:"quota_bytes"`
	}
	if err := d.DecodeLimits(&limits); err != nil || limits.Replicas != 3 || limits.QuotaBytes != 1024 {
		t.Fatalf("limits: %+v %v", limits, err)
	}
	if d, err = c.Authorize(ctx, request(alice, "repo.write", repoA)); err != nil || !d.Allow || d.TTL != authz.MaxTTL {
		t.Fatalf("ttl capped: %+v, %v", d, err)
	}
	if d, err = c.Authorize(ctx, request("https://iss|bob", "repo.admin", repoA)); err != nil || !d.Allow || d.TTL != authz.DefaultTTL || d.Limits != nil {
		t.Fatalf("defaults: %+v, %v", d, err)
	}
	if d, err = c.Authorize(ctx, request("https://iss|eve", "repo.read", repoA)); err != nil || d.Allow || d.Reason != "not welcome" {
		t.Fatalf("deny: %+v, %v", d, err)
	}
	got := s.Requests()
	if len(got) != 4 || got[0].Subject != alice || got[0].Issuer != "https://iss" || got[0].Sub != "alice" ||
		got[0].Claims["sub"] != "alice" || got[0].Resource.ID != repoA || got[0].Resource.Kind != "Repository" ||
		got[0].Action != "repo.read" || got[0].Request.IP != "203.0.113.4" {
		t.Fatalf("the envelope: %+v", got[0])
	}
	// Cached: the same four answer without a call, until each ttl.
	for _, r := range []authz.Request{request(alice, "repo.read", repoA), request("https://iss|bob", "repo.admin", repoA), request("https://iss|eve", "repo.read", repoA)} {
		if _, err := c.Authorize(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.Requests()) != 4 {
		t.Fatalf("cached answers called the authorizer: %d", len(s.Requests()))
	}
	clk.Advance(authz.DenyTTL + time.Second)
	if _, err := c.Authorize(ctx, request("https://iss|eve", "repo.read", repoA)); err != nil || len(s.Requests()) != 5 {
		t.Fatalf("a deny cached past 5 seconds: %v, %d", err, len(s.Requests()))
	}
	if _, err := c.Authorize(ctx, request(alice, "repo.read", repoA)); err != nil || len(s.Requests()) != 5 {
		t.Fatal("a 30 second allow expired early")
	}
	clk.Advance(30 * time.Second)
	if _, err := c.Authorize(ctx, request(alice, "repo.read", repoA)); err != nil || len(s.Requests()) != 6 {
		t.Fatal("a 30 second allow did not expire")
	}
	// An answer about a resource with no id is never cached.
	for range 2 {
		if _, err := c.Authorize(ctx, request(alice, "repo.admin", "")); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.Requests()) != 8 || c.CacheLen() != 4 {
		t.Fatalf("an unresolved name was cached: %d calls, %d entries", len(s.Requests()), c.CacheLen())
	}
	// Each cache key component alone distinguishes two calls.
	before := len(s.Requests())
	for _, r := range []authz.Request{request("https://iss|carol", "repo.read", repoA), request(alice, "repo.admin", repoA), request(alice, "repo.read", "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d")} {
		if _, err := c.Authorize(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.Requests()) != before+3 {
		t.Fatal("two calls shared a cache entry")
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if strings.Join(obs.seen[:4], ",") != "allow,allow,allow,deny" {
		t.Fatalf("observed %v", obs.seen)
	}
	if c.URL() != s.URL() {
		t.Fatal("URL")
	}
}

func TestClientFailsClosedOnEveryUnavailability(t *testing.T) {
	clk := newClock()
	s := stub.New(t)
	obs := &results{}
	c := newClient(t, s.URL(), s.Token(), &http.Transport{}, clk, obs)
	ctx := context.Background()
	req := request(alice, "repo.read", repoA)

	// A 500 is one request and never retried.
	s.Fail(http.StatusInternalServerError)
	_, err := c.Authorize(ctx, req)
	var u *authz.Unavailable
	if !errors.As(err, &u) || u.Status != 500 || len(s.Requests()) != 1 {
		t.Fatalf("500: %v, %d requests", err, len(s.Requests()))
	}
	// A bad bearer is a 401, which is an outage of the same kind.
	s.Fail(0)
	wrong := newClient(t, s.URL(), "wrong", &http.Transport{}, clk, nil)
	if _, err := wrong.Authorize(ctx, req); !errors.As(err, &u) || u.Status != 401 {
		t.Fatalf("401: %v", err)
	}
	// A hang is abandoned at the timeout, and not retried.
	s.Hang()
	s.ClearRequests()
	start := time.Now()
	_, err = c.Authorize(ctx, req)
	if !errors.As(err, &u) || time.Since(start) > 3*time.Second || len(s.Requests()) != 1 {
		t.Fatalf("hang: %v after %s, %d requests", err, time.Since(start), len(s.Requests()))
	}
	s.Resume()
	// Nothing of the outage was cached: the first request after it is
	// served.
	if d, err := c.Authorize(ctx, req); err != nil || !d.Allow {
		t.Fatalf("recovery: %+v %v", d, err)
	}
	// A body with no verdict, and one that does not parse.
	for _, body := range []string{`{"reason":"?"}`, `{`, strings.Repeat("x", 70<<10)} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
		bad := newClient(t, srv.URL, "t", &http.Transport{}, clk, nil)
		if _, err := bad.Authorize(ctx, req); !errors.As(err, &u) || u.Status != 200 || u.Err == nil {
			t.Fatalf("body %q: %v", body[:min(len(body), 10)], err)
		}
		srv.Close()
	}
	// A refused connection is retried once and then fails closed.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	dials := &countingTransport{next: &http.Transport{}}
	refused := newClient(t, "http://"+addr, "t", dials, clk, obs)
	if _, err := refused.Authorize(ctx, req); !errors.As(err, &u) || !authz.Retryable(err) || dials.attempts.Load() != 2 {
		t.Fatalf("refused connection: %v after %d attempts", err, dials.attempts.Load())
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if obs.seen[0] != "error" || obs.seen[len(obs.seen)-1] != "error" {
		t.Fatalf("observed %v", obs.seen)
	}
}

type countingTransport struct {
	next     http.RoundTripper
	attempts atomic.Int64
}

func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.attempts.Add(1)
	return t.next.RoundTrip(r)
}

// TestClosedConnectionIsRetried forces the one retry the contract allows: a
// peer that closes the connection before any response byte.
func TestClosedConnectionIsRetried(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			if accepted.Add(1) == 1 {
				_ = conn.Close()
				continue
			}
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{\"allow\":true}")
			_ = conn.Close()
		}
	}()
	c := newClient(t, "http://"+l.Addr().String(), "t", &http.Transport{DisableKeepAlives: true}, newClock(), nil)
	d, err := c.Authorize(context.Background(), request(alice, "repo.read", repoA))
	if err != nil || !d.Allow || accepted.Load() != 2 {
		t.Fatalf("retry after a closed connection: %+v %v, %d connections", d, err, accepted.Load())
	}
}

func TestRetryableNamesTheOneClass(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{&authz.Unavailable{Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}, true},
		{&authz.Unavailable{Err: syscall.ECONNRESET}, true},
		{&authz.Unavailable{Err: io.EOF}, true},
		{&authz.Unavailable{Err: io.ErrUnexpectedEOF}, true},
		{&authz.Unavailable{Err: errors.New("http: server closed idle connection")}, true},
		{&authz.Unavailable{Err: context.DeadlineExceeded}, false},
		{&authz.Unavailable{Err: context.Canceled}, false},
		{&authz.Unavailable{Status: 500}, false},
		{&authz.Unavailable{Status: 200, Err: io.EOF}, false},
		{&authz.Unavailable{Err: errors.New("other")}, false},
		{errors.New("not unavailable"), false},
	} {
		if got := authz.Retryable(tc.err); got != tc.want {
			t.Errorf("Retryable(%v) = %v", tc.err, got)
		}
	}
}

func TestAskReturnsACoresOwnAnswer(t *testing.T) {
	s := stub.New(t, stub.WithAction("repo.list", func(req authz.Request) any {
		return map[string]any{"repos": []string{req.Subject}, "next_cursor": req.Resource.String("cursor")}
	}))
	c := newClient(t, s.URL(), s.Token(), &http.Transport{}, newClock(), nil)
	req := request(alice, "repo.list", "")
	req.Resource = authz.NewResource("Repository", "", map[string]any{"cursor": "c1", "limit": 50})
	raw, err := c.Ask(context.Background(), req)
	if err != nil || !strings.Contains(string(raw), `"next_cursor":"c1"`) || !strings.Contains(string(raw), alice) {
		t.Fatalf("ask: %s %v", raw, err)
	}
	if got := s.Requests(); len(got) != 1 || got[0].Resource.Int("limit") != 50 {
		t.Fatalf("recorded: %+v", got)
	}
	// Ask is never cached, and fails closed the same way.
	if _, err := c.Ask(context.Background(), req); err != nil || len(s.Requests()) != 2 {
		t.Fatal("ask was cached")
	}
	s.Fail(http.StatusBadGateway)
	var u *authz.Unavailable
	if _, err := c.Ask(context.Background(), req); !errors.As(err, &u) || u.Status != 502 {
		t.Fatalf("ask under an outage: %v", err)
	}
}

func TestNewClientNeedsAClientAndAURL(t *testing.T) {
	if _, err := authz.NewClient(authz.Options{URL: "http://x"}); err == nil {
		t.Fatal("no HTTP client")
	}
	if _, err := authz.NewClient(authz.Options{HTTP: http.DefaultClient}); err == nil {
		t.Fatal("no URL")
	}
	c, err := authz.NewClient(authz.Options{HTTP: http.DefaultClient, URL: "http://x"})
	if err != nil || c.CacheLen() != 0 {
		t.Fatal(err)
	}
	// A URL the request cannot be built from is an outage, not a panic.
	bad, _ := authz.NewClient(authz.Options{HTTP: http.DefaultClient, URL: "::not a url"})
	var u *authz.Unavailable
	if _, err := bad.Authorize(context.Background(), request(alice, "repo.read", repoA)); !errors.As(err, &u) {
		t.Fatalf("bad url: %v", err)
	}
}

func TestCacheIsBounded(t *testing.T) {
	s := stub.New(t)
	c := newClient(t, s.URL(), s.Token(), &handlerTransport{h: s.Handler()}, newClock(), nil)
	ctx := context.Background()
	first := request(alice, "repo.read", "00000000-0000-4000-8000-000000000000")
	if _, err := c.Authorize(ctx, first); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= authz.CacheEntries; i++ {
		id := strings.Replace("00000000-0000-4000-8000-000000000000", "000000000000", pad(i), 1)
		if _, err := c.Authorize(ctx, request(alice, "repo.read", id)); err != nil {
			t.Fatal(err)
		}
	}
	if c.CacheLen() != authz.CacheEntries {
		t.Fatalf("cache holds %d", c.CacheLen())
	}
	before := len(s.Requests())
	if _, err := c.Authorize(ctx, first); err != nil || len(s.Requests()) != before+1 {
		t.Fatal("the first entry was not evicted")
	}
}

func pad(i int) string {
	s := "000000000000" + itoa(i)
	return s[len(s)-12:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// handlerTransport serves a handler in-process, with no socket.
type handlerTransport struct{ h http.Handler }

func (t *handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// TestAnUnknownActionNeverReachesTheWire: with a vocabulary configured,
// an action outside it is refused before the call, as an *UnknownAction
// and never an *Unavailable, so a core tells its own typo from an
// authorizer that is down.
func TestAnUnknownActionNeverReachesTheWire(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"allow": true}`)
	}))
	t.Cleanup(srv.Close)
	vocabulary, err := authz.NewVocabulary("origo",
		authz.Action{Name: "repo.read", Kind: "Repository"},
		authz.Action{Name: "repo.write", Kind: "Repository"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		vocabulary authz.Vocabulary
		action     string
		refused    bool
	}{
		{"an action of the table", vocabulary, "repo.read", false},
		{"a typo", vocabulary, "repo.raed", true},
		{"the empty action", vocabulary, "", true},
		{"no vocabulary validates nothing", authz.Vocabulary{}, "repo.raed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls = 0
			var observed int
			c, err := authz.NewClient(authz.Options{URL: srv.URL, HTTP: srv.Client(), Vocabulary: tc.vocabulary,
				Observe: func(string, float64) { observed++ }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Authorize(t.Context(), authz.Request{Action: tc.action, Resource: authz.NewResource("Repository", "r1", nil)})
			if !tc.refused {
				if err != nil {
					t.Fatalf("Authorize = %v; the action is answered", err)
				}
				if calls != 1 {
					t.Fatalf("the endpoint saw %d calls; want 1", calls)
				}
				return
			}
			var unknown *authz.UnknownAction
			if !errors.As(err, &unknown) {
				t.Fatalf("Authorize = %v; want an *UnknownAction", err)
			}
			if unknown.Core != "origo" || unknown.Action != tc.action {
				t.Fatalf("UnknownAction = %+v", unknown)
			}
			if !strings.Contains(unknown.Error(), "origo") {
				t.Fatalf("the message does not name the core: %q", unknown.Error())
			}
			var unavailable *authz.Unavailable
			if errors.As(err, &unavailable) {
				t.Fatal("a typo reads as an outage; a core would fail closed on its own mistake")
			}
			if authz.Retryable(err) {
				t.Fatal("a typo is retryable")
			}
			if calls != 0 || observed != 0 {
				t.Fatalf("the endpoint saw %d calls and the metric %d results; the request never leaves", calls, observed)
			}
			if c.CacheLen() != 0 {
				t.Fatalf("a refused action reached the cache")
			}
		})
	}
}
