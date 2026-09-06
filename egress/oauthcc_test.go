// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tokenServer is a scripted RFC 6749 token endpoint.
type tokenServer struct {
	t      *testing.T
	srv    *httptest.Server
	mints  atomic.Int32
	mu     sync.Mutex
	status int
	body   string
	last   *http.Request
	form   map[string]string
	delay  time.Duration
	block  chan struct{} // when set, a mint blocks until closed
}

func newTokenServer(t *testing.T) *tokenServer {
	t.Helper()
	ts := &tokenServer{t: t, status: http.StatusOK}
	ts.setToken("tok-1", 3600)
	ts.srv = httptest.NewServer(http.HandlerFunc(ts.serve))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *tokenServer) setToken(tok string, expiresIn int) {
	ts.respond(http.StatusOK, fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","expires_in":%d}`, tok, expiresIn))
}

func (ts *tokenServer) respond(status int, body string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.status, ts.body = status, body
}

func (ts *tokenServer) serve(w http.ResponseWriter, r *http.Request) {
	ts.mints.Add(1)
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ts.mu.Lock()
	ts.last = r
	ts.form = map[string]string{}
	for k := range r.PostForm {
		ts.form[k] = r.PostForm.Get(k)
	}
	status, body, delay, block := ts.status, ts.body, ts.delay, ts.block
	ts.mu.Unlock()
	if block != nil {
		<-block
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (ts *tokenServer) client(now *fakeClock) *OAuthClientCredentials {
	return &OAuthClientCredentials{
		TokenURL:     ts.srv.URL,
		ClientID:     "id with space",
		ClientSecret: "s3cret/+=",
		Scope:        "read write",
		Audience:     "https://api.example",
		HTTPClient:   ts.srv.Client(),
		Now:          now.Now,
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func resolve(t *testing.T, cc *OAuthClientCredentials) string {
	t.Helper()
	b, err := cc.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return string(b)
}

func TestOAuthClientCredentials_MintsBareTokenWithRFCRequest(t *testing.T) {
	ts := newTokenServer(t)
	cc := ts.client(newClock())
	if got := resolve(t, cc); got != "tok-1" {
		t.Fatalf("token = %q", got)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	r := ts.last
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
		t.Fatalf("request shape: %s %v", r.Method, r.Header)
	}
	id, secret, ok := r.BasicAuth()
	if !ok || id != "id+with+space" || secret != "s3cret%2F%2B%3D" {
		t.Fatalf("basic auth = %q %q %v (RFC 6749 2.3.1 form-encodes both)", id, secret, ok)
	}
	want := map[string]string{"grant_type": "client_credentials", "scope": "read write", "audience": "https://api.example"}
	for k, v := range want {
		if ts.form[k] != v {
			t.Errorf("form[%s] = %q, want %q", k, ts.form[k], v)
		}
	}
	if _, ok := ts.form["client_id"]; ok {
		t.Error("client_id must not also ride in the form")
	}
}

func TestOAuthClientCredentials_OmitsEmptyScopeAndAudience(t *testing.T) {
	ts := newTokenServer(t)
	cc := &OAuthClientCredentials{TokenURL: ts.srv.URL, ClientID: "a", ClientSecret: "b", HTTPClient: ts.srv.Client()}
	resolve(t, cc)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for _, k := range []string{"scope", "audience"} {
		if _, ok := ts.form[k]; ok {
			t.Errorf("%s sent although empty", k)
		}
	}
}

func TestOAuthClientCredentials_CachesAndRefreshesAheadOfExpiry(t *testing.T) {
	ts := newTokenServer(t)
	clock := newClock()
	cc := ts.client(clock)
	cc.Skew = time.Minute
	resolve(t, cc)
	resolve(t, cc)
	if ts.mints.Load() != 1 {
		t.Fatalf("mints = %d, want 1 (cached)", ts.mints.Load())
	}
	ts.setToken("tok-2", 3600)
	clock.Advance(3600*time.Second - 61*time.Second)
	if got := resolve(t, cc); got != "tok-1" || ts.mints.Load() != 1 {
		t.Fatalf("before the skew window: %q, mints=%d", got, ts.mints.Load())
	}
	clock.Advance(2 * time.Second)
	if got := resolve(t, cc); got != "tok-2" || ts.mints.Load() != 2 {
		t.Fatalf("inside the skew window: %q, mints=%d", got, ts.mints.Load())
	}
}

func TestOAuthClientCredentials_DefaultSkew(t *testing.T) {
	ts := newTokenServer(t)
	clock := newClock()
	cc := ts.client(clock)
	ts.setToken("tok-1", 60)
	resolve(t, cc)
	ts.setToken("tok-2", 60)
	clock.Advance(29 * time.Second)
	if got := resolve(t, cc); got != "tok-1" {
		t.Fatalf("29s into a 60s token with 30s skew: %q", got)
	}
	clock.Advance(time.Second)
	if got := resolve(t, cc); got != "tok-2" {
		t.Fatalf("30s into a 60s token with 30s skew: %q", got)
	}
}

func TestOAuthClientCredentials_ServesStaleOnMintFailure(t *testing.T) {
	ts := newTokenServer(t)
	clock := newClock()
	cc := ts.client(clock)
	ts.setToken("tok-1", 100)
	resolve(t, cc)
	ts.respond(http.StatusInternalServerError, "down")
	clock.Advance(80 * time.Second) // inside skew, still valid
	if got := resolve(t, cc); got != "tok-1" || ts.mints.Load() != 2 {
		t.Fatalf("stale-but-valid should be served: %q mints=%d", got, ts.mints.Load())
	}
	clock.Advance(21 * time.Second) // expired
	_, err := cc.Resolve(context.Background())
	if !errors.Is(err, ErrNoValidToken) {
		t.Fatalf("err = %v, want ErrNoValidToken", err)
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "down") {
		t.Fatalf("err should carry the endpoint's status and body: %v", err)
	}
	// Recovery: the next mint succeeds.
	ts.setToken("tok-3", 100)
	if got := resolve(t, cc); got != "tok-3" {
		t.Fatalf("after recovery: %q", got)
	}
}

func TestOAuthClientCredentials_ErrorBodyText(t *testing.T) {
	ts := newTokenServer(t)
	cc := ts.client(newClock())
	ts.respond(http.StatusBadRequest, `{"error":"invalid_client","error_description":"bad secret"}`)
	_, err := cc.Resolve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid_client: bad secret") {
		t.Fatalf("err = %v", err)
	}
	ts.respond(http.StatusBadRequest, `{"error":"invalid_client"}`)
	_, err = cc.Resolve(context.Background())
	if err == nil || !strings.HasSuffix(err.Error(), "invalid_client") {
		t.Fatalf("err = %v", err)
	}
	ts.respond(http.StatusBadGateway, strings.Repeat("x", 300))
	_, err = cc.Resolve(context.Background())
	if err == nil || !strings.HasSuffix(err.Error(), strings.Repeat("x", 200)+"...") {
		t.Fatalf("long body not truncated: %v", err)
	}
}

func TestOAuthClientCredentials_NoExpiresInIsNotCached(t *testing.T) {
	ts := newTokenServer(t)
	cc := ts.client(newClock())
	ts.respond(http.StatusOK, `{"access_token":"once","token_type":"bearer"}`)
	if got := resolve(t, cc); got != "once" {
		t.Fatalf("token = %q", got)
	}
	resolve(t, cc)
	if ts.mints.Load() != 2 {
		t.Fatalf("mints = %d, want 2 (no lifetime, no cache)", ts.mints.Load())
	}
	ts.respond(http.StatusInternalServerError, "down")
	if _, err := cc.Resolve(context.Background()); !errors.Is(err, ErrNoValidToken) {
		t.Fatalf("an unknown-lifetime token must never be served stale: %v", err)
	}
}

func TestOAuthClientCredentials_SingleFlight(t *testing.T) {
	ts := newTokenServer(t)
	cc := ts.client(newClock())
	block := make(chan struct{})
	ts.mu.Lock()
	ts.block = block
	ts.mu.Unlock()

	const n = 32
	var wg sync.WaitGroup
	results := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			b, err := cc.Resolve(context.Background())
			results[i], errs[i] = string(b), err
		})
	}
	// Every goroutine is parked on the one mint; release it.
	deadline := time.Now().Add(5 * time.Second)
	for ts.mints.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(block)
	wg.Wait()
	for i := range n {
		if errs[i] != nil || results[i] != "tok-1" {
			t.Fatalf("[%d] = %q, %v", i, results[i], errs[i])
		}
	}
	if ts.mints.Load() != 1 {
		t.Fatalf("mints = %d, want 1", ts.mints.Load())
	}
	// The slot is clear: a later miss starts a fresh mint.
	cc.mu.Lock()
	inflight := cc.call
	cc.mu.Unlock()
	if inflight != nil {
		t.Fatal("in-flight slot not cleared")
	}
}

// Concurrent callers across refreshes: no data race, every result is a token
// the server issued, and the mint count is bounded by the refresh count.
func TestOAuthClientCredentials_ConcurrentMintsRace(t *testing.T) {
	ts := newTokenServer(t)
	clock := newClock()
	cc := ts.client(clock)
	ts.setToken("tok", 60)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				b, err := cc.Resolve(context.Background())
				if err != nil || string(b) != "tok" {
					t.Errorf("Resolve = %q, %v", b, err)
					return
				}
			}
		})
	}
	wg.Go(func() {
		for range 50 {
			clock.Advance(time.Second)
		}
	})
	wg.Wait()
	if m := ts.mints.Load(); m < 1 || m > 25 {
		t.Fatalf("mints = %d, expected between 1 and 25 over a 50s advance of a 60s token", m)
	}
}

func TestOAuthClientCredentials_CallerContextCancelledWhileMinting(t *testing.T) {
	ts := newTokenServer(t)
	cc := ts.client(newClock())
	block := make(chan struct{})
	ts.mu.Lock()
	ts.block = block
	ts.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := cc.Resolve(ctx)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for ts.mints.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	// The mint outlives the cancelled caller and serves the next one.
	close(block)
	if got := resolve(t, cc); got != "tok-1" || ts.mints.Load() != 1 {
		t.Fatalf("after cancel: %q mints=%d", got, ts.mints.Load())
	}
}

func TestOAuthClientCredentials_MintTimeout(t *testing.T) {
	ts := newTokenServer(t)
	cc := ts.client(newClock())
	cc.MintTimeout = 20 * time.Millisecond
	ts.mu.Lock()
	ts.delay = 500 * time.Millisecond
	ts.mu.Unlock()
	_, err := cc.Resolve(context.Background())
	if !errors.Is(err, ErrNoValidToken) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestOAuthClientCredentials_TransportAndRequestErrors(t *testing.T) {
	cc := &OAuthClientCredentials{TokenURL: "http://127.0.0.1:1/token", HTTPClient: &http.Client{Timeout: time.Second}}
	if _, err := cc.Resolve(context.Background()); !errors.Is(err, ErrNoValidToken) {
		t.Fatalf("dial failure: %v", err)
	}
	cc = &OAuthClientCredentials{TokenURL: "http://bad host/\x7f"}
	if _, err := cc.Resolve(context.Background()); !errors.Is(err, ErrNoValidToken) {
		t.Fatalf("bad URL: %v", err)
	}
	// A response cut short of its Content-Length is a read error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte(`{"access`))
	}))
	t.Cleanup(srv.Close)
	cc = &OAuthClientCredentials{TokenURL: srv.URL, HTTPClient: srv.Client()}
	if _, err := cc.Resolve(context.Background()); !errors.Is(err, ErrNoValidToken) {
		t.Fatalf("short body: %v", err)
	}
}

func TestOAuthClientCredentials_Defaults(t *testing.T) {
	cc := &OAuthClientCredentials{}
	if cc.skew() != DefaultTokenSkew || cc.mintTimeout() != DefaultMintTimeout || cc.httpClient() != defaultTokenClient || defaultTokenClient.Transport == nil {
		t.Fatal("defaults not applied")
	}
	if d := time.Since(cc.now()); d < 0 || d > time.Minute {
		t.Fatalf("default clock is off: %v", d)
	}
}

func TestParseTokenResponse(t *testing.T) {
	cases := []struct {
		body     string
		token    string
		lifetime time.Duration
		wantErr  string
	}{
		{`{"access_token":"a","token_type":"Bearer","expires_in":3600}`, "a", time.Hour, ""},
		{`{"access_token":"a","token_type":"bearer","expires_in":"90"}`, "a", 90 * time.Second, ""},
		{`{"access_token":"a","token_type":"BEARER","expires_in":1.5}`, "a", 1500 * time.Millisecond, ""},
		{`{"access_token":"a","expires_in":null}`, "a", 0, ""},
		{`{"access_token":"a"}`, "a", 0, ""},
		{`{"access_token":"a","expires_in":0}`, "a", 0, ""},
		{`{"token_type":"bearer"}`, "", 0, "missing access_token"},
		{`{"access_token":"a","token_type":"mac"}`, "", 0, `unsupported token_type "mac"`},
		{`{"access_token":"a","expires_in":-1}`, "", 0, "invalid expires_in"},
		{`{"access_token":"a","expires_in":"soon"}`, "", 0, "invalid expires_in"},
		{`{"access_token":"a","expires_in":1e300}`, "", 0, "invalid expires_in"},
		{`{"access_token":"a","expires_in":{}}`, "", 0, "invalid expires_in"},
		{`not json`, "", 0, "token response"},
		{``, "", 0, "token response"},
	}
	for _, c := range cases {
		tok, lt, err := parseTokenResponse([]byte(c.body))
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: err = %v, want %q", c.body, err, c.wantErr)
			}
			continue
		}
		if err != nil || tok != c.token || lt != c.lifetime {
			t.Errorf("%s: (%q, %v, %v), want (%q, %v)", c.body, tok, lt, err, c.token, c.lifetime)
		}
	}
}

func FuzzParseTokenResponse(f *testing.F) {
	f.Add([]byte(`{"access_token":"a","token_type":"Bearer","expires_in":3600}`))
	f.Add([]byte(`{"access_token":"a","expires_in":"90"}`))
	f.Add([]byte(`{"access_token":"","expires_in":-5}`))
	f.Add([]byte(`{"access_token":"a","expires_in":[1]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		tok, lt, err := parseTokenResponse(body)
		if err != nil {
			if tok != "" || lt != 0 {
				t.Fatalf("error must zero the result: %q %v", tok, lt)
			}
			return
		}
		if tok == "" || lt < 0 {
			t.Fatalf("success with empty token or negative lifetime: %q %v", tok, lt)
		}
		var tr tokenResponse
		if json.Unmarshal(body, &tr) != nil || tr.AccessToken != tok {
			t.Fatalf("token %q does not match the JSON", tok)
		}
	})
}

func FuzzTokenErrorText(f *testing.F) {
	f.Add([]byte(`{"error":"x","error_description":"y"}`))
	f.Add([]byte(strings.Repeat("z", 400)))
	f.Fuzz(func(t *testing.T, body []byte) {
		s := tokenErrorText(body)
		if !json.Valid(body) && len(s) > 203 {
			t.Fatalf("excerpt not bounded: %d", len(s))
		}
	})
}
