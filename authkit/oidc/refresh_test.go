// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rotatingIssuer is a token endpoint that rotates refresh tokens the way a
// rotating issuer does: the first use of a refresh token answers a new
// token set with the next refresh token, and any later use of the same one
// is refused with invalid_grant, as replay. hold delays the answer to a
// first use, so requests that would each refresh overlap.
type rotatingIssuer struct {
	t      *testing.T
	hold   time.Duration
	status int // when set, every refresh answers this status instead

	mu    sync.Mutex
	spent map[string]bool
	next  int
	calls atomic.Int32
}

func (ri *rotatingIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ri.calls.Add(1)
	if err := r.ParseForm(); err != nil {
		ri.t.Errorf("ParseForm: %v", err)
	}
	if ri.status != 0 {
		w.WriteHeader(ri.status)
		return
	}
	rt := r.FormValue("refresh_token")
	ri.mu.Lock()
	reused := ri.spent[rt]
	ri.spent[rt] = true
	ri.next++
	n := ri.next
	ri.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if reused {
		w.WriteHeader(http.StatusBadRequest)
		if _, err := w.Write([]byte(`{"error":"invalid_grant","error_description":"The refresh token was already used."}`)); err != nil {
			ri.t.Errorf("write refusal: %v", err)
		}
		return
	}
	time.Sleep(ri.hold)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"access_token":  makeRichJWT(map[string]any{"sub": "u1", "n": n}),
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": rt + "-next",
	}); err != nil {
		ri.t.Errorf("encode token: %v", err)
	}
}

// rotatingClient is a client whose issuer is ri.
func rotatingClient(t *testing.T, ri *rotatingIssuer) *Client {
	t.Helper()
	ri.t = t
	ri.spent = map[string]bool{}
	ts := httptest.NewServer(ri)
	t.Cleanup(ts.Close)
	c := New(Config{
		AuthURL: ts.URL, ClientID: "cid", RedirectURL: "https://app.example.com/cb",
		CookieKey: "0123456789abcdef0123456789abcdef", SessionTTL: 30 * 24 * time.Hour,
	})
	if c == nil {
		t.Fatal("New returned nil")
	}
	return c
}

// staleSession is a session whose access token is inside the refresh
// leeway, holding refreshToken.
func staleSession(refreshToken string) *Session {
	return &Session{
		AccessToken:   makeRichJWT(map[string]any{"sub": "u1"}),
		RefreshToken:  refreshToken,
		Expiry:        time.Now().UTC().Add(refreshLeeway / 2),
		SessionExpiry: time.Now().UTC().Add(24 * time.Hour),
		User:          User{Name: "Ada"},
	}
}

// requestWith is a request carrying the cookies a response set.
func requestWith(cookies []*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, ck := range cookies {
		r.AddCookie(ck)
	}
	return r
}

// TestConcurrentRefreshesSpendOneRefreshToken is the race behind a person
// signed out of a page that loads several routes at once: each request finds
// the access token about to expire and refreshes the same rotating refresh
// token; the issuer takes the second use for replay and revokes the family.
// The requests must share one refresh, and every one of them must succeed.
func TestConcurrentRefreshesSpendOneRefreshToken(t *testing.T) {
	ri := &rotatingIssuer{hold: 100 * time.Millisecond}
	c := rotatingClient(t, ri)
	seed := seedCookie(t, c, staleSession("rt-1"))

	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	got := make([]*Session, n)
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			<-start
			got[i], errs[i] = c.SessionFromRequest(httptest.NewRecorder(), requestWith(seed.Cookies()))
		})
	}
	close(start)
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Fatalf("request %d: %v", i, errs[i])
		}
		if got[i].RefreshToken != "rt-1-next" || got[i].AccessToken != got[0].AccessToken {
			t.Errorf("request %d holds %q, want the one refresh's rt-1-next and access token", i, got[i].RefreshToken)
		}
	}
	if calls := ri.calls.Load(); calls != 1 {
		t.Errorf("the issuer was asked %d times, want 1", calls)
	}
}

// TestARequestWithTheSpentTokenGetsTheRefreshMade: a request sent with the
// cookie from before a refresh, which the browser had not replaced yet, is
// answered with that refresh, not a second use of the spent token.
func TestARequestWithTheSpentTokenGetsTheRefreshMade(t *testing.T) {
	ri := &rotatingIssuer{}
	c := rotatingClient(t, ri)
	old := seedCookie(t, c, staleSession("rt-1"))

	first, err := c.SessionFromRequest(httptest.NewRecorder(), requestWith(old.Cookies()))
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	w := httptest.NewRecorder()
	second, err := c.SessionFromRequest(w, requestWith(old.Cookies()))
	if err != nil {
		t.Fatalf("a request with the spent token: %v", err)
	}
	if second.AccessToken != first.AccessToken || second.RefreshToken != "rt-1-next" {
		t.Errorf("second = %q/%q, want the first refresh's", second.AccessToken, second.RefreshToken)
	}
	if len(w.Result().Cookies()) != 1 {
		t.Errorf("the session is written back to the request that carried the old cookie")
	}
	if calls := ri.calls.Load(); calls != 1 {
		t.Errorf("the issuer was asked %d times, want 1", calls)
	}
}

// TestTheReuseWindowLapses: past the window a spent token goes to the issuer
// again, which refuses it, and the refusal ends the session.
func TestTheReuseWindowLapses(t *testing.T) {
	ri := &rotatingIssuer{}
	c := rotatingClient(t, ri)
	at := time.Now()
	c.refreshes.now = func() time.Time { return at }
	old := seedCookie(t, c, staleSession("rt-1"))

	if _, err := c.SessionFromRequest(httptest.NewRecorder(), requestWith(old.Cookies())); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	at = at.Add(refreshReuse + time.Second)
	_, err := c.SessionFromRequest(httptest.NewRecorder(), requestWith(old.Cookies()))
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired for a refused refresh", err)
	}
	if calls := ri.calls.Load(); calls != 2 {
		t.Errorf("the issuer was asked %d times, want 2", calls)
	}
	if len(c.refreshes.flights) != 1 {
		t.Errorf("the lapsed flight was not swept: %d kept", len(c.refreshes.flights))
	}
}

// TestARefusedRefreshIsKeptAndEndsTheSession: a refused refresh is the end
// of the session, and the token is not offered to the issuer again within
// the window.
func TestARefusedRefreshIsKeptAndEndsTheSession(t *testing.T) {
	ri := &rotatingIssuer{status: http.StatusBadRequest}
	c := rotatingClient(t, ri)
	r := seedCookie(t, c, staleSession("rt-dead"))
	for range 2 {
		_, err := c.SessionFromRequest(httptest.NewRecorder(), requestWith(r.Cookies()))
		if !errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrIssuerUnavailable) {
			t.Fatalf("err = %v, want ErrSessionExpired alone", err)
		}
	}
	if calls := ri.calls.Load(); calls != 1 {
		t.Errorf("the issuer was asked %d times, want 1", calls)
	}
}

// TestAFailedRefreshIsTriedAgain: a refresh that failed without a refusal
// says the issuer is unavailable, and the next request tries it again.
func TestAFailedRefreshIsTriedAgain(t *testing.T) {
	ri := &rotatingIssuer{status: http.StatusServiceUnavailable}
	c := rotatingClient(t, ri)
	r := seedCookie(t, c, staleSession("rt-1"))
	for range 2 {
		_, err := c.SessionFromRequest(httptest.NewRecorder(), requestWith(r.Cookies()))
		if !errors.Is(err, ErrIssuerUnavailable) || errors.Is(err, ErrSessionExpired) {
			t.Fatalf("err = %v, want ErrIssuerUnavailable alone", err)
		}
	}
	if calls := ri.calls.Load(); calls != 2 {
		t.Errorf("the issuer was asked %d times, want 2", calls)
	}
}

// TestAnUnreachableIssuerIsUnavailable: a token endpoint that does not
// answer at all is no refusal.
func TestAnUnreachableIssuerIsUnavailable(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	addr := ts.URL
	ts.Close()
	c := New(Config{AuthURL: addr, ClientID: "cid", RedirectURL: "https://app.example.com/cb", CookieKey: "k"})
	r := seedCookie(t, c, staleSession("rt-1"))
	_, err := c.SessionFromRequest(httptest.NewRecorder(), requestWith(r.Cookies()))
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("err = %v, want ErrIssuerUnavailable", err)
	}
}

// TestBuildMeKeepsTheCookieWhenTheIssuerIsUnavailable: only a refusal clears
// the session; a failed connection leaves it for the next request.
func TestBuildMeKeepsTheCookieWhenTheIssuerIsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		status  int
		cleared bool
	}{{http.StatusServiceUnavailable, false}, {http.StatusBadRequest, true}} {
		ri := &rotatingIssuer{status: tc.status}
		c := rotatingClient(t, ri)
		sess := staleSession("rt-1")
		sess.Expiry = time.Now().Add(-time.Minute)
		r := seedCookie(t, c, sess)
		w := httptest.NewRecorder()
		me, err := c.BuildMe(w, requestWith(r.Cookies()))
		if me != nil || err != nil {
			t.Fatalf("status %d: BuildMe = %v, %v; want nil, nil", tc.status, me, err)
		}
		cleared := false
		for _, ck := range w.Result().Cookies() {
			cleared = cleared || ck.MaxAge < 0
		}
		if cleared != tc.cleared {
			t.Errorf("status %d: session cleared = %v, want %v", tc.status, cleared, tc.cleared)
		}
	}
}

// TestAWaiterLeavesWhenItsRequestEnds: a request waiting on another's
// refresh stops waiting when it is cancelled, and the refresh goes on for
// the request that started it, whose own cancellation does not stop it.
func TestAWaiterLeavesWhenItsRequestEnds(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-2","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-2"}`))
	}))
	t.Cleanup(ts.Close)
	c := New(Config{AuthURL: ts.URL, ClientID: "cid", RedirectURL: "https://app.example.com/cb", CookieKey: "k"})

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.renew(firstCtx, "rt-1")
		done <- err
	}()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	cancelWaiter()
	if _, err := c.renew(waiterCtx, "rt-1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter err = %v, want context.Canceled", err)
	}
	cancelFirst()
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("the refresh stopped with its request: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("the issuer was asked %d times, want 1", calls.Load())
	}
}

// TestReadSession covers every answer of the non-refreshing read, which
// must agree with SessionFromRequest on when a refresh is due.
func TestReadSession(t *testing.T) {
	ri := &rotatingIssuer{}
	c := rotatingClient(t, ri)
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		sess *Session
		want error
	}{
		{"fresh", &Session{AccessToken: "at", RefreshToken: "rt", Expiry: now.Add(time.Hour)}, nil},
		{"within the leeway, refreshable", &Session{AccessToken: "at", RefreshToken: "rt", Expiry: now.Add(refreshLeeway / 2)}, ErrRefreshRequired},
		{"expired, refreshable", &Session{AccessToken: "at", RefreshToken: "rt", Expiry: now.Add(-time.Hour)}, ErrRefreshRequired},
		{"no expiry, refreshable", &Session{AccessToken: "at", RefreshToken: "rt"}, ErrRefreshRequired},
		{"within the leeway, nothing to refresh with", &Session{AccessToken: "at", Expiry: now.Add(refreshLeeway / 2)}, nil},
		{"expired, nothing to refresh with", &Session{AccessToken: "at", Expiry: now.Add(-time.Minute)}, ErrSessionExpired},
		{"the session's lifetime elapsed", &Session{AccessToken: "at", RefreshToken: "rt", Expiry: now.Add(time.Hour), SessionExpiry: now.Add(-time.Minute)}, ErrSessionExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// SetSession keeps a stamped expiry as it is, an elapsed one too.
			r := seedCookie(t, c, tc.sess)
			got, err := c.ReadSession(r)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if (got != nil) != (tc.want == nil) {
				t.Errorf("session = %v with err %v", got, err)
			}
			if tc.want == nil {
				// The two reads agree: what ReadSession hands over,
				// SessionFromRequest does not refresh.
				if _, err := c.SessionFromRequest(httptest.NewRecorder(), r); err != nil {
					t.Errorf("SessionFromRequest: %v", err)
				}
			}
		})
	}
	if _, err := c.ReadSession(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Error("a request without the cookie read a session")
	}
	if calls := ri.calls.Load(); calls != 0 {
		t.Errorf("ReadSession, or a fresh SessionFromRequest, asked the issuer %d times", calls)
	}
}
