// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// ErrRefreshRequired is returned by [Client.ReadSession] when the session is
// alive but its access token has expired or is within the refresh leeway of
// expiring, and the session holds a refresh token. The session is renewed by
// a request that refreshes it, [Client.SessionFromRequest], and is then
// usable again.
var ErrRefreshRequired = errors.New("oidc: the session's access token needs a refresh")

// ErrIssuerUnavailable is wrapped by a refresh that failed without the
// issuer refusing it: the token endpoint could not be reached, timed out, or
// answered with a server error. The session may still be good, so a caller
// keeps the cookie and answers that the request can be tried again.
var ErrIssuerUnavailable = errors.New("oidc: the issuer could not refresh the session")

// refreshReuse is how long the outcome of a refresh is kept for a request
// that presents the same refresh token. A rotating issuer treats a second
// use of a spent refresh token as replay and revokes the token family, so a
// request that still carries the cookie from before the refresh, sent before
// the browser stored the new one, is answered with the refresh already made
// instead of spending the token a second time.
const refreshReuse = 30 * time.Second

// refreshTimeout bounds one refresh at the issuer. The refresh runs detached
// from the request that started it, because the requests waiting on it would
// otherwise fail with that one request's cancellation.
const refreshTimeout = 15 * time.Second

// needsRefresh reports whether sess's access token is expired or within the
// refresh leeway of expiring. It is the one predicate ReadSession and
// SessionFromRequest share: a read that says a refresh is required and a
// refresh that does not happen would send a caller around in a loop.
func needsRefresh(sess *Session, now time.Time) bool {
	return sess.Expiry.IsZero() || !sess.Expiry.Add(-refreshLeeway).After(now)
}

// ReadSession reads and decrypts the session cookie and checks it, without
// refreshing it and without writing anything. It is the read for a request
// that may run beside others from the same page: a refresh rotates the
// refresh token, and two requests that each refresh spend one token twice.
//
// It returns the session when its access token is good for longer than the
// refresh leeway, or when the session holds no refresh token and the access
// token has not expired. It returns [ErrRefreshRequired] when the access
// token needs a refresh and the session holds a refresh token,
// [ErrSessionExpired] when the session's lifetime has elapsed or its access
// token has expired with nothing to refresh it, and the cookie error
// unchanged when the cookie is absent or cannot be decrypted.
func (c *Client) ReadSession(r *http.Request) (*Session, error) {
	sess, err := c.GetSession(r)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if sessionWindowElapsed(sess, now) {
		return nil, ErrSessionExpired
	}
	if !needsRefresh(sess, now) {
		return sess, nil
	}
	if sess.RefreshToken != "" {
		return nil, ErrRefreshRequired
	}
	if accessTokenExpired(sess, now) {
		return nil, ErrSessionExpired
	}
	return sess, nil
}

// refreshFlight is one refresh of one refresh token: in flight until done
// is closed, then its outcome, kept until refreshReuse after it completed.
type refreshFlight struct {
	done  chan struct{}
	token *oauth2.Token
	err   error
	// completed is when the outcome was stored; zero while in flight. It is
	// read and written under refreshGroup.mu.
	completed time.Time
}

// refreshGroup is the refreshes a Client has made recently, by the hash of
// the refresh token each one spent.
type refreshGroup struct {
	mu      sync.Mutex
	flights map[[sha256.Size]byte]*refreshFlight
	// now is the clock; a test sets it. Nil is time.Now.
	now func() time.Time
}

func (g *refreshGroup) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// renew trades refreshToken for a new token set at most once in this
// process for a given token: a refresh of the same token already in flight
// is waited for, and one that completed within refreshReuse is answered
// with its outcome. A refusal by the issuer is kept and answered the same
// way, since the token cannot succeed again; any other failure is not, so
// the next request tries again.
//
// The deduplication covers one process. A relying party that serves one
// browser from several replicas also needs the browser not to send two
// refreshing requests at once.
func (c *Client) renew(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	key := sha256.Sum256([]byte(refreshToken))
	g := &c.refreshes
	g.mu.Lock()
	now := g.clock()
	for k, f := range g.flights {
		if !f.completed.IsZero() && now.Sub(f.completed) > refreshReuse {
			delete(g.flights, k)
		}
	}
	if f, ok := g.flights[key]; ok {
		g.mu.Unlock()
		select {
		case <-f.done:
			return f.token, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if g.flights == nil {
		g.flights = map[[sha256.Size]byte]*refreshFlight{}
	}
	f := &refreshFlight{done: make(chan struct{})}
	g.flights[key] = f
	g.mu.Unlock()

	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	token, err := c.provider.Refresh(detached, refreshToken)
	cancel()
	if err != nil {
		err = classifyRefresh(err)
	}

	g.mu.Lock()
	f.token, f.err, f.completed = token, err, g.clock()
	if err != nil && !errors.Is(err, ErrSessionExpired) {
		delete(g.flights, key)
	}
	g.mu.Unlock()
	close(f.done)
	return token, err
}

// classifyRefresh wraps a failed refresh in what it means for the session.
// The issuer refusing the grant (400 or 401 from the token endpoint, such as
// invalid_grant for a spent or revoked refresh token) ends the session and
// wraps [ErrSessionExpired]. Anything else wraps [ErrIssuerUnavailable].
func classifyRefresh(err error) error {
	if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok && re.Response != nil &&
		(re.Response.StatusCode == http.StatusBadRequest || re.Response.StatusCode == http.StatusUnauthorized) {
		return fmt.Errorf("%w: the issuer refused the refresh: %w", ErrSessionExpired, err)
	}
	return fmt.Errorf("%w: %w", ErrIssuerUnavailable, err)
}
