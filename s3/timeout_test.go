// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"latere.ai/x/pkg/retry"
	"latere.ai/x/pkg/s3"
)

type deadlineTransport func(*http.Request) (*http.Response, error)

func (f deadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type deadlineBody struct {
	ctx    context.Context
	closed bool
}

func (b *deadlineBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (b *deadlineBody) Close() error             { b.closed = true; return nil }

func timeoutClient(t *testing.T, transport deadlineTransport) *s3.Client {
	t.Helper()
	c, err := s3.New("http://storage.invalid", "region", "bucket", "key", "secret", s3.WithPathStyle(), s3.WithHTTPClient(&http.Client{Transport: transport}), s3.WithRetry(retry.Policy{MaxAttempts: 2, Timeout: time.Second, Base: time.Nanosecond}))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestS3AttemptDeadlineRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		c := timeoutClient(t, func(r *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("pack"))}, nil
		})
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		body, _, err := c.GetObject(ctx, "key", "")
		if err != nil {
			t.Fatal(err)
		}
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil || string(raw) != "pack" || attempts != 2 {
			t.Fatalf("body=%q err=%v attempts=%d", raw, err, attempts)
		}
	})
}

func TestS3GetDeadlineEndsAtHeaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var child context.Context
		c := timeoutClient(t, func(r *http.Request) (*http.Response, error) {
			child = r.Context()
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("pack"))}, nil
		})
		body, _, err := c.GetObject(t.Context(), "key", "")
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		if child.Err() != nil {
			t.Fatal("header deadline canceled returned body")
		}
		raw, err := io.ReadAll(body)
		if err != nil || string(raw) != "pack" {
			t.Fatal("returned body unreadable")
		}
		if err := body.Close(); err != nil {
			t.Fatal(err)
		}
		if child.Err() != context.Canceled {
			t.Fatal("body close did not release context")
		}
	})
}

func TestS3GetRetainsParentCancellation(t *testing.T) {
	var child context.Context
	c := timeoutClient(t, func(r *http.Request) (*http.Response, error) {
		child = r.Context()
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: &deadlineBody{ctx: child}}, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	body, _, err := c.GetObject(ctx, "key", "")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	cancel()
	if _, err := io.ReadAll(body); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestS3DeadlineBoundsResponseBodies(t *testing.T) {
	for _, status := range []int{200, 503} {
		synctest.Test(t, func(t *testing.T) {
			attempts := 0
			var stalled *deadlineBody
			c := timeoutClient(t, func(r *http.Request) (*http.Response, error) {
				attempts++
				if attempts == 1 {
					stalled = &deadlineBody{ctx: r.Context()}
					return &http.Response{StatusCode: status, Header: http.Header{}, Body: stalled}, nil
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("<ListBucketResult/>"))}, nil
			})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err := c.ListObjects(ctx, s3.ListOptions{})
			if err != nil || attempts != 2 || !stalled.closed {
				t.Fatalf("status=%d attempts=%d err=%v closed=%v", status, attempts, err, stalled.closed)
			}
		})
	}
}

func TestS3PermanentStatusDoesNotRetryAfterBodyTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		c := timeoutClient(t, func(r *http.Request) (*http.Response, error) {
			attempts++
			return &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}, Body: &deadlineBody{ctx: r.Context()}}, nil
		})
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_, _, err := c.GetObject(ctx, "key", "")
		if !errors.Is(err, context.DeadlineExceeded) || attempts != 1 {
			t.Fatalf("permanent status retried: attempts=%d err=%v", attempts, err)
		}
	})
}
