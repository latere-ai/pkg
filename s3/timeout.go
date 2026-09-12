// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"context"
	"io"
	"time"
)

// attemptContext permits detaching the attempt timer at accepted GET headers
// without detaching parent cancellation. finish synchronizes with a timer that
// already fired, so a timeout cannot race with handing a successful body back.
func attemptContext(parent context.Context, timeout time.Duration) (context.Context, func() error, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	release := func() { cancel(context.Canceled) }
	if timeout <= 0 {
		return ctx, func() error { return context.Cause(ctx) }, release
	}
	done := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		cancel(context.DeadlineExceeded)
		close(done)
	})
	finish := func() error {
		if !timer.Stop() {
			<-done
		}
		return context.Cause(ctx)
	}
	return ctx, finish, func() { timer.Stop(); release() }
}

// ownedBody keeps parent cancellation live until the reader finishes or closes.
type ownedBody struct {
	io.ReadCloser
	cancel func()
}

func (b *ownedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.cancel()
	}
	return n, err
}

func (b *ownedBody) Close() error {
	defer b.cancel()
	return b.ReadCloser.Close()
}
