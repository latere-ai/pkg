// Package wait provides cancellable time primitives: a sleep, a ticker loop,
// and a poll. Each returns as soon as its context is done, so a shutdown is
// never held up by a timer that was started before it.
package wait

import (
	"context"
	"time"
)

// Sleep blocks for d or until ctx is done, whichever comes first. It returns
// ctx.Err() when the context ended the wait and nil otherwise.
//
// A non-positive d still observes ctx: it returns ctx.Err() when ctx is
// already done and nil otherwise. A caller that computes a zero delay
// therefore cannot slip past a cancellation.
func Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Every calls fn once per interval until ctx is done. The first call happens
// one interval after Every is entered, matching [time.NewTicker]; a caller
// that wants a leading call makes it before calling Every.
//
// fn runs on the calling goroutine, so a slow fn delays the next tick rather
// than overlapping with it. A non-positive interval returns immediately,
// which lets a zero setting disable a periodic job without a branch at the
// call site.
func Every(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn(ctx)
		}
	}
}

// Until calls cond immediately and then once per interval until cond reports
// done, cond returns an error, or ctx is done. It returns cond's error, or
// ctx.Err() when the context ended the poll. A non-positive interval polls
// without pausing.
func Until(ctx context.Context, interval time.Duration, cond func(context.Context) (bool, error)) error {
	for {
		done, err := cond(ctx)
		if err != nil || done {
			return err
		}
		if err := Sleep(ctx, interval); err != nil {
			return err
		}
	}
}
