// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package retry runs a function under a bounded exponential backoff policy
// with jitter. The budget is finite on purpose: an unbounded retry against a
// permanently failing input is an infinite loop that reads as activity on
// every dashboard except the one showing the work is not getting done.
package retry

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"latere.ai/x/pkg/wait"
)

// Defaults applied by the zero Policy.
const (
	// DefaultMaxAttempts is the total attempts one call gets, the first
	// included.
	DefaultMaxAttempts = 3
	// DefaultBase is the wait after the first failed attempt.
	DefaultBase = time.Second
	// DefaultMax caps the exponential growth.
	DefaultMax = 30 * time.Second
	// DefaultJitter is the fraction of a computed delay that is randomised.
	// Without it, replicas that failed together retry together.
	DefaultJitter = 0.2
)

// Policy is bounded exponential backoff with jitter. The zero value means the
// defaults above, so a caller that sets nothing still retries a finite
// number of times with a randomised delay.
type Policy struct {
	// MaxAttempts is the total attempts, the first included. Zero or less
	// means DefaultMaxAttempts.
	MaxAttempts int
	// Base is the delay after the first failure. Zero or less means
	// DefaultBase.
	Base time.Duration
	// Max caps the delay and is never below Base. Zero or less means
	// DefaultMax.
	Max time.Duration
	// Jitter is the fraction of each delay that is randomised downward.
	// Zero means DefaultJitter, a negative value means none, and values
	// above 1 are clamped to 1.
	Jitter float64
}

// Attempts reports the attempt budget, with the default applied. A caller
// that drives its own loop pairs it with [Policy.Delay].
func (p Policy) Attempts() int {
	if p.MaxAttempts <= 0 {
		return DefaultMaxAttempts
	}
	return p.MaxAttempts
}

func (p Policy) base() time.Duration {
	if p.Base <= 0 {
		return DefaultBase
	}
	return p.Base
}

func (p Policy) ceiling() time.Duration {
	if p.Max <= 0 {
		return max(DefaultMax, p.base())
	}
	return max(p.Max, p.base())
}

func (p Policy) jitter() float64 {
	switch {
	case p.Jitter == 0:
		return DefaultJitter
	case p.Jitter < 0:
		return 0
	default:
		return min(p.Jitter, 1)
	}
}

// Delay reports the wait after the attempt-th failed attempt, counting from
// 1. The delay doubles per attempt up to Max, then a random fraction of at
// most Jitter is subtracted. Jitter reduces rather than extends, so Max is a
// ceiling.
func (p Policy) Delay(attempt int) time.Duration {
	return p.delay(attempt, rand.Float64)
}

// delay is Delay with the random source as a parameter, so the bounds are
// assertable in tests.
func (p Policy) delay(attempt int, random func() float64) time.Duration {
	d := p.base()
	ceiling := p.ceiling()
	// Stop doubling once the next step would reach the ceiling. Bounding the
	// loop this way, rather than by attempt count, means a large attempt
	// number cannot overflow time.Duration.
	for i := 1; i < attempt; i++ {
		if d >= ceiling/2 {
			d = ceiling
			break
		}
		d *= 2
	}
	d = min(d, ceiling)
	if j := p.jitter(); j > 0 {
		d = time.Duration(float64(d) * (1 - j*random()))
	}
	return d
}

// Do calls fn until it returns nil, returns an error marked by [Stop], the
// attempt budget is spent, or ctx is done while waiting between attempts.
//
// The error fn returned is passed back unwrapped when the budget runs out,
// so a caller's errors.Is on its own sentinels keeps working. A cancellation
// during the wait returns ctx.Err().
func Do(ctx context.Context, p Policy, fn func(context.Context) error) error {
	budget := p.Attempts()
	for attempt := 1; ; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if stop, ok := errors.AsType[*stopError](err); ok {
			return stop.err
		}
		if attempt >= budget {
			return err
		}
		if err := wait.Sleep(ctx, p.Delay(attempt)); err != nil {
			return err
		}
	}
}

// Stop marks err as permanent, so [Do] returns err without another attempt.
// A nil err stays nil.
func Stop(err error) error {
	if err == nil {
		return nil
	}
	return &stopError{err: err}
}

type stopError struct{ err error }

func (e *stopError) Error() string { return e.err.Error() }
func (e *stopError) Unwrap() error { return e.err }
