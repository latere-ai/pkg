// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package semaphore bounds concurrent work with cancellable admission.
package semaphore

import (
	"context"
	"sync"
	"time"
)

// Semaphore is a concurrent counting semaphore. The zero value and nil receiver
// are uncapped. A permit remains held until its release function is called.
type Semaphore struct{ slots chan struct{} }

// New creates n slots. Nonpositive n disables the cap.
func New(n int) *Semaphore {
	if n <= 0 {
		return &Semaphore{}
	}
	return &Semaphore{slots: make(chan struct{}, n)}
}

// Size returns the capacity, or zero when uncapped.
func (s *Semaphore) Size() int {
	if s == nil {
		return 0
	}
	return cap(s.slots)
}

// Held returns the number of occupied slots, or zero when uncapped.
func (s *Semaphore) Held() int {
	if s == nil {
		return 0
	}
	return len(s.slots)
}

// Acquire waits at most wait for a slot; nonpositive wait tries once. Cancellation
// observed before admission refuses the request. Success returns a release
// function safe for repeated concurrent calls. No FIFO ordering is promised.
func (s *Semaphore) Acquire(ctx context.Context, wait time.Duration) (func(), bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	if s == nil || s.slots == nil {
		return func() {}, true
	}
	select {
	case s.slots <- struct{}{}:
		return s.acquired(ctx)
	default:
	}
	if wait <= 0 {
		return nil, false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case s.slots <- struct{}{}:
		return s.acquired(ctx)
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

func (s *Semaphore) acquired(ctx context.Context) (func(), bool) {
	if ctx.Err() != nil {
		<-s.slots
		return nil, false
	}
	return sync.OnceFunc(func() { <-s.slots }), true
}
