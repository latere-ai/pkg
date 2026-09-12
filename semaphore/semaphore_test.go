// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package semaphore

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestAdmissionAndConcurrentRelease(t *testing.T) {
	s := New(1)
	release, ok := s.Acquire(t.Context(), 0)
	if !ok || s.Size() != 1 || s.Held() != 1 {
		t.Fatal("slot not acquired")
	}
	if r, ok := s.Acquire(t.Context(), 0); ok || r != nil {
		t.Fatal("saturated semaphore admitted")
	}
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(release)
	}
	wg.Wait()
	if s.Held() != 0 {
		t.Fatal("release leaked slot")
	}
	release, ok = s.Acquire(t.Context(), -time.Second)
	if !ok {
		t.Fatal("try-only did not acquire free slot")
	}
	release()
}

func TestWaitDeadlineAndWakeup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(1)
		release, _ := s.Acquire(t.Context(), 0)
		start := time.Now()
		if _, ok := s.Acquire(t.Context(), time.Second); ok {
			t.Fatal("deadline admitted")
		}
		if time.Since(start) != time.Second {
			t.Fatal("wait not bounded")
		}
		go func() { time.Sleep(time.Second); release() }()
		next, ok := s.Acquire(t.Context(), 2*time.Second)
		if !ok {
			t.Fatal("released slot did not wake waiter")
		}
		next()
	})
}

func TestCancellationAndUncapped(t *testing.T) {
	for _, s := range []*Semaphore{nil, New(0), New(-1), New(1)} {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if release, ok := s.Acquire(ctx, time.Second); ok || release != nil {
			t.Fatal("canceled context admitted")
		}
		release, ok := s.Acquire(t.Context(), 0)
		if !ok {
			t.Fatal("live context denied")
		}
		release()
		if s.Held() != 0 {
			t.Fatal("slot retained")
		}
	}
	if New(0).Size() != 0 {
		t.Fatal("uncapped size")
	}
	synctest.Test(t, func(t *testing.T) {
		s := New(1)
		release, _ := s.Acquire(t.Context(), 0)
		defer release()
		ctx, cancel := context.WithCancel(t.Context())
		go func() { time.Sleep(time.Second); cancel() }()
		if _, ok := s.Acquire(ctx, time.Hour); ok {
			t.Fatal("canceled waiter admitted")
		}
	})
}

func TestCancellationDuringAdmissionReturnsSlot(t *testing.T) {
	var uncapped *Semaphore
	if uncapped.Size() != 0 {
		t.Fatal("nil semaphore has capacity")
	}
	s := New(1)
	s.slots <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if release, ok := s.acquired(ctx); ok || release != nil || s.Held() != 0 {
		t.Fatal("cancellation leaked acquired slot")
	}
}
