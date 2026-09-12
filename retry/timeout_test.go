// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package retry

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestAttemptTimeoutRetriesWithFreshContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		var first, second context.Context
		err := Do(t.Context(), Policy{MaxAttempts: 2, Timeout: time.Second, Base: time.Nanosecond}, func(ctx context.Context) error {
			attempts++
			if attempts == 1 {
				first = ctx
				<-ctx.Done()
				return ctx.Err()
			}
			second = ctx
			if ctx.Err() != nil {
				t.Fatal("second attempt reused expired context")
			}
			return nil
		})
		if err != nil || attempts != 2 || !errors.Is(first.Err(), context.DeadlineExceeded) || !errors.Is(second.Err(), context.Canceled) {
			t.Fatalf("attempts=%d err=%v", attempts, err)
		}
	})
}

func TestAttemptParentDeadlineAndExhaustion(t *testing.T) {
	for _, parent := range []time.Duration{time.Second, 10 * time.Second} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), parent)
			defer cancel()
			attempts := 0
			err := Do(ctx, Policy{MaxAttempts: 2, Timeout: 2 * time.Second, Base: time.Nanosecond}, func(ctx context.Context) error { attempts++; <-ctx.Done(); return ctx.Err() })
			want := 2
			if parent == time.Second {
				want = 1
			}
			if !errors.Is(err, context.DeadlineExceeded) || attempts != want {
				t.Fatalf("err=%v attempts=%d", err, attempts)
			}
		})
	}
}

func TestAttemptPermanentErrorReleasesContext(t *testing.T) {
	var child context.Context
	sentinel := errors.New("permanent")
	err := Do(t.Context(), Policy{Timeout: time.Hour}, func(ctx context.Context) error { child = ctx; return Stop(sentinel) })
	if err != sentinel || child.Err() != context.Canceled {
		t.Fatal("permanent error or cancellation lost")
	}
}

func TestCanceledParentStartsNoAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := Do(ctx, Policy{}, func(context.Context) error { t.Fatal("called after cancellation"); return nil })
	if err != context.Canceled {
		t.Fatal(err)
	}
}

func TestDisabledTimeoutPreservesContext(t *testing.T) {
	for _, timeout := range []time.Duration{0, -1} {
		ctx := t.Context()
		if err := Do(ctx, Policy{Timeout: timeout}, func(got context.Context) error {
			if got != ctx {
				t.Fatal("disabled timeout replaced context")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
