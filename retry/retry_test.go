// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package retry

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestDelayDoublesToCeiling(t *testing.T) {
	p := Policy{Base: time.Second, Max: 10 * time.Second, Jitter: -1}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second, 10 * time.Second}
	for i, w := range want {
		if got := p.Delay(i + 1); got != w {
			t.Fatalf("Delay(%d) = %v, want %v", i+1, got, w)
		}
	}
}

func TestDelayAttemptBelowOneIsFirstDelay(t *testing.T) {
	p := Policy{Base: time.Second, Jitter: -1}
	if got := p.Delay(0); got != time.Second {
		t.Fatalf("Delay(0) = %v, want 1s", got)
	}
	if got := p.Delay(-5); got != time.Second {
		t.Fatalf("Delay(-5) = %v, want 1s", got)
	}
}

func TestDelayDoesNotOverflow(t *testing.T) {
	p := Policy{Base: time.Second, Max: time.Hour, Jitter: -1}
	if got := p.Delay(64); got != time.Hour {
		t.Fatalf("Delay(64) = %v, want 1h", got)
	}
	if got := p.Delay(1 << 20); got != time.Hour {
		t.Fatalf("Delay(1<<20) = %v, want 1h", got)
	}
}

func TestDelayJitterBounds(t *testing.T) {
	p := Policy{Base: time.Second, Max: time.Second, Jitter: 0.5}
	if got := p.delay(1, func() float64 { return 0 }); got != time.Second {
		t.Fatalf("no draw: %v, want 1s", got)
	}
	if got := p.delay(1, func() float64 { return 0.999999 }); got < 500*time.Millisecond || got >= time.Second {
		t.Fatalf("max draw: %v, want in [500ms, 1s)", got)
	}
	for range 1000 {
		got := p.Delay(1)
		if got < 500*time.Millisecond || got > time.Second {
			t.Fatalf("Delay(1) = %v, outside [500ms, 1s]", got)
		}
	}
}

func TestZeroPolicyUsesDefaults(t *testing.T) {
	var p Policy
	if p.Attempts() != DefaultMaxAttempts || p.base() != DefaultBase || p.ceiling() != DefaultMax || p.jitter() != DefaultJitter {
		t.Fatalf("zero policy = %d %v %v %v", p.Attempts(), p.base(), p.ceiling(), p.jitter())
	}
}

func TestPolicyClamps(t *testing.T) {
	p := Policy{Base: time.Minute, Max: time.Second, Jitter: 7}
	if p.ceiling() != time.Minute {
		t.Fatalf("ceiling below base: %v", p.ceiling())
	}
	if p.jitter() != 1 {
		t.Fatalf("jitter above 1: %v", p.jitter())
	}
	if (Policy{Jitter: -1}).jitter() != 0 {
		t.Fatal("negative jitter should mean none")
	}
	if (Policy{Base: time.Hour}).ceiling() != time.Hour {
		t.Fatal("default ceiling should rise to the base")
	}
}

func fast(attempts int) Policy {
	return Policy{MaxAttempts: attempts, Base: time.Microsecond, Max: time.Microsecond, Jitter: -1}
}

func TestDoReturnsNilOnSuccess(t *testing.T) {
	calls := 0
	err := Do(context.Background(), fast(3), func(context.Context) error {
		calls++
		if calls < 2 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("err = %v, calls = %d; want nil, 2", err, calls)
	}
}

func TestDoReturnsLastErrorWhenBudgetSpent(t *testing.T) {
	calls := 0
	err := Do(context.Background(), fast(3), func(context.Context) error {
		calls++
		return fmt.Errorf("attempt %d", calls)
	})
	if calls != 3 || err == nil || err.Error() != "attempt 3" {
		t.Fatalf("err = %v, calls = %d; want attempt 3, 3", err, calls)
	}
}

func TestDoStopsOnStop(t *testing.T) {
	sentinel := errors.New("bad input")
	calls := 0
	err := Do(context.Background(), fast(5), func(context.Context) error {
		calls++
		return Stop(fmt.Errorf("wrapped: %w", sentinel))
	})
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want to wrap sentinel", err)
	}
	if _, ok := errors.AsType[*stopError](err); ok {
		t.Fatal("Do leaked the stop marker to the caller")
	}
}

func TestDoReturnsContextErrorDuringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	p := Policy{MaxAttempts: 5, Base: time.Hour, Jitter: -1}
	err := Do(ctx, p, func(context.Context) error {
		calls++
		cancel()
		return errors.New("transient")
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("err = %v, calls = %d; want context.Canceled, 1", err, calls)
	}
}

func TestStopNilIsNil(t *testing.T) {
	if Stop(nil) != nil {
		t.Fatal("Stop(nil) should be nil")
	}
	err := Stop(errors.New("x"))
	if err.Error() != "x" {
		t.Fatalf("Error() = %q", err.Error())
	}
}
