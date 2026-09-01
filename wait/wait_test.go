package wait

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSleepReturnsAfterDuration(t *testing.T) {
	start := time.Now()
	if err := Sleep(context.Background(), 20*time.Millisecond); err != nil {
		t.Fatalf("Sleep: %v", err)
	}
	if got := time.Since(start); got < 20*time.Millisecond {
		t.Fatalf("returned after %v, want at least 20ms", got)
	}
}

func TestSleepReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := Sleep(ctx, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := time.Since(start); got > time.Second {
		t.Fatalf("returned after %v, want well under the minute", got)
	}
}

func TestSleepZeroObservesContext(t *testing.T) {
	if err := Sleep(context.Background(), 0); err != nil {
		t.Fatalf("live ctx, d=0: %v", err)
	}
	if err := Sleep(context.Background(), -time.Second); err != nil {
		t.Fatalf("live ctx, d<0: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Sleep(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("done ctx, d=0: err = %v, want context.Canceled", err)
	}
}

func TestEveryTicksUntilCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	Every(ctx, time.Millisecond, func(context.Context) {
		calls++
		if calls == 3 {
			cancel()
		}
	})
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestEveryNonPositiveIntervalReturns(t *testing.T) {
	called := false
	Every(context.Background(), 0, func(context.Context) { called = true })
	Every(context.Background(), -time.Second, func(context.Context) { called = true })
	if called {
		t.Fatal("fn ran with a non-positive interval")
	}
}

func TestEveryDoneContextReturnsWithoutCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	Every(ctx, time.Hour, func(context.Context) { called = true })
	if called {
		t.Fatal("fn ran on a done context")
	}
}

func TestUntilRunsCondImmediately(t *testing.T) {
	calls := 0
	err := Until(context.Background(), time.Hour, func(context.Context) (bool, error) {
		calls++
		return true, nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("err = %v, calls = %d; want nil, 1", err, calls)
	}
}

func TestUntilPollsUntilDone(t *testing.T) {
	calls := 0
	err := Until(context.Background(), time.Millisecond, func(context.Context) (bool, error) {
		calls++
		return calls == 3, nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err = %v, calls = %d; want nil, 3", err, calls)
	}
}

func TestUntilReturnsCondError(t *testing.T) {
	boom := errors.New("boom")
	err := Until(context.Background(), time.Millisecond, func(context.Context) (bool, error) {
		return false, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

func TestUntilReturnsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := Until(ctx, time.Hour, func(context.Context) (bool, error) {
		calls++
		cancel()
		return false, nil
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("err = %v, calls = %d; want context.Canceled, 1", err, calls)
	}
}
