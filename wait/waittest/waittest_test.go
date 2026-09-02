// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package waittest

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// recorder captures Fatalf instead of ending the test, so For's failure path
// can be asserted from inside a passing test.
type recorder struct {
	testing.TB
	failed string
}

func (r *recorder) Helper() {}

func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = fmt.Sprintf(format, args...)
}

func TestForReturnsWhenConditionHolds(t *testing.T) {
	var n atomic.Int32
	go func() {
		time.Sleep(20 * time.Millisecond)
		n.Store(1)
	}()
	rec := &recorder{TB: t}
	For(rec, time.Second, func() bool { return n.Load() == 1 })
	if rec.failed != "" {
		t.Fatalf("For failed: %s", rec.failed)
	}
}

func TestForReportsTimeout(t *testing.T) {
	rec := &recorder{TB: t}
	For(rec, 30*time.Millisecond, func() bool { return false })
	if !strings.Contains(rec.failed, "30ms") {
		t.Fatalf("failure = %q, want the timeout named", rec.failed)
	}
}

func TestForChecksBeforeSleeping(t *testing.T) {
	calls := 0
	start := time.Now()
	For(t, time.Second, func() bool { calls++; return true })
	if calls != 1 || time.Since(start) >= Interval {
		t.Fatalf("calls = %d after %v; want 1 call with no pause", calls, time.Since(start))
	}
}
