// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"testing"
	"time"
)

// TestBackoffDelayNeverBelowScheduleAfterOverflow pins the delay for every
// failure count up to 128. The product form baseDelay * 2^(n-1) wraps once
// it passes 2^63, and a wrapped value can land positive and below MaxDelay:
// with a base of 2^33+1 ns the 32nd failure computes (2^33+1) * 2^31, which
// is 2^64 + 2^31 and wraps to 2.1s in place of the 5m cap. A range check
// on the result cannot see that.
func TestBackoffDelayNeverBelowScheduleAfterOverflow(t *testing.T) {
	now := time.Unix(0, 0)
	base := time.Duration(1<<33 + 1)
	b := NewBackoff(BackoffConfig{
		BaseDelay: base,
		MaxDelay:  5 * time.Minute,
		Now:       func() time.Time { return now },
	})
	want := base
	for n := 1; n <= 128; n++ {
		b.RecordFailure()
		at, open := b.RetryAt()
		if !open {
			t.Fatalf("failure %d: breaker closed", n)
		}
		if got := at.Sub(now); got != want {
			t.Fatalf("failure %d: delay = %v, want %v", n, got, want)
		}
		if want < 5*time.Minute {
			want = min(want*2, 5*time.Minute)
		}
	}
}
