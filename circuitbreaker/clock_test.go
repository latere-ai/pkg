// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"testing"
	"time"
)

func TestClockControlsOpenWindows(t *testing.T) {
	now := time.Unix(100, 0)
	b := New(1, time.Minute, WithClock(func() time.Time { return now }))
	b.RecordFailure()
	now = now.Add(time.Minute - time.Nanosecond)
	if b.Allow() {
		t.Fatal("probe admitted before cooldown")
	}
	now = now.Add(time.Nanosecond)
	if !b.Allow() || b.Allow() {
		t.Fatal("exactly one probe must be admitted at deadline")
	}
	b.RecordFailure()
	if b.Allow() {
		t.Fatal("failed probe did not restart cooldown")
	}
	now = now.Add(time.Minute)
	if !b.Allow() {
		t.Fatal("second cooldown did not expire")
	}
	b.RecordSuccess()
	if !b.Allow() || b.Failures() != 0 {
		t.Fatal("success did not reset breaker")
	}
}

func TestNilClockUsesWallTime(t *testing.T) {
	b := New(1, time.Hour, WithClock(nil))
	b.RecordFailure()
	if b.Allow() {
		t.Fatal("nil clock did not retain wall clock")
	}
}
