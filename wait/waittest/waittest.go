// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package waittest polls a condition in a test until it holds or a deadline
// passes. It replaces the deadline-loop-sleep block that every test with a
// background goroutine otherwise writes for itself, each with its own
// timeout and its own sleep.
package waittest

import (
	"testing"
	"time"
)

// Interval is the pause between polls.
const Interval = 10 * time.Millisecond

// For fails t when cond is still false after timeout. It returns as soon as
// cond reports true. cond runs on the calling goroutine, so it must read
// shared state through whatever synchronisation the code under test
// provides.
func For(t testing.TB, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition still false after %v", timeout)
			return
		}
		time.Sleep(Interval)
	}
}
