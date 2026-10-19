// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"testing"
)

// A program keeps its mechanism until it adopts Seatbelt.

// TestAutoKeepsSrtWithoutALauncher checks that a program that has not called
// Main keeps srt under IsolationAuto, so its Preflight still asks for srt,
// and gets Seatbelt once it has.
func TestAutoKeepsSrtWithoutALauncher(t *testing.T) {
	none := func(string) (string, error) { return "", exec.ErrNotFound }
	if got := New(Config{Platform: Darwin}).Isolation(); got != IsolationSeatbelt {
		t.Fatalf("with Main called, Auto on macOS = %q", got)
	}
	withoutLauncher(t)
	driver := New(Config{Platform: Darwin, Look: none})
	if got := driver.Isolation(); got != IsolationSRT {
		t.Fatalf("without Main, Auto on macOS = %q, want srt", got)
	}
	var notReady *NotReadyError
	if err := driver.Preflight(context.Background()); !errors.As(err, &notReady) || !slices.Equal(notReady.Components, []string{"srt"}) {
		t.Fatalf("without Main, Preflight = %v, want srt asked for", err)
	}
	if !driver.Capabilities().NetworkModes[NetworkAllowlist] {
		t.Fatal("without Main, srt's allowlist is not declared")
	}
	if got := New(Config{Isolation: IsolationSeatbelt, Platform: Darwin}).Isolation(); got != IsolationSeatbelt {
		t.Fatalf("an explicit Seatbelt without Main = %q", got)
	}
}
