// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"errors"
	"strings"
	"testing"
)

func TestPathDestination(t *testing.T) {
	if got := (Path{Host: "/a/b", Access: ReadWrite}).Destination(); got != "/a/b" {
		t.Errorf("unmapped destination = %q", got)
	}
	if got := (Path{Host: "/a/b", Guest: "/workspace"}).Destination(); got != "/workspace" {
		t.Errorf("mapped destination = %q", got)
	}
}

func TestStageStatusSucceededNeedsAFinishedStage(t *testing.T) {
	for _, c := range []struct {
		status StageStatus
		want   bool
	}{
		{StageStatus{Running: true}, false},
		{StageStatus{}, true},
		{StageStatus{ExitCode: 1}, false},
		{StageStatus{Gone: true}, false},
	} {
		if got := c.status.Succeeded(); got != c.want {
			t.Errorf("%+v.Succeeded() = %v", c.status, got)
		}
	}
}

// TestHandlesDoNotCrossDrivers checks that a handle from one driver is not
// looked up by another. Both are opaque strings, so only this check stops a
// pid from being read as a container name.
func TestHandlesDoNotCrossDrivers(t *testing.T) {
	handle := StageHandle{Driver: Host, ID: "pid:1@2:/log"}
	if err := MatchHandle(Host, handle); err != nil {
		t.Fatalf("matching handle refused: %v", err)
	}
	err := MatchHandle("container", handle)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("cross-driver handle accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "host") || !strings.Contains(err.Error(), "container") {
		t.Errorf("mismatch names only one side: %v", err)
	}
	for _, invalid := range []StageHandle{{}, {Driver: Host}, {ID: "x"}, {Driver: " ", ID: "x"}} {
		if err := MatchHandle(Host, invalid); !errors.Is(err, ErrInvalidHandle) {
			t.Errorf("%+v accepted: %v", invalid, err)
		}
	}
}
