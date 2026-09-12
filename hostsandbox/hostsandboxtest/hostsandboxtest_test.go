// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandboxtest_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"latere.ai/x/pkg/hostsandbox"
	"latere.ai/x/pkg/hostsandbox/hostsandboxtest"
)

// TestTheSuiteAcceptsTheDriver runs the contract against the srt driver with
// a stand-in for srt that drops `--settings <file> --` and runs the command,
// so the suite runs on a machine with nothing installed. The suite is about
// the driver's bookkeeping; srt's isolation is the driver's own test.
func TestTheSuiteAcceptsTheDriver(t *testing.T) {
	shim := filepath.Join(t.TempDir(), "srt")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nshift 3\nexec \"$@\"\n"), 0o700); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	look := func(name string) (string, error) {
		if name == "srt" {
			return shim, nil
		}
		return "/bin/echo", nil
	}
	hostsandboxtest.Run(t, func(t *testing.T) *hostsandboxtest.Subject {
		return &hostsandboxtest.Subject{
			Driver: hostsandbox.New(hostsandbox.Config{Home: t.TempDir(), Look: look, Lookup: os.LookupEnv, StopGrace: time.Second}),
			Dir:    t.TempDir(),
			Print: func(text string, code int) []string {
				return []string{"/bin/sh", "-c", fmt.Sprintf("printf %%s %q; exit %d", text, code)}
			},
			Wait: func(d time.Duration) []string {
				return []string{"/bin/sh", "-c", fmt.Sprintf("sleep %d", int(d.Seconds()))}
			},
		}
	})
}
