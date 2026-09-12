// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"latere.ai/x/pkg/hostsandbox"
	"latere.ai/x/pkg/hostsandbox/hostsandboxtest"
)

// TestDriverMeetsTheContractUnderSRT runs the contract suite through a real
// srt where one is installed, and reports why it was skipped where it is
// not. The home directory is the operator's, because the profile denies it;
// nothing is written there. Everything the stages touch is under a temporary
// directory.
func TestDriverMeetsTheContractUnderSRT(t *testing.T) {
	home, _ := os.UserHomeDir()
	driver := hostsandbox.New(hostsandbox.Config{Home: home, Lookup: os.LookupEnv, StopGrace: 2 * time.Second})
	if err := driver.Preflight(context.Background()); err != nil {
		t.Skipf("the host sandbox is not installed here, so its contract is unchecked under srt:\n%v", err)
	}
	hostsandboxtest.Run(t, func(t *testing.T) *hostsandboxtest.Subject {
		return &hostsandboxtest.Subject{
			Driver: driver,
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
