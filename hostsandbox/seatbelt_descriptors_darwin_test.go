// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// What a stage inherits under macOS's own Seatbelt, which only darwin has.

//go:build darwin

package hostsandbox

import (
	"os"
	"strings"
	"testing"
)

// TestSeatbeltStageWithNoNetworkHoldsNothingItsCallerLeaks runs a stage with
// no network under the real Seatbelt while this process holds a connected
// socket and a file open without close-on-exec, and checks that the stage,
// writing into every descriptor above stderr it holds, reaches neither, so
// no descriptor its caller leaks carries it to the network or to a file its
// profile denies.
func TestSeatbeltStageWithNoNetworkHoldsNothingItsCallerLeaks(t *testing.T) {
	driver, home := seatbeltHere(t)
	leaked := leak(t)
	env := coverage(t)
	env[forgeVariable] = "1"
	output, err := attached(t, driver, StageSpec{
		Name: "forge", Argv: []string{os.Args[0]}, Workdir: home, Env: env,
		Paths:   []Path{{Host: home, Access: ReadWrite}, {Host: env["GOCOVERDIR"], Access: ReadWrite}},
		Network: Network{Mode: NetworkNone},
	})
	if err != nil || !strings.Contains(output, "forged into 0") {
		t.Fatalf("the stage held a descriptor it could write: %q, %v", output, err)
	}
	leaked.unused(t)
}
