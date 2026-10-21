// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// What a stage inherits under macOS's own Seatbelt, which only darwin has.

//go:build darwin

package hostsandbox

import (
	"context"
	"os"
	"path/filepath"
	"slices"
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

// TestSeatbeltLauncherStartsWithoutTheLoadersVariables checks under the real
// Seatbelt that a stage's DYLD_* variables reach neither its launcher, which
// runs outside the sandbox, nor the stage, attached or detached and whatever
// its network, while its other variables reach the stage.
func TestSeatbeltLauncherStartsWithoutTheLoadersVariables(t *testing.T) {
	driver, home := seatbeltHere(t)
	for _, network := range []Network{{Mode: NetworkNone}, {Mode: NetworkAllowlist, Domains: []string{"example.com"}}, {Mode: NetworkDenylist}} {
		env := coverage(t)
		env["DYLD_INSERT_LIBRARIES"], env["DYLD_LIBRARY_PATH"], env["STAGE_VALUE"] = home+"/left.dylib", home, "kept"
		spec := StageSpec{
			Name: "env", Argv: []string{"/usr/bin/env"}, Workdir: home, Env: env,
			Paths: []Path{{Host: home, Access: ReadWrite}}, Network: network,
			LogPath: filepath.Join(t.TempDir(), "env.log"),
		}
		command, cleanup, err := driver.Command(context.Background(), spec)
		if err != nil {
			t.Fatalf("Command: %v", err)
		}
		if slices.ContainsFunc(command.Env, func(entry string) bool { return strings.HasPrefix(entry, "DYLD_") }) {
			t.Fatalf("%s: the launcher starts with the loader's variables", network.Mode)
		}
		output, err := command.Output()
		cleanup()
		if err != nil || !strings.Contains(string(output), "STAGE_VALUE=kept") || strings.Contains(string(output), "DYLD_") {
			t.Fatalf("%s: the attached stage's environment = %q, %v", network.Mode, output, err)
		}
		handle, err := driver.Launch(context.Background(), spec)
		if err != nil {
			t.Fatalf("Launch: %v", err)
		}
		waitFor(t, driver, handle)
		if log := readLog(t, driver, handle); !strings.Contains(log, "STAGE_VALUE=kept") || strings.Contains(log, "DYLD_") {
			t.Fatalf("%s: the launched stage's environment = %q", network.Mode, log)
		}
	}
}
