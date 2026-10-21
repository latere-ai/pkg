// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// The clone stage and this check build on macOS alone, where the clone
// system call and the Seatbelt driver both live.

//go:build darwin

package hostsandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// cloneStage, set here because the clone system call is macOS's, clones
// source onto dest from inside the sandbox and reports whether the kernel
// allowed it. The driver starts this test binary as the stage.
func init() {
	cloneStage = func(source, dest string) int {
		if err := unix.Clonefile(source, dest, 0); err != nil {
			return 1
		}
		return 0
	}
}

// TestADirectoryCloneIsRefused runs, under the real Seatbelt, a stage that
// clones a readable directory holding a file withheld from it into a grant
// it may write, and checks the clone is refused and the withheld file does
// not reach the copy, while cloning a readable file still works and an
// ordinary recursive copy inside the grant, which falls back to copying when
// a clone is refused, still works.
func TestADirectoryCloneIsRefused(t *testing.T) {
	driver, home := realSeatbelt(t)
	source, destination := filepath.Join(home, "source"), filepath.Join(home, "dest")
	secret := filepath.Join(source, "a", "b", "secret")
	for path, body := range map[string]string{
		secret:                              "withheld",
		filepath.Join(source, "a", "plain"): "readable",
		filepath.Join(destination, "keep"):  "kept",
		filepath.Join(destination, "sub", "inner", "file"): "copied",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	clone := func(src, dst string) error {
		env := coverage(t)
		env[cloneSourceVariable], env[cloneDestVariable] = src, dst
		_, err := attached(t, driver, StageSpec{
			Name: "clone", Argv: []string{os.Args[0]}, Workdir: destination, Env: env,
			Paths:  []Path{{Host: source, Access: ReadOnly}, {Host: destination, Access: ReadWrite}},
			Denied: []string{secret}, Network: Network{Mode: NetworkNone},
		})
		return err
	}
	// Cloning the directory that holds the withheld file is refused, and the
	// file does not reach a copy.
	copied := filepath.Join(destination, "copy")
	if err := clone(filepath.Join(source, "a"), copied); err == nil {
		t.Error("cloning a directory was allowed")
	}
	if _, err := os.Stat(filepath.Join(copied, "b", "secret")); err == nil {
		t.Error("the withheld file reached the clone")
	}
	// Cloning a readable file still works.
	cloned := filepath.Join(destination, "plain")
	if err := clone(filepath.Join(source, "a", "plain"), cloned); err != nil {
		t.Errorf("cloning a readable file was refused: %v", err)
	}
	if body, err := os.ReadFile(cloned); err != nil || string(body) != "readable" {
		t.Errorf("the file clone = %q, %v", body, err)
	}
	// An ordinary recursive copy inside the grant still works, falling back
	// to copying when the clone is refused.
	if output, err := attached(t, driver, StageSpec{
		Name: "copy", Workdir: destination, Network: Network{Mode: NetworkNone},
		Argv:  []string{"/bin/sh", "-c", "cp -R " + ShellQuote(filepath.Join(destination, "sub")) + " " + ShellQuote(filepath.Join(destination, "sub-copy")) + " && cat " + ShellQuote(filepath.Join(destination, "sub-copy", "inner", "file"))},
		Paths: []Path{{Host: destination, Access: ReadWrite}},
	}); err != nil || !strings.Contains(output, "copied") {
		t.Errorf("an ordinary recursive copy inside the grant failed: %q, %v", output, err)
	}
}
