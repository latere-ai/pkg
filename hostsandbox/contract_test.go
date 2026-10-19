// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	driver := hostsandbox.New(hostsandbox.Config{Isolation: hostsandbox.IsolationSRT, Home: home, Lookup: os.LookupEnv, StopGrace: 2 * time.Second})
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
			Copy: func() []string { return []string{"/bin/cat"} },
			Orphan: func(d time.Duration) []string {
				return []string{"/bin/sh", "-c", fmt.Sprintf("(i=0; while [ $i -lt %d ]; do echo tick; sleep 0.1; i=$((i+1)); done) & exit 0", int(d/(100*time.Millisecond)))}
			},
		}
	})
}

// TestDriverMeetsTheContractUnderSeatbelt runs the contract suite through
// macOS's own Seatbelt where sandbox-exec is present, and reports why it was
// skipped where it is not. As under srt, the home directory is the
// operator's and nothing is written there.
func TestDriverMeetsTheContractUnderSeatbelt(t *testing.T) {
	home, _ := os.UserHomeDir()
	driver := hostsandbox.New(hostsandbox.Config{Isolation: hostsandbox.IsolationSeatbelt, Home: home, Lookup: os.LookupEnv, StopGrace: 2 * time.Second})
	if err := driver.Preflight(context.Background()); err != nil {
		t.Skipf("Seatbelt is not available here, so its contract is unchecked:\n%v", err)
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
			Copy: func() []string { return []string{"/bin/cat"} },
			Orphan: func(d time.Duration) []string {
				return []string{"/bin/sh", "-c", fmt.Sprintf("(i=0; while [ $i -lt %d ]; do echo tick; sleep 0.1; i=$((i+1)); done) & exit 0", int(d/(100*time.Millisecond)))}
			},
		}
	})
}

// TestCommandIsConfinedUnderSRT runs the attached form through a real srt
// where one is installed: a granted file inside the home directory is
// readable, a file beside it that is not granted is not, and neither is a
// path on the always-deny table even inside the grant. The home directory is
// a temporary one, resolved through its links because the operating system
// sandbox checks real paths.
func TestCommandIsConfinedUnderSRT(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	driver := hostsandbox.New(hostsandbox.Config{Isolation: hostsandbox.IsolationSRT, Home: home, Lookup: os.LookupEnv})
	if err := driver.Preflight(context.Background()); err != nil {
		t.Skipf("the host sandbox is not installed here, so the attached form is unchecked under srt:\n%v", err)
	}
	granted := filepath.Join(home, "project")
	for path, body := range map[string]string{
		filepath.Join(granted, "notes.txt"):   "granted",
		filepath.Join(home, "outside.txt"):    "outside",
		filepath.Join(home, ".ssh", "id_key"): "private",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(paths []hostsandbox.Path, file string) (string, error) {
		t.Helper()
		command, cleanup, err := driver.Command(context.Background(), hostsandbox.StageSpec{
			Name:    "attached",
			Argv:    []string{"/bin/cat", file},
			Workdir: granted,
			Paths:   paths,
			Network: hostsandbox.Network{Mode: hostsandbox.NetworkNone},
		})
		if err != nil {
			t.Fatalf("Command: %v", err)
		}
		defer cleanup()
		output, err := command.Output()
		return string(output), err
	}
	project := []hostsandbox.Path{{Host: granted, Access: hostsandbox.ReadWrite}}
	if output, err := run(project, filepath.Join(granted, "notes.txt")); err != nil || output != "granted" {
		t.Fatalf("the granted file = %q, %v", output, err)
	}
	if output, err := run(project, filepath.Join(home, "outside.txt")); err == nil {
		t.Fatalf("a file outside the grant was read: %q", output)
	}
	whole := []hostsandbox.Path{{Host: home, Access: hostsandbox.ReadOnly}}
	if output, err := run(whole, filepath.Join(home, ".ssh", "id_key")); err == nil {
		t.Fatalf("a path on the always-deny table was read inside a grant: %q", output)
	}
	command, cleanup, err := driver.Command(context.Background(), hostsandbox.StageSpec{
		Name: "attached", Argv: []string{"/bin/cat"}, Workdir: granted, Paths: project,
		Network: hostsandbox.Network{Mode: hostsandbox.NetworkNone},
	})
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	defer cleanup()
	command.Stdin = strings.NewReader("through srt")
	if output, err := command.Output(); err != nil || string(output) != "through srt" {
		t.Fatalf("stdin under srt = %q, %v", output, err)
	}
}
