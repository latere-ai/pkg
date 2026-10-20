// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// settingsOf returns the path of the settings file an attached command runs
// with: the argument after "--settings".
func settingsOf(t *testing.T, command *exec.Cmd) string {
	t.Helper()
	at := slices.Index(command.Args, "--settings")
	if at < 0 || at+1 >= len(command.Args) {
		t.Fatalf("no settings in %q", command.Args)
	}
	return command.Args[at+1]
}

// TestCommandRunsAStageAttached checks the attached form end to end through a
// stand-in for srt: the caller's stdin reaches the stage and its output and
// exit code come back, the settings are the stage's profile with the settings
// directory denied writing, and the cleanup removes them.
func TestCommandRunsAStageAttached(t *testing.T) {
	home := t.TempDir()
	driver := New(Config{Isolation: IsolationSRT, Home: home, Look: shim(t), Lookup: os.LookupEnv})
	dir := t.TempDir()
	spec := stage(t, dir, "/bin/sh", "-c", `cat; exit 4`)
	spec.Paths = []Path{{Host: dir, Access: ReadWrite}}
	command, cleanup, err := driver.Command(context.Background(), spec)
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	settingsPath := settingsOf(t, command)
	body, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("the settings were not written before the start: %v", err)
	}
	var settings Settings
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if !slices.Contains(settings.Filesystem.DenyRead, home) || !slices.Contains(settings.Filesystem.AllowWrite, dir) {
		t.Fatalf("the settings are not the stage's profile: %+v", settings.Filesystem)
	}
	for _, denied := range []string{filepath.Dir(settingsPath), filepath.Dir(spec.LogPath)} {
		if !slices.Contains(settings.Filesystem.DenyWrite, denied) {
			t.Errorf("%s is writable by the stage: %v", denied, settings.Filesystem.DenyWrite)
		}
	}
	if command.Dir != dir {
		t.Errorf("workdir = %q, want %q", command.Dir, dir)
	}
	command.Stdin = strings.NewReader("from the caller")
	output, err := command.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 4 {
		t.Fatalf("Output = %v, want exit 4", err)
	}
	if string(output) != "from the caller" {
		t.Fatalf("output = %q", output)
	}
	// The log path is not written: output goes to the caller's pipes.
	if _, err := os.Stat(spec.LogPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the attached stage wrote its log: %v", err)
	}
	cleanup()
	cleanup()
	if _, err := os.Stat(filepath.Dir(settingsPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the cleanup left the settings: %v", err)
	}
}

// TestCommandSeparatesTheArgvAndPassesOnlyTheAllowlist checks that the argv
// follows "--" in order, so srt consumes none of its flags, and that the
// stage's environment is the allowlist plus HOME, TERM and its own variables,
// with a credential in the caller's environment left out.
func TestCommandSeparatesTheArgvAndPassesOnlyTheAllowlist(t *testing.T) {
	t.Setenv("HOSTSANDBOX_TEST_CANARY", "leaked-into-the-sandbox")
	home := t.TempDir()
	driver := New(Config{Isolation: IsolationSRT, Home: home, Look: shim(t), Lookup: os.LookupEnv})
	dir := t.TempDir()
	argv := []string{"/bin/sh", "-c", `/usr/bin/env`, "-d", "-s"}
	spec := stage(t, dir, argv...)
	spec.Env = map[string]string{"STAGE_WS": dir}
	command, cleanup, err := driver.Command(context.Background(), spec)
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	defer cleanup()
	separator := slices.Index(command.Args, "--")
	if separator < 0 || !slices.Equal(command.Args[separator+1:], argv) {
		t.Fatalf("args = %q, want %q after --", command.Args, argv)
	}
	output, err := command.Output()
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	seen := string(output)
	if strings.Contains(seen, "HOSTSANDBOX_TEST_CANARY") {
		t.Errorf("the caller's environment reached the stage:\n%s", seen)
	}
	for _, want := range []string{"PATH=", "HOME=" + home, "TERM=dumb", "STAGE_WS=" + dir} {
		if !strings.Contains(seen, want) {
			t.Errorf("the stage did not get %s:\n%s", want, seen)
		}
	}
}

// TestCommandEndsItsGroupWithItsContext checks that the context ending kills
// the stage and a process it started, not only srt's pid: the leftover
// appends to a marker, and after Wait the stage's whole process group
// empties without the marker growing on. Each step waits on its condition,
// bounded by the test's deadline, not on a fixed time.
func TestCommandEndsItsGroupWithItsContext(t *testing.T) {
	driver := New(Config{Isolation: IsolationSRT, Home: t.TempDir(), Look: shim(t), Lookup: os.LookupEnv})
	dir := t.TempDir()
	marker := filepath.Join(dir, "ticks")
	spec := stage(t, dir, "/bin/sh", "-c", `( while :; do echo tick >> "$MARK"; sleep 0.05; done ) & sleep 30`)
	spec.Env = map[string]string{"MARK": marker}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command, cleanup, err := driver.Command(ctx, spec)
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	defer cleanup()
	if err := command.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	exited, waitErr := waitInBackground(command)
	appears(t, marker, mainEnded(exited, waitErr))
	cancel()
	select {
	case <-exited:
		if *waitErr == nil {
			t.Fatal("a stage whose context ended reported success")
		}
	case <-time.After(time.Until(until(t))):
		t.Fatal("the stage outlived its context")
	}
	// Every process of the group dies with it. Once Wait has returned, the
	// group empties as the system finishes the killed processes, which is
	// the condition waited for. A leftover still looping meanwhile appends a
	// tick every 50 milliseconds, so two more ticks fail at once; one more
	// could be a write already under way when the kill came.
	pid := command.Process.Pid
	size := fileSize(t, marker)
	by := until(t)
	for {
		if err := syscall.Kill(-pid, 0); errors.Is(err, syscall.ESRCH) {
			break
		}
		if grown := fileSize(t, marker); grown >= size+2*int64(len("tick\n")) {
			t.Fatalf("the leftover kept running after the context ended: marker grew from %d to %d", size, grown)
		}
		if time.Now().After(by) {
			t.Fatal("the stage's process group outlived its context")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestCommandWaitsForAStageSlowToStart checks that a stage which takes longer
// to reach its first step than the five seconds the tests once allowed is
// waited for, not failed: a loaded machine stalls a stage's startup for many
// seconds, and only the stage's own end or the test's deadline ends the wait.
func TestCommandWaitsForAStageSlowToStart(t *testing.T) {
	driver := New(Config{Isolation: IsolationSRT, Home: t.TempDir(), Look: shim(t), Lookup: os.LookupEnv})
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	spec := stage(t, dir, "/bin/sh", "-c", `sleep 5.5; touch "$MARK"; sleep 30`)
	spec.Env = map[string]string{"MARK": marker}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command, cleanup, err := driver.Command(ctx, spec)
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	defer cleanup()
	if err := command.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	exited, waitErr := waitInBackground(command)
	appears(t, marker, mainEnded(exited, waitErr))
	cancel()
	<-exited
}

// TestWaitForFileEndsWithTheStage checks the two other ends of the wait for a
// stage's file: a stage that has ended without creating it fails the wait at
// once, rather than at the test's deadline, and a deadline that has passed
// ends it too. A file the stage created just before it ended still counts.
func TestWaitForFileEndsWithTheStage(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "never")
	gone := errors.New("exit status 127")
	start := time.Now()
	err := waitForFile(missing, func() error { return gone }, time.Now().Add(time.Hour))
	if !errors.Is(err, gone) {
		t.Fatalf("a stage that ended gave %v, want its error", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the wait for a stage that had ended took %v", elapsed)
	}
	if err := waitForFile(missing, nil, time.Now()); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("a passed deadline gave %v", err)
	}
	present := filepath.Join(dir, "made")
	if err := os.WriteFile(present, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := waitForFile(present, func() error { return gone }, time.Now()); err != nil {
		t.Fatalf("a file made before the stage ended gave %v", err)
	}
}

// mainEnded is, for appears, an attached stage whose main process has
// ended, as waitInBackground reports it.
func mainEnded(exited <-chan struct{}, waitErr *error) func() error {
	return func() error {
		select {
		case <-exited:
			if *waitErr == nil {
				return errors.New("its main process exited with status 0")
			}
			return fmt.Errorf("its main process ended: %w", *waitErr)
		default:
			return nil
		}
	}
}

// waitInBackground waits for command in a goroutine, so a test can tell
// whether the stage's main process has ended while it waits for something
// else. The error is readable once exited is closed.
func waitInBackground(command *exec.Cmd) (exited chan struct{}, err *error) {
	exited = make(chan struct{})
	err = new(error)
	go func() {
		*err = command.Wait()
		close(exited)
	}()
	return exited, err
}

// TestCommandRefusesWhatItCannotRun checks the refusals before a command is
// built: an unready machine, no argv, no PATH, srt gone between the preflight
// and the build, and a temporary directory that cannot be created.
func TestCommandRefusesWhatItCannotRun(t *testing.T) {
	dir := t.TempDir()
	ready := found("srt", "rg", "bwrap", "socat")
	missing := New(Config{Isolation: IsolationSRT, Platform: Darwin, Home: t.TempDir(), Look: found(), Lookup: os.LookupEnv})
	if _, _, err := missing.Command(context.Background(), stage(t, dir, "/bin/sh")); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Command on an unready machine = %v", err)
	}
	driver := New(Config{Isolation: IsolationSRT, Home: t.TempDir(), Look: ready, Lookup: os.LookupEnv})
	if _, _, err := driver.Command(context.Background(), stage(t, dir)); err == nil || !strings.Contains(err.Error(), "argv") {
		t.Fatalf("a stage with no command was built: %v", err)
	}
	noPath := New(Config{Isolation: IsolationSRT, Home: t.TempDir(), Look: ready, Lookup: func(name string) (string, bool) { return "/x", name == "HOME" }})
	if _, _, err := noPath.Command(context.Background(), stage(t, dir, "/bin/sh")); !errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), "PATH") {
		t.Fatalf("Command with no PATH = %v", err)
	}
	// srt resolves for the preflight and is gone when the command is built.
	looks := 0
	vanishing := New(Config{Isolation: IsolationSRT, Home: t.TempDir(), Lookup: os.LookupEnv, Look: func(name string) (string, error) {
		if name == "srt" {
			looks++
			if looks > 1 {
				return "", exec.ErrNotFound
			}
		}
		return ready(name)
	}})
	if _, _, err := vanishing.Command(context.Background(), stage(t, dir, "/bin/sh")); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Command with srt gone = %v", err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", filepath.Join(file, "tmp"))
	if _, cleanup, err := driver.Command(context.Background(), stage(t, dir, "/bin/sh")); err == nil || cleanup != nil {
		t.Fatalf("a temporary directory under a file was accepted: %v", err)
	}
}

// TestKillGroupReportsAnEmptyGroupAsDone checks that cancelling a command
// whose group has already emptied reads as a command that finished, which
// exec.Cmd needs to report the command's own exit status.
func TestKillGroupReportsAnEmptyGroupAsDone(t *testing.T) {
	sleeper := exec.Command("/bin/sh", "-c", "exit 0")
	sleeper.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := sleeper.Run(); err != nil {
		t.Fatal(err)
	}
	if err := killGroup(sleeper.Process.Pid); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("killGroup on an empty group = %v", err)
	}
}
