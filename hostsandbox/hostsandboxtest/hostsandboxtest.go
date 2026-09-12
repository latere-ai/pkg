// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package hostsandboxtest is the contract suite every hostsandbox.Sandbox is
// held to. A consumer assumes four things of any driver: a stage outlives the
// process that launched it, its exit status is recoverable after that process
// is gone, its output is readable from an offset out of a location the stage
// cannot write, and its handle is refused by any other driver. Run drives one
// driver through all four.
package hostsandboxtest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pkg/hostsandbox"
)

// Subject is one driver under test, together with the commands it can run.
// The commands differ per driver, because one runs in the host's shell and
// another inside an image, so the suite asks for them rather than assuming
// them.
type Subject struct {
	// Driver is the implementation under test.
	Driver hostsandbox.Sandbox
	// Print builds an argv that writes text to stdout and exits with code.
	Print func(text string, code int) []string
	// Wait builds an argv that stays alive for at least the given duration.
	Wait func(d time.Duration) []string
	// Dir is a writable directory the stage may use. The suite puts the
	// workspace and the log directory under it.
	Dir string
}

// Timeout bounds how long the suite waits for a stage to finish.
const Timeout = 30 * time.Second

// Run drives one driver through the contract. newSubject is called once per
// case, so every case starts from a fresh directory.
func Run(t *testing.T, newSubject func(t *testing.T) *Subject) {
	t.Helper()

	t.Run("a stage runs, exits, and reports its status", func(t *testing.T) {
		subject := newSubject(t)
		handle := subject.launch(t, subject.Print("hello sandbox", 0))
		status := subject.waitFor(t, handle)
		expect(t, status.Succeeded(), "status = %+v, want a zero exit", status)
		body := subject.readAll(t, handle, 0)
		expect(t, bytes.Contains(body, []byte("hello sandbox")), "output = %q, want the printed text", body)
	})

	t.Run("a non-zero exit is reported, not swallowed", func(t *testing.T) {
		subject := newSubject(t)
		handle := subject.launch(t, subject.Print("failing", 3))
		status := subject.waitFor(t, handle)
		expect(t, !status.Succeeded() && status.ExitCode == 3, "status = %+v, want exit 3", status)
	})

	t.Run("output is readable from an offset", func(t *testing.T) {
		subject := newSubject(t)
		handle := subject.launch(t, subject.Print("abcdefgh", 0))
		subject.waitFor(t, handle)
		whole := subject.readAll(t, handle, 0)
		expect(t, len(whole) >= 4, "output = %q, want at least four bytes", whole)
		tail := subject.readAll(t, handle, 4)
		expect(t, bytes.Equal(whole[4:], tail), "reading from an offset diverged:\nwhole %q\ntail  %q", whole, tail)
	})

	t.Run("a running stage can be stopped", func(t *testing.T) {
		subject := newSubject(t)
		handle := subject.launch(t, subject.Wait(Timeout))
		must(t, subject.Driver.Stop(context.Background(), handle), "Stop")
		status := subject.waitFor(t, handle)
		expect(t, !status.Running, "a stopped stage is still running: %+v", status)
		// Stopping twice, and stopping a stage that has already finished,
		// both succeed. A controller cancels without knowing the state.
		must(t, subject.Driver.Stop(context.Background(), handle), "repeated Stop")
	})

	t.Run("discard is idempotent and leaves the log", func(t *testing.T) {
		subject := newSubject(t)
		spec := subject.spec(t, subject.Print("done", 0))
		handle, err := subject.Driver.Launch(context.Background(), spec)
		must(t, err, "Launch")
		subject.waitFor(t, handle)
		for range 2 {
			must(t, subject.Driver.Discard(context.Background(), handle), "Discard")
		}
		_, err = os.Stat(spec.LogPath)
		must(t, err, "the stage log after Discard; the log is the consumer's")
	})

	t.Run("a handle from another driver is refused", func(t *testing.T) {
		subject := newSubject(t)
		other := hostsandbox.StageHandle{Driver: "not-this-one", ID: "x"}
		_, err := subject.Driver.Observe(context.Background(), other)
		expect(t, errors.Is(err, hostsandbox.ErrMismatch), "Observe = %v, want ErrMismatch", err)
		_, err = subject.Driver.Output(context.Background(), other, 0)
		expect(t, errors.Is(err, hostsandbox.ErrMismatch), "Output = %v, want ErrMismatch", err)
		err = subject.Driver.Stop(context.Background(), other)
		expect(t, errors.Is(err, hostsandbox.ErrMismatch), "Stop = %v, want ErrMismatch", err)
		err = subject.Driver.Discard(context.Background(), other)
		expect(t, errors.Is(err, hostsandbox.ErrMismatch), "Discard = %v, want ErrMismatch", err)
	})

	t.Run("the declaration names what it enforces", func(t *testing.T) {
		subject := newSubject(t)
		capabilities := subject.Driver.Capabilities()
		expect(t, len(capabilities.NetworkModes) > 0, "a driver that declares no network mode can run nothing")
		expect(t, capabilities.NetworkModes[hostsandbox.NetworkNone], "every driver must be able to close the network")
	})
}

// spec builds a stage whose log is in a directory the stage is not granted.
// The log file is created before the launch, because it is the consumer's
// file: a driver that writes the stage's output appends to it, and a driver
// that streams the output from elsewhere leaves it alone. Either way it must
// survive Discard.
func (s *Subject) spec(t *testing.T, argv []string) hostsandbox.StageSpec {
	t.Helper()
	logDir := filepath.Join(s.Dir, "log")
	must(t, os.MkdirAll(logDir, 0o700), "mkdir log")
	workspace := filepath.Join(s.Dir, "workspace")
	must(t, os.MkdirAll(workspace, 0o700), "mkdir workspace")
	name := stageName(t)
	logPath := filepath.Join(logDir, name+".log")
	must(t, os.WriteFile(logPath, nil, 0o600), "create the stage log")
	return hostsandbox.StageSpec{
		Name:    name,
		Argv:    argv,
		Workdir: workspace,
		Paths:   []hostsandbox.Path{{Host: workspace, Guest: "/workspace", Access: hostsandbox.ReadWrite}},
		Network: hostsandbox.Network{Mode: hostsandbox.NetworkNone},
		LogPath: logPath,
	}
}

// stageName is a stage name unique to the case that asked for it, so that a
// driver which names what it creates after the stage, as a container driver
// does, does not collide with the stage the previous case launched.
func stageName(t *testing.T) string {
	t.Helper()
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		default:
			return '-'
		}
	}, t.Name())
	return "stage-" + strings.Trim(safe, "-")
}

func (s *Subject) launch(t *testing.T, argv []string) hostsandbox.StageHandle {
	t.Helper()
	handle, err := s.Driver.Launch(context.Background(), s.spec(t, argv))
	must(t, err, "Launch")
	return handle
}

func (s *Subject) waitFor(t *testing.T, handle hostsandbox.StageHandle) hostsandbox.StageStatus {
	t.Helper()
	deadline := time.Now().Add(Timeout)
	for time.Now().Before(deadline) {
		status, err := s.Driver.Observe(context.Background(), handle)
		must(t, err, "Observe")
		if !status.Running {
			return status
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the stage did not finish within %v", Timeout)
	return hostsandbox.StageStatus{}
}

func (s *Subject) readAll(t *testing.T, handle hostsandbox.StageHandle, offset int64) []byte {
	t.Helper()
	stream, err := s.Driver.Output(context.Background(), handle, offset)
	must(t, err, "Output")
	defer func() { _ = stream.Close() }()
	body, err := io.ReadAll(stream)
	must(t, err, "read output")
	return body
}

func must(t *testing.T, err error, operation string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
}

func expect(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}
