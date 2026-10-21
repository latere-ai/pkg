// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// leakedDescriptors are a socket and a file this process holds open without
// close-on-exec, as a program calling the driver may: every process it
// starts inherits them.
type leakedDescriptors struct {
	// received is what the socket's peer read, closed once the peer is
	// done.
	received chan []byte
	file     string
	// fds are the inheritable copies, closed once by release.
	fds  []int
	once sync.Once
}

// release closes the inheritable copies, so the socket's peer sees the
// socket end. It is idempotent, so a number the system hands out again
// later is never closed by it.
func (l *leakedDescriptors) release() {
	l.once.Do(func() {
		for _, fd := range l.fds {
			_ = syscall.Close(fd)
		}
	})
}

// leak opens a connected socket and a file, and makes a copy of each that a
// child inherits, placed at 900 or above so a probe of the first few
// descriptors alone would miss them.
func leak(t *testing.T) *leakedDescriptors {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	leaked := &leakedDescriptors{received: make(chan []byte, 1), file: filepath.Join(t.TempDir(), "leaked")}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			leaked.received <- nil
			return
		}
		defer func() { _ = conn.Close() }()
		var got bytes.Buffer
		buffer := make([]byte, 512)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buffer)
			got.Write(buffer[:n])
			if err != nil {
				leaked.received <- got.Bytes()
				return
			}
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	socket, err := conn.(*net.TCPConn).File()
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(leaked.file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leaked.release)
	for _, open := range []*os.File{socket, file} {
		leaked.fds = append(leaked.fds, inheritable(t, int(open.Fd())))
		_ = open.Close()
	}
	return leaked
}

// inheritable copies fd to a descriptor at 900 or above that a child
// inherits: F_DUPFD, unlike its close-on-exec form, leaves the flag clear.
func inheritable(t *testing.T, fd int) int {
	t.Helper()
	moved, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD, 900)
	if errno != 0 {
		t.Fatal(errno)
	}
	if flags, err := fcntl(int(moved), syscall.F_GETFD); err != nil || flags&syscall.FD_CLOEXEC != 0 {
		t.Fatalf("the copy is not one a child inherits: flags %d, %v", flags, err)
	}
	return int(moved)
}

// unused checks that nothing the stage wrote reached the socket's peer or
// the file, once the copies this process holds are closed.
func (l *leakedDescriptors) unused(t *testing.T) {
	t.Helper()
	l.release()
	select {
	case got := <-l.received:
		if len(got) != 0 {
			t.Errorf("the stage wrote %q into the leaked socket", got)
		}
	case <-time.After(time.Until(until(t))):
		t.Error("the leaked socket's peer never saw it close")
	}
	if body, err := os.ReadFile(l.file); err != nil || len(body) != 0 {
		t.Errorf("the stage wrote %q into the leaked file, %v", body, err)
	}
}

// TestAStageWithNoNetworkHoldsNothingItsCallerLeaks runs a stage with no
// network, attached and detached, while this process holds a connected
// socket and a file open without close-on-exec, and checks that the stage,
// which writes into every descriptor above stderr it holds, holds neither:
// an inherited socket would carry a stage with no network to the network.
func TestAStageWithNoNetworkHoldsNothingItsCallerLeaks(t *testing.T) {
	driver := seatbelt(t)
	for _, attached := range []bool{true, false} {
		leaked := leak(t)
		spec := stage(t, t.TempDir(), os.Args[0])
		spec.Env = map[string]string{forgeVariable: "1", "GOCOVERDIR": t.TempDir()}
		var output string
		if attached {
			command, cleanup, err := driver.Command(context.Background(), spec)
			if err != nil {
				t.Fatalf("Command: %v", err)
			}
			body, err := command.CombinedOutput()
			cleanup()
			if err != nil {
				t.Fatalf("the stage: %v\n%s", err, body)
			}
			output = string(body)
		} else {
			handle, err := driver.Launch(context.Background(), spec)
			if err != nil {
				t.Fatalf("Launch: %v", err)
			}
			waitFor(t, driver, handle)
			output = readLog(t, driver, handle)
		}
		if !strings.Contains(output, "forged into 0") {
			t.Fatalf("attached %v: the stage held a descriptor it could write: %q", attached, output)
		}
		leaked.unused(t)
	}
}

// TestALauncherBecomesAStageWithNoNetwork runs the launcher in this process
// for a stage with no network, with the exec it would become the stage by
// recorded rather than made: it keeps every descriptor above stderr from the
// stage, serves no proxy, and becomes sandbox-exec with the profile the
// driver rendered and the stage's argv after "--", in an environment
// without the stage file. A launcher that cannot keep its descriptors, or
// cannot become the stage, runs nothing and says why.
func TestALauncherBecomesAStageWithNoNetwork(t *testing.T) {
	leaked := leak(t)
	t.Setenv(stageFileVariable, "/the/stage/file")
	t.Setenv("HOSTSANDBOX_TEST_KEPT", "kept")
	path, policy := writeStage(t, stageFile{Profile: Profile{Network: Network{Mode: NetworkNone}}, Argv: []string{"-dash", "arg"}, SandboxExec: "/usr/bin/sandbox-exec", NoProxy: true})
	saved := execStage
	t.Cleanup(func() { execStage = saved })
	var gotPath string
	var gotArgv, gotEnv []string
	execStage = func(path string, argv, env []string) error {
		gotPath, gotArgv, gotEnv = path, argv, env
		return errors.New("not made in a test")
	}
	stderr := &lockedBuffer{}
	if code := runLauncher(path, strings.NewReader(""), io.Discard, stderr); code != launcherExit || !strings.Contains(stderr.String(), "not made in a test") {
		t.Fatalf("the launcher exited %d: %q", code, stderr.String())
	}
	if want := []string{"/usr/bin/sandbox-exec", "-f", policy, "--", "-dash", "arg"}; gotPath != want[0] || !slices.Equal(gotArgv, want) {
		t.Fatalf("the launcher became %s %v, want %v", gotPath, gotArgv, want)
	}
	if slices.ContainsFunc(gotEnv, func(entry string) bool { return strings.HasPrefix(entry, stageFileVariable+"=") }) ||
		!slices.Contains(gotEnv, "HOSTSANDBOX_TEST_KEPT=kept") ||
		slices.ContainsFunc(gotEnv, func(entry string) bool { return strings.HasPrefix(entry, "HTTPS_PROXY=http://127.0.0.1") }) {
		t.Fatalf("the stage's environment = %v", gotEnv)
	}
	for _, fd := range leaked.fds {
		if flags, err := fcntl(fd, syscall.F_GETFD); err != nil || flags&syscall.FD_CLOEXEC == 0 {
			t.Fatalf("the leaked descriptor %d would reach the stage: flags %d, %v", fd, flags, err)
		}
	}
	savedList := openDescriptors
	t.Cleanup(func() { openDescriptors = savedList })
	openDescriptors = func() ([]os.DirEntry, error) { return nil, errors.New("no descriptor list") }
	gotPath = ""
	stderr = &lockedBuffer{}
	if code := runLauncher(path, strings.NewReader(""), io.Discard, stderr); code != launcherExit || !strings.Contains(stderr.String(), "no descriptor list") || gotPath != "" {
		t.Fatalf("a launcher that cannot keep its descriptors exited %d, became %q: %q", code, gotPath, stderr.String())
	}
}
