// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
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

// found returns a Look that resolves only the named executables, so that a
// preflight can be tested on a machine that has none of them.
func found(names ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		if slices.Contains(names, name) {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
}

// shim writes a stand-in for srt that drops `--settings <file> --` and runs
// the command, and returns a Look that resolves srt to it and everything else
// to /bin/echo. What is under test is the driver's bookkeeping, not srt's
// isolation.
func shim(t *testing.T) func(string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "srt")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nshift 3\nexec \"$@\"\n"), 0o700); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	return func(name string) (string, error) {
		if name == "srt" {
			return path, nil
		}
		return "/bin/echo", nil
	}
}

// stage builds a spec whose log is in a directory of its own under dir.
func stage(t *testing.T, dir string, argv ...string) StageSpec {
	t.Helper()
	logDir := filepath.Join(dir, "log")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return StageSpec{
		Name: "worker-0", Argv: argv, Workdir: dir,
		Network: Network{Mode: NetworkNone},
		LogPath: filepath.Join(logDir, "worker-0.log"),
	}
}

func waitFor(t *testing.T, driver *Driver, handle StageHandle) StageStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, err := driver.Observe(context.Background(), handle)
		if err != nil {
			t.Fatalf("Observe: %v", err)
		}
		if !status.Running {
			return status
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the stage never finished")
	return StageStatus{}
}

// TestPreflightRefusalsAreActionable checks that every way a machine can be
// unready produces a refusal that names what to install and the consumer's
// alternative. None of the cases needs srt installed.
func TestPreflightRefusalsAreActionable(t *testing.T) {
	cases := []struct {
		name     string
		platform Platform
		look     func(string) (string, error)
		want     []string
	}{
		{"no srt on macOS", Darwin, found(), []string{"(srt: missing)", "npm install -g @anthropic-ai/sandbox-runtime"}},
		{"no bubblewrap on Linux", Linux, found("srt", "rg"), []string{"(bubblewrap, socat: missing)", "apt-get"}},
		{"no ripgrep on macOS", Darwin, found("srt"), []string{"(rg: missing)", "brew install ripgrep"}},
		{"no required program", Darwin, found("srt", "rg"), []string{"(claude: missing)", "npm install -g @anthropic-ai/claude-code", "claude --version"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			driver := New(Config{
				Platform: c.platform, Look: c.look, Home: "/home/x",
				Requires:    []string{"claude"},
				Remedies:    Remedies{"claude": {Install: map[Platform][]string{Darwin: {"npm install -g @anthropic-ai/claude-code"}}, Verify: "claude --version"}},
				Alternative: "Or run in a container instead:  --sandbox container",
			})
			err := driver.Preflight(context.Background())
			if !errors.Is(err, ErrNotReady) {
				t.Fatalf("Preflight = %v", err)
			}
			for _, want := range append(c.want, "--sandbox container") {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("message missing %q:\n%s", want, err)
				}
			}
		})
	}
	ready := New(Config{Platform: Darwin, Look: found("srt", "rg", "claude"), Requires: []string{" claude "}, Home: "/home/x"})
	if err := ready.Preflight(context.Background()); err != nil {
		t.Fatalf("a ready machine was refused: %v", err)
	}
	if ready.Name() != Host || ready.Capabilities().NetworkModes[NetworkOpen] || !ready.Capabilities().NetworkModes[NetworkAllowlist] {
		t.Errorf("declaration = %s %+v", ready.Name(), ready.Capabilities())
	}
	// Windows is refused regardless of what is installed.
	windows := New(Config{Platform: Windows, Look: found("srt", "rg"), Alternative: "elsewhere"})
	err := windows.Preflight(context.Background())
	if !errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), "WSL2") || !strings.Contains(err.Error(), "elsewhere") {
		t.Fatalf("windows = %v", err)
	}
}

// TestTheProfileIsBuiltFromTheStagePaths checks that the stage's paths and
// denials determine its access and that the driver adds only the log
// directory denial and the required programs' directories.
func TestTheProfileIsBuiltFromTheStagePaths(t *testing.T) {
	bin := t.TempDir()
	real := filepath.Join(bin, "lib", "node_modules", "claude", "cli.js")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	look := func(name string) (string, error) {
		if name == "claude" {
			return link, nil
		}
		return "", exec.ErrNotFound
	}
	driver := New(Config{Platform: Darwin, Home: "/Users/x", Look: look, Requires: []string{"claude", "absent"}})
	settings := Render(driver.Profile(StageSpec{
		Name: "judge-1",
		Paths: []Path{
			{Host: "/s/workspace", Guest: "/workspace", Access: ReadOnly},
			{Host: "/s/grade", Guest: "/grade", Access: ReadWrite},
			{Host: "/Users/x/Library/Keychains", Access: ReadOnly},
		},
		Denied:       []string{"/Users/x/.claude/CLAUDE.md", "~/.claude/plugins"},
		DeniedWrites: []string{"/s/session"},
		Network:      Network{Mode: NetworkOpen},
		LogPath:      "/s/session/raw/judge-1.log",
	}))
	if slices.Contains(settings.Filesystem.AllowWrite, "/s/workspace") || slices.Contains(settings.Filesystem.AllowWrite, "/Users/x/Library/Keychains") {
		t.Fatalf("a read-only path is writable: %v", settings.Filesystem.AllowWrite)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/s/workspace", "/s/grade", "/Users/x/Library/Keychains", filepath.Dir(link), filepath.Dir(resolved)} {
		if !slices.Contains(settings.Filesystem.AllowRead, want) {
			t.Errorf("%s is not readable: %v", want, settings.Filesystem.AllowRead)
		}
	}
	if !slices.Contains(settings.Filesystem.AllowWrite, "/s/grade") {
		t.Fatalf("the writable path is not writable: %v", settings.Filesystem.AllowWrite)
	}
	for _, want := range []string{"/s/session", "/s/session/raw"} {
		if !slices.Contains(settings.Filesystem.DenyWrite, want) {
			t.Errorf("%s is writable: %v", want, settings.Filesystem.DenyWrite)
		}
	}
	for _, want := range []string{"/Users/x/.claude/CLAUDE.md", "/Users/x/.claude/plugins", "/Users/x"} {
		if !slices.Contains(settings.Filesystem.DenyRead, want) {
			t.Errorf("%s reaches the stage: %v", want, settings.Filesystem.DenyRead)
		}
	}
	// A stage with no log path is denied nothing extra rather than the
	// current directory.
	if writes := driver.Profile(StageSpec{}).DenyWrites; len(writes) != 0 {
		t.Errorf("a stage with no log denies %v", writes)
	}
}

// TestCredentialsTravelInTheEnvironmentNotTheCommandLine checks that a
// credential named in EnvFile reaches the stage through the launcher's
// environment, which the process table does not show, and never through the
// argv.
func TestCredentialsTravelInTheEnvironmentNotTheCommandLine(t *testing.T) {
	driver := New(Config{Platform: Darwin, Home: t.TempDir(), Look: found("srt", "rg")})
	spec := StageSpec{
		Name:    "worker-0",
		Argv:    []string{"claude", "--print", "--", "reproduce it"},
		Env:     map[string]string{"ANTHROPIC_API_KEY": "sk-secret", "TMPDIR": "/s/tmp"},
		EnvFile: []string{"ANTHROPIC_API_KEY"},
	}
	environment := driver.environment([]string{"PATH=/bin"}, spec)
	if !slices.Contains(environment, "ANTHROPIC_API_KEY=sk-secret") || !slices.Contains(environment, "TERM=dumb") {
		t.Fatalf("environment = %v", environment)
	}
	if strings.Contains(wrapperScript(spec.Argv, "/s/log/worker-0.status"), "sk-secret") {
		t.Fatal("the credential is in the command line")
	}
}

// TestTheCommandIsSeparatedFromTheSandboxsOwnFlags checks that the argv is
// separated from srt's own options by "--", every element quoted and in
// order, and that the status is renamed into place rather than written to the
// path it is read from.
func TestTheCommandIsSeparatedFromTheSandboxsOwnFlags(t *testing.T) {
	argv := []string{"claude", "--print", "-d", "-s", "-c", "--", "it's"}
	script := wrapperScript(append([]string{"/opt/srt", "--settings", "/s/p.json", "--"}, argv...), "/s/log/worker-0.status")
	separator := strings.Index(script, "'--'")
	first := strings.Index(script, "'claude'")
	if separator < 0 || first < 0 || separator > first {
		t.Fatalf("the command is not separated from the sandbox's own flags:\n%s", script)
	}
	previous := separator
	for _, arg := range argv {
		at := strings.Index(script[previous:], " "+ShellQuote(arg))
		if at < 0 {
			t.Fatalf("%q did not reach the command line in order:\n%s", arg, script)
		}
		previous += at
	}
	if !strings.Contains(script, "mv -f '/s/log/worker-0.status.part' '/s/log/worker-0.status'") {
		t.Fatalf("the status is not written atomically:\n%s", script)
	}
}

// TestAStageOutlivesItsLauncherAndItsStatusIsRecoverable checks the handle's
// promise: a driver that never saw the launch observes the exit status, a pid
// that never existed is reported gone, and a live process that is not the
// stage is not mistaken for it.
func TestAStageOutlivesItsLauncherAndItsStatusIsRecoverable(t *testing.T) {
	driver := New(Config{Home: t.TempDir(), Look: shim(t), Lookup: os.LookupEnv})
	dir := t.TempDir()
	spec := stage(t, dir, "/bin/sh", "-c", "printf %s hello; exit 3")
	handle, err := driver.Launch(context.Background(), spec)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if handle.Driver != Host || !strings.HasPrefix(handle.ID, "pid:") || !strings.HasSuffix(handle.ID, ":"+spec.LogPath) {
		t.Fatalf("handle = %+v", handle)
	}
	pid, start, _, err := parseHandle(handle)
	if err != nil || pid <= 0 || start <= 0 {
		t.Fatalf("handle %q parsed to %d@%d, %v", handle.ID, pid, start, err)
	}
	if status := waitFor(t, driver, handle); status.Running || status.Gone || status.ExitCode != 3 {
		t.Fatalf("status = %+v", status)
	}
	// The settings file is written beside the log, which shows the profile
	// was built and not only that the stage was launched.
	if _, err := os.Stat(sidecar(spec.LogPath, ".srt.json")); err != nil {
		t.Fatalf("no settings file: %v", err)
	}
	// A driver that never saw the launch reads the same status.
	fresh := New(Config{Home: t.TempDir(), Look: found()})
	if again, err := fresh.Observe(context.Background(), handle); err != nil || again.Running || again.ExitCode != 3 {
		t.Fatalf("a fresh driver lost the exit status: %+v, %v", again, err)
	}
	body, _ := os.ReadFile(spec.LogPath)
	if string(body) != "hello" {
		t.Fatalf("log = %q", body)
	}
	// A pid that never existed, with no status recorded, is gone rather than
	// running: an unknown exit must not be reported as success.
	lost := StageHandle{Driver: Host, ID: formatHandle(999999, 1, filepath.Join(dir, "log", "worker-9.log"))}
	if got, err := fresh.Observe(context.Background(), lost); err != nil || !got.Gone {
		t.Fatalf("a lost stage = %+v, %v", got, err)
	}
	// A live process whose start time differs from the handle's is another
	// process that inherited the pid, not the stage.
	sleeper := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() })
	actual, err := startTime(sleeper.Process.Pid)
	if err != nil {
		t.Fatalf("start time: %v", err)
	}
	recycled := StageHandle{Driver: Host, ID: formatHandle(sleeper.Process.Pid, actual-1, filepath.Join(dir, "log", "worker-8.log"))}
	if got, err := fresh.Observe(context.Background(), recycled); err != nil || !got.Gone {
		t.Fatalf("a recycled pid was mistaken for the stage: %+v, %v", got, err)
	}
	same := StageHandle{Driver: Host, ID: formatHandle(sleeper.Process.Pid, actual, filepath.Join(dir, "log", "worker-8.log"))}
	if got, err := fresh.Observe(context.Background(), same); err != nil || !got.Running {
		t.Fatalf("the process that matches its handle is not running: %+v, %v", got, err)
	}
}

// TestStopKillsAStageThatIgnoresSIGTERM checks that a stage which ignores
// SIGTERM is killed with SIGKILL, together with its process group, when the
// grace period elapses. The stage appends to a marker while it runs, so its
// death is observed directly rather than inferred from the leader.
func TestStopKillsAStageThatIgnoresSIGTERM(t *testing.T) {
	grace := 400 * time.Millisecond
	driver := New(Config{Home: t.TempDir(), Look: shim(t), Lookup: os.LookupEnv, StopGrace: grace})
	dir := t.TempDir()
	marker := filepath.Join(dir, "ticks")
	spec := stage(t, dir, "/bin/sh", "-c", `trap "" TERM; while :; do echo tick >> "$MARK"; sleep 0.05; done`)
	spec.Env = map[string]string{"MARK": marker}
	handle, err := driver.Launch(context.Background(), spec)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the stage never started ticking: %v", err)
	}
	if status, err := driver.Observe(context.Background(), handle); err != nil || !status.Running {
		t.Fatalf("a ticking stage is not running: %+v, %v", status, err)
	}
	start := time.Now()
	if err := driver.Stop(context.Background(), handle); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if elapsed := time.Since(start); elapsed < grace {
		t.Errorf("Stop returned in %v, before the %v grace", elapsed, grace)
	}
	size := fileSize(t, marker)
	time.Sleep(300 * time.Millisecond)
	if grown := fileSize(t, marker); grown != size {
		t.Fatalf("the stage kept running after Stop: marker grew from %d to %d", size, grown)
	}
	if status, err := driver.Observe(context.Background(), handle); err != nil || status.Running {
		t.Fatalf("the stage is still running after Stop: %+v, %v", status, err)
	}
}

// TestStopHonoursACancelledContext checks that a cancelled context ends the
// grace period early with SIGKILL and reports the cancellation.
func TestStopHonoursACancelledContext(t *testing.T) {
	driver := New(Config{Home: t.TempDir(), Look: shim(t), Lookup: os.LookupEnv, StopGrace: 10 * time.Second})
	dir := t.TempDir()
	handle, err := driver.Launch(context.Background(), stage(t, dir, "/bin/sh", "-c", `trap "" TERM; sleep 30`))
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := driver.Stop(ctx, handle); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop = %v", err)
	}
	if status := waitFor(t, driver, handle); status.Running {
		t.Fatalf("status = %+v", status)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

// TestStopAndDiscardTolerateAGoneStage checks that stopping and discarding a
// stage that has already finished, or one this driver never launched, both
// succeed, and that a foreign or malformed handle is refused rather than
// acted on.
func TestStopAndDiscardTolerateAGoneStage(t *testing.T) {
	driver := New(Config{Home: t.TempDir(), Lookup: os.LookupEnv, Look: found()})
	dir := t.TempDir()
	handle := StageHandle{Driver: Host, ID: formatHandle(999999, 1, filepath.Join(dir, "worker-9.log"))}
	for range 2 {
		if err := driver.Stop(context.Background(), handle); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if err := driver.Discard(context.Background(), handle); err != nil {
			t.Fatalf("Discard: %v", err)
		}
	}
	// A finished stage is left alone even if its pid is alive again.
	if err := os.WriteFile(filepath.Join(dir, "worker-9.status"), []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := driver.Stop(context.Background(), handle); err != nil {
		t.Fatalf("Stop on a finished stage: %v", err)
	}
	other := StageHandle{Driver: "container", ID: "x"}
	if err := driver.Stop(context.Background(), other); !errors.Is(err, ErrMismatch) {
		t.Errorf("Stop = %v", err)
	}
	if _, err := driver.Output(context.Background(), other, 0); !errors.Is(err, ErrMismatch) {
		t.Errorf("Output = %v", err)
	}
	for _, malformed := range []string{"not-a-handle", "pid:1", "pid:1:/log", "pid:x@1:/log", "pid:1@x:/log", "pid:0@1:/log", "pid:1@1:"} {
		_, err := driver.Observe(context.Background(), StageHandle{Driver: Host, ID: malformed})
		if !errors.Is(err, ErrInvalidHandle) {
			t.Errorf("Observe(%q) = %v", malformed, err)
		}
	}
}

// FuzzParseHandle checks that parsing never panics and that a handle the
// driver formats parses back to what it was built from.
func FuzzParseHandle(f *testing.F) {
	f.Add(1, int64(2), "/s/log/worker-0.log")
	f.Add(48213, int64(1724570400), "/Users/x/.local/sessions/7f3a91c2/session/raw/worker-0.log")
	f.Add(7, int64(0), "a:b:c")
	f.Fuzz(func(t *testing.T, pid int, start int64, logPath string) {
		id := formatHandle(pid, start, logPath)
		gotPid, gotStart, gotLog, err := parseHandle(StageHandle{Driver: Host, ID: id})
		if pid <= 0 || strings.TrimSpace(logPath) == "" || logPath == "" {
			if err == nil {
				t.Fatalf("%q was accepted", id)
			}
			return
		}
		if err != nil {
			t.Fatalf("%q was refused: %v", id, err)
		}
		if gotPid != pid || gotStart != start || gotLog != logPath {
			t.Fatalf("%q parsed to %d@%d %q", id, gotPid, gotStart, gotLog)
		}
		_, _, _, _ = parseHandle(StageHandle{Driver: Host, ID: logPath})
	})
}

// TestOutputReadsTheStageLogFromAnOffset checks that the stage's output is
// readable from an offset and that a stage which has written nothing yet
// reads empty rather than failing, because the caller polls.
func TestOutputReadsTheStageLogFromAnOffset(t *testing.T) {
	driver := New(Config{Home: t.TempDir(), Lookup: os.LookupEnv, Look: found()})
	dir := t.TempDir()
	logPath := filepath.Join(dir, "worker-0.log")
	if err := os.WriteFile(logPath, []byte("hello sandbox"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stream, err := driver.Output(context.Background(), StageHandle{Driver: Host, ID: formatHandle(1, 1, logPath)}, 6)
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	defer func() { _ = stream.Close() }()
	body := make([]byte, 32)
	n, _ := stream.Read(body)
	if string(body[:n]) != "sandbox" {
		t.Fatalf("output from offset = %q", body[:n])
	}
	absent := StageHandle{Driver: Host, ID: formatHandle(1, 1, filepath.Join(dir, "absent.log"))}
	stream, err = driver.Output(context.Background(), absent, 0)
	if err != nil {
		t.Fatalf("Output on an absent log: %v", err)
	}
	defer func() { _ = stream.Close() }()
	if n, _ := stream.Read(body); n != 0 {
		t.Fatalf("an absent log returned %q", body[:n])
	}
	// A log that cannot be opened for another reason is an error, as is an
	// offset that cannot be sought to.
	unreadable := filepath.Join(dir, "unreadable.log")
	if err := os.WriteFile(unreadable, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Output(context.Background(), StageHandle{Driver: Host, ID: formatHandle(1, 1, unreadable)}, 0); err == nil && os.Getuid() != 0 {
		t.Fatal("an unreadable log was opened")
	}
	if _, err := driver.Output(context.Background(), StageHandle{Driver: Host, ID: formatHandle(1, 1, logPath)}, -1); err == nil {
		t.Fatal("a negative offset was accepted")
	}
}

// TestLaunchRefusesWhatItCannotRun checks the refusals before a process
// starts: no command, no log path, an unready machine, and no PATH.
func TestLaunchRefusesWhatItCannotRun(t *testing.T) {
	dir := t.TempDir()
	driver := New(Config{Home: t.TempDir(), Look: found("srt", "rg"), Lookup: os.LookupEnv})
	spec := stage(t, dir)
	if _, err := driver.Launch(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "argv") {
		t.Fatalf("a stage with no command was launched: %v", err)
	}
	spec.Argv = []string{"/bin/sh"}
	spec.LogPath = ""
	if _, err := driver.Launch(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "log path") {
		t.Fatalf("a stage with no log was launched: %v", err)
	}
	missing := New(Config{Platform: Darwin, Home: t.TempDir(), Look: found(), Lookup: os.LookupEnv})
	if _, err := missing.Launch(context.Background(), stage(t, dir, "/bin/sh")); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Launch on an unready machine = %v", err)
	}
	// A stage with no PATH resolves nothing, not even srt, whose shebang
	// needs node. It used to fail with exit code 127 and an empty log.
	for _, lookup := range []func(string) (string, bool){nil, func(name string) (string, bool) { return "/x", name == "HOME" }} {
		noPath := New(Config{Home: t.TempDir(), Look: found("srt", "rg"), Lookup: lookup})
		_, err := noPath.Launch(context.Background(), stage(t, dir, "/bin/sh"))
		if !errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), "PATH") {
			t.Fatalf("Launch with no PATH = %v", err)
		}
	}
	// A log directory that cannot be created, and a start time that cannot
	// be read, both fail the launch rather than leave a stage unaccounted for.
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := stage(t, dir, "/bin/sh")
	blocked.LogPath = filepath.Join(file, "log", "worker-0.log")
	if _, err := driver.Launch(context.Background(), blocked); err == nil {
		t.Fatal("a log under a file was accepted")
	}
	blocked.LogPath = filepath.Join(dir, "log", "worker-0.log")
	if err := os.WriteFile(sidecar(blocked.LogPath, ".srt.json"), nil, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(blocked.LogPath), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(blocked.LogPath), 0o700) })
	if _, err := driver.Launch(context.Background(), blocked); err == nil {
		t.Fatal("an unwritable settings file was accepted")
	}
	_ = os.Chmod(filepath.Dir(blocked.LogPath), 0o700)

	broken := New(Config{Home: t.TempDir(), Look: shim(t), Lookup: os.LookupEnv})
	previous := startTime
	startTime = func(pid int) (int64, error) { return 0, fmt.Errorf("ps refused pid %d", pid) }
	t.Cleanup(func() { startTime = previous })
	fresh := t.TempDir()
	marker := filepath.Join(fresh, "started")
	failed := stage(t, fresh, "/bin/sh", "-c", "sleep 0.5; touch \"$MARK\"")
	failed.Env = map[string]string{"MARK": marker}
	if _, err := broken.Launch(context.Background(), failed); err == nil || !strings.Contains(err.Error(), "ps refused") {
		t.Fatalf("Launch with no start time = %v", err)
	}
	time.Sleep(time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the stage was left running after its launch failed")
	}
}

// TestStartTimeIsReadThroughPS checks the one process query the driver makes,
// against a process this test owns, and its failure on a pid that is gone.
func TestStartTimeIsReadThroughPS(t *testing.T) {
	sleeper := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() })
	start, err := startTime(sleeper.Process.Pid)
	if err != nil {
		t.Fatalf("startTime: %v", err)
	}
	if drift := time.Since(time.Unix(start, 0)); drift < 0 || drift > time.Minute {
		t.Fatalf("start time %v is %v from now", time.Unix(start, 0), drift)
	}
	if !isStage(sleeper.Process.Pid, start) || isStage(sleeper.Process.Pid, start+1) || isStage(0, start) {
		t.Fatal("liveness does not follow the start time")
	}
	if _, err := startTime(999999); err == nil {
		t.Fatal("a pid that does not exist has a start time")
	}
	// A status file that holds something other than an exit code is not a
	// status.
	path := filepath.Join(t.TempDir(), "worker-0.status")
	if err := os.WriteFile(path, []byte("done\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readStatus(path); ok {
		t.Fatal("a malformed status was read as an exit code")
	}
	if !errors.Is(syscall.Kill(sleeper.Process.Pid, 0), nil) {
		t.Fatal("the sleeper is not alive")
	}
}

// TestAStageReadsTheNullDeviceAndInheritsOnlyTheAllowlist checks the process
// a stage actually receives: stdin is the null device, because a program that
// reads an inherited stdin waits on it; and the environment is the allowlist
// plus HOME, TERM and the stage's own variables, with nothing the operator
// exported reaching it.
func TestAStageReadsTheNullDeviceAndInheritsOnlyTheAllowlist(t *testing.T) {
	t.Setenv("HOSTSANDBOX_TEST_CANARY", "leaked-into-the-sandbox")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-leaked")
	home := t.TempDir()
	driver := New(Config{Home: home, Lookup: os.LookupEnv, Look: shim(t)})
	dir := t.TempDir()
	spec := stage(t, dir, "/bin/sh", "-c", `printf 'stdin:[%s]\n' "$(cat)"; /usr/bin/env`)
	spec.Env = map[string]string{"STAGE_WS": dir}
	handle, err := driver.Launch(context.Background(), spec)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if status := waitFor(t, driver, handle); !status.Succeeded() {
		t.Fatalf("status = %+v", status)
	}
	body, err := os.ReadFile(spec.LogPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	seen := string(body)
	if !strings.Contains(seen, "stdin:[]") {
		t.Fatalf("the stage did not read an empty stdin: %q", seen)
	}
	for _, leaked := range []string{"HOSTSANDBOX_TEST_CANARY", "ANTHROPIC_API_KEY"} {
		if strings.Contains(seen, leaked) {
			t.Errorf("%s reached the stage:\n%s", leaked, seen)
		}
	}
	for _, want := range []string{"PATH=", "HOME=" + home, "TERM=dumb", "STAGE_WS=" + dir} {
		if !strings.Contains(seen, want) {
			t.Errorf("the stage did not get %s:\n%s", want, seen)
		}
	}
}
