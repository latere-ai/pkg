// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// seatbelt composes a driver under Seatbelt on macOS with the stand-in for
// sandbox-exec, so its bookkeeping runs on any platform.
func seatbelt(t *testing.T) *Driver {
	t.Helper()
	fakeSandboxExec(t)
	return New(Config{Isolation: IsolationSeatbelt, Platform: Darwin, Home: t.TempDir(), Lookup: os.LookupEnv, StopGrace: 2 * time.Second})
}

// withoutLauncher makes this test binary a program that did not call Main.
func withoutLauncher(t *testing.T) {
	t.Helper()
	saved := launcherInstalled.Load()
	launcherInstalled.Store(false)
	t.Cleanup(func() { launcherInstalled.Store(saved) })
}

func readLog(t *testing.T, driver *Driver, handle StageHandle) string {
	t.Helper()
	stream, err := driver.Output(context.Background(), handle, 0)
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	defer func() { _ = stream.Close() }()
	body, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	return string(body)
}

// TestIsolationFollowsThePlatform checks what IsolationAuto picks, and that
// an explicit choice is kept.
func TestIsolationFollowsThePlatform(t *testing.T) {
	for _, c := range []struct {
		isolation Isolation
		platform  Platform
		want      Isolation
	}{
		{IsolationAuto, Darwin, IsolationSeatbelt},
		{IsolationAuto, Linux, IsolationSRT},
		{IsolationAuto, Windows, IsolationSRT},
		{IsolationSRT, Darwin, IsolationSRT},
		{IsolationSeatbelt, Linux, IsolationSeatbelt},
	} {
		if got := New(Config{Isolation: c.isolation, Platform: c.platform}).Isolation(); got != c.want {
			t.Errorf("%q on %s = %q, want %q", c.isolation, c.platform, got, c.want)
		}
	}
	if New(Config{Platform: Darwin}).Name() != Host {
		t.Error("the driver's name changed with its isolation; a handle means the same under both")
	}
}

// TestSeatbeltPreflight checks each way Seatbelt can be unavailable: on
// another platform, with sandbox-exec gone, and with a required program
// missing. Nothing beyond sandbox-exec and Requires is needed: no srt, no
// ripgrep.
func TestSeatbeltPreflight(t *testing.T) {
	ctx := context.Background()
	fake := fakeSandboxExec(t)
	none := func(string) (string, error) { return "", exec.ErrNotFound }
	ready := New(Config{Isolation: IsolationSeatbelt, Platform: Darwin, Look: none})
	if err := ready.Preflight(ctx); err != nil {
		t.Fatalf("Seatbelt needs only sandbox-exec, yet Preflight = %v", err)
	}
	var notReady *NotReadyError
	for _, platform := range []Platform{Linux, Windows} {
		err := New(Config{Isolation: IsolationSeatbelt, Platform: platform}).Preflight(ctx)
		if !errors.As(err, &notReady) || notReady.Condition != ConditionUnsupported || !strings.Contains(notReady.Remediation, "IsolationSRT") {
			t.Errorf("Seatbelt on %s = %v, want unsupported with srt named", platform, err)
		}
	}
	err := New(Config{Isolation: IsolationSeatbelt, Platform: Darwin, Look: none, Requires: []string{"claude"}}).Preflight(ctx)
	if !errors.As(err, &notReady) || notReady.Condition != ConditionMissing || !slices.Equal(notReady.Components, []string{"claude"}) {
		t.Errorf("a missing required program = %v", err)
	}
	sandboxExec = filepath.Join(filepath.Dir(fake), "gone")
	err = ready.Preflight(ctx)
	if !errors.As(err, &notReady) || !slices.Equal(notReady.Components, []string{"sandbox-exec"}) || !strings.Contains(notReady.Error(), "/usr/bin/sandbox-exec") {
		t.Errorf("sandbox-exec gone = %v", err)
	}
}

// TestSeatbeltDeclaresTheAllowlistOnlyWithALauncher checks the declaration:
// without Main no proxy can run beside a stage, so the allowlist is not
// declared, and srt declares it either way.
func TestSeatbeltDeclaresTheAllowlistOnlyWithALauncher(t *testing.T) {
	driver := New(Config{Isolation: IsolationSeatbelt, Platform: Darwin})
	if modes := driver.Capabilities().NetworkModes; !modes[NetworkNone] || !modes[NetworkAllowlist] || modes[NetworkOpen] {
		t.Fatalf("with a launcher, modes = %v", modes)
	}
	withoutLauncher(t)
	if modes := driver.Capabilities().NetworkModes; !modes[NetworkNone] || modes[NetworkAllowlist] {
		t.Fatalf("without a launcher, modes = %v", modes)
	}
	if modes := New(Config{Isolation: IsolationSRT}).Capabilities().NetworkModes; !modes[NetworkAllowlist] {
		t.Fatalf("srt's modes = %v", modes)
	}
}

// TestSeatbeltLaunchRunsAStageWithNoNetworkUnderSandboxExec checks the
// bookkeeping of a stage with no network: its profile beside the log, the
// stage run under sandbox-exec with the argv after "--", its status and
// output recovered as under srt.
func TestSeatbeltLaunchRunsAStageWithNoNetworkUnderSandboxExec(t *testing.T) {
	driver := seatbelt(t)
	spec := stage(t, t.TempDir(), "/bin/sh", "-c", "printf 'under seatbelt'; exit 5")
	handle, err := driver.Launch(context.Background(), spec)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	status := waitFor(t, driver, handle)
	if status.ExitCode != 5 || readLog(t, driver, handle) != "under seatbelt" {
		t.Fatalf("status = %+v, output %q", status, readLog(t, driver, handle))
	}
	profile, err := os.ReadFile(sidecar(spec.LogPath, ".sb"))
	if err != nil || !strings.Contains(string(profile), "(deny default)") || strings.Contains(string(profile), "network") {
		t.Fatalf("the profile beside the log = %q, %v", profile, err)
	}
	if _, err := os.Stat(sidecar(spec.LogPath, ".stage.json")); err == nil {
		t.Fatal("a stage with no network was given a launcher")
	}
}

// TestSeatbeltLaunchRunsAnAllowlistedStageUnderItsLauncher checks that a
// stage with an allowlist runs under this program started again as its
// launcher, sees the egress proxy in its environment, and has its exit
// recorded as any stage's.
func TestSeatbeltLaunchRunsAnAllowlistedStageUnderItsLauncher(t *testing.T) {
	driver := seatbelt(t)
	spec := stage(t, t.TempDir(), "/bin/sh", "-c", `printf 'proxy %s' "$HTTPS_PROXY"; exit 7`)
	spec.Network = Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}}
	spec.Env = map[string]string{"API_TOKEN": "token-value"}
	spec.EnvFile = []string{"API_TOKEN"}
	handle, err := driver.Launch(context.Background(), spec)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	status := waitFor(t, driver, handle)
	output := readLog(t, driver, handle)
	if status.ExitCode != 7 || !strings.HasPrefix(output, "proxy http://127.0.0.1:") {
		t.Fatalf("status = %+v, output %q", status, output)
	}
	var file stageFile
	body, err := os.ReadFile(sidecar(spec.LogPath, ".stage.json"))
	if err != nil || json.Unmarshal(body, &file) != nil || !slices.Equal(file.Argv, spec.Argv) {
		t.Fatalf("the stage file = %q, %v", body, err)
	}
	if strings.Contains(string(body), "token-value") {
		t.Fatalf("the stage file holds a credential from the environment: %q", body)
	}
	if profile, err := os.ReadFile(file.Policy); err != nil || !strings.Contains(string(profile), "network-outbound") {
		t.Fatalf("the launcher's profile = %q, %v", profile, err)
	}
}

// TestSeatbeltRefusesAnAllowlistWithoutALauncher checks that an allowlisted
// stage in a program that did not call Main is refused with the remedy,
// before anything runs, while a stage with no network still launches.
func TestSeatbeltRefusesAnAllowlistWithoutALauncher(t *testing.T) {
	driver := seatbelt(t)
	withoutLauncher(t)
	spec := stage(t, t.TempDir(), "/bin/true")
	spec.Network = Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}}
	_, err := driver.Launch(context.Background(), spec)
	var notReady *NotReadyError
	if !errors.As(err, &notReady) || notReady.Condition != ConditionNoLauncher || !strings.Contains(notReady.Remediation, "hostsandbox.Main") {
		t.Fatalf("Launch = %v, want the launcher's remedy", err)
	}
	if _, _, err := driver.Command(context.Background(), spec); !errors.As(err, &notReady) {
		t.Fatalf("Command = %v, want the launcher's remedy", err)
	}
	spec.Network = Network{Mode: NetworkAllowlist}
	handle, err := driver.Launch(context.Background(), spec)
	if err != nil {
		t.Fatalf("an empty allowlist, which is no network, was refused: %v", err)
	}
	waitFor(t, driver, handle)
}

// TestSeatbeltCommandRunsAttached checks the attached form under Seatbelt,
// with no network and with an allowlist: stdin passes through, the exit
// code is the stage's, and the cleanup removes the profile's directory.
func TestSeatbeltCommandRunsAttached(t *testing.T) {
	driver := seatbelt(t)
	spec := stage(t, t.TempDir(), "/bin/sh", "-c", `read line; printf '%s %s' "$line" "${HTTP_PROXY:-direct}"; exit 2`)
	for _, network := range []Network{{Mode: NetworkNone}, {Mode: NetworkAllowlist, Domains: []string{"example.com"}}} {
		spec.Network = network
		command, cleanup, err := driver.Command(context.Background(), spec)
		if err != nil {
			t.Fatalf("Command: %v", err)
		}
		command.Stdin = strings.NewReader("hello\n")
		output, err := command.Output()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 {
			t.Fatalf("%s: run = %v, want exit 2", network.Mode, err)
		}
		want := "hello direct"
		if network.Mode == NetworkAllowlist {
			want = "hello http://127.0.0.1:"
		}
		if !strings.HasPrefix(string(output), want) {
			t.Fatalf("%s: output = %q, want %q", network.Mode, output, want)
		}
		// The profile follows sandbox-exec's -f, or the stage file names it.
		dir := ""
		if network.Mode == NetworkNone {
			dir = filepath.Dir(command.Args[2])
		}
		cleanup()
		if dir != "" {
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the profile's directory %s outlived the cleanup: %v", dir, err)
			}
		}
	}
}

// TestSeatbeltLaunchReportsWhatItCannotWrite checks that a profile or stage
// file that cannot be written fails the launch with the stage named.
func TestSeatbeltLaunchReportsWhatItCannotWrite(t *testing.T) {
	driver := seatbelt(t)
	spec := stage(t, t.TempDir(), "/bin/true")
	spec.Paths = []Path{{Host: "/a\nb", Access: ReadOnly}}
	if _, err := driver.Launch(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("a path with a control character = %v", err)
	}
	saved := executable
	executable = func() (string, error) { return "", errors.New("no executable") }
	t.Cleanup(func() { executable = saved })
	spec = stage(t, t.TempDir(), "/bin/true")
	spec.Network = Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}}
	if _, err := driver.Launch(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "worker-0") {
		t.Fatalf("no executable to launch with = %v", err)
	}
}

// coverage gives a launcher, this test binary started again, a directory to
// write its coverage data to. Without one, a binary built for coverage
// prints a warning on exit, and the warning lands in the stage's output.
func coverage(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{"GOCOVERDIR": t.TempDir()}
}

// realSeatbelt composes a driver under the real Seatbelt, with a home
// directory of its own resolved through its links, or skips where macOS's
// sandbox-exec is not present.
func realSeatbelt(t *testing.T) (*Driver, string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	driver := New(Config{Isolation: IsolationSeatbelt, Home: home, Lookup: os.LookupEnv, StopGrace: 2 * time.Second})
	if err := driver.Preflight(context.Background()); err != nil {
		t.Skipf("Seatbelt is not available here, so it is unchecked:\n%v", err)
	}
	return driver, home
}

// attached runs argv attached under driver with spec's paths and network
// and returns its output and error.
func attached(t *testing.T, driver *Driver, spec StageSpec) (string, error) {
	t.Helper()
	command, cleanup, err := driver.Command(context.Background(), spec)
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	defer cleanup()
	output, err := command.CombinedOutput()
	return string(output), err
}

// TestSeatbeltConfinesAStage runs stages under the real Seatbelt: a granted
// file is readable and a file beside it is not, the always-deny table and a
// stage's denial hold inside a grant, a write lands only in a writable
// grant and never in what stays read-only inside it, and a stage with no
// network reaches nothing, not even a server on this machine.
func TestSeatbeltConfinesAStage(t *testing.T) {
	driver, home := realSeatbelt(t)
	project := filepath.Join(home, "project")
	elsewhere, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		filepath.Join(project, "notes.txt"):   "granted",
		filepath.Join(project, ".env"):        "withheld",
		filepath.Join(project, "keep", "x"):   "kept",
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
	spec := func(argv ...string) StageSpec {
		return StageSpec{
			Name: "confined", Argv: argv, Workdir: project,
			Paths:        []Path{{Host: project, Access: ReadWrite}},
			Denied:       []string{filepath.Join(project, ".env")},
			DeniedWrites: []string{filepath.Join(project, "keep")},
			Network:      Network{Mode: NetworkNone},
		}
	}
	if output, err := attached(t, driver, spec("/bin/cat", filepath.Join(project, "notes.txt"))); err != nil || output != "granted" {
		t.Fatalf("the granted file = %q, %v", output, err)
	}
	for _, path := range []string{filepath.Join(home, "outside.txt"), filepath.Join(project, ".env")} {
		if output, err := attached(t, driver, spec("/bin/cat", path)); err == nil {
			t.Errorf("%s was read: %q", path, output)
		}
	}
	whole := spec("/bin/cat", filepath.Join(home, ".ssh", "id_key"))
	whole.Paths = []Path{{Host: home, Access: ReadOnly}}
	if output, err := attached(t, driver, whole); err == nil {
		t.Errorf("a path on the always-deny table was read inside a grant: %q", output)
	}
	if output, err := attached(t, driver, spec("/bin/sh", "-c", "echo new > "+filepath.Join(project, "new.txt"))); err != nil {
		t.Fatalf("a write in the writable grant failed: %q, %v", output, err)
	}
	for _, path := range []string{filepath.Join(project, "keep", "y"), filepath.Join(elsewhere, "escape.txt"), filepath.Join(home, "planted.txt")} {
		if output, err := attached(t, driver, spec("/bin/sh", "-c", "echo x > "+path)); err == nil {
			t.Errorf("a write to %s succeeded: %q", path, output)
		}
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s was written", path)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "reached") }))
	t.Cleanup(server.Close)
	if output, err := attached(t, driver, spec("/usr/bin/curl", "-q", "-sS", "--max-time", "5", server.URL)); err == nil || strings.Contains(output, "reached") {
		t.Fatalf("a stage with no network reached a server: %q, %v", output, err)
	}
}

// TestSeatbeltAllowlistGoesOnlyThroughTheProxy runs a stage with an
// allowlist under the real Seatbelt and this test binary as its launcher:
// an allowed host is reached through the egress proxy, another host is
// refused by it, and a connection that tries to go around the proxy is
// refused by the sandbox.
func TestSeatbeltAllowlistGoesOnlyThroughTheProxy(t *testing.T) {
	driver, home := realSeatbelt(t)
	localDestinations = true
	t.Cleanup(func() { localDestinations = false })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "reached through the proxy") }))
	t.Cleanup(server.Close)
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	allowed := "http://localhost:" + address.Port() + "/"
	spec := func(argv ...string) StageSpec {
		return StageSpec{
			Name: "egress", Argv: argv, Workdir: home,
			Paths:   []Path{{Host: home, Access: ReadWrite}},
			Network: Network{Mode: NetworkAllowlist, Domains: []string{"localhost"}},
			Env:     coverage(t),
		}
	}
	if output, err := attached(t, driver, spec("/usr/bin/curl", "-q", "-sS", "--max-time", "10", allowed)); err != nil || output != "reached through the proxy" {
		t.Fatalf("an allowed host = %q, %v", output, err)
	}
	// The refusal is the proxy's 403, and its line in the stage's output
	// says which host was refused.
	output, err := attached(t, driver, spec("/usr/bin/curl", "-q", "-sS", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "http://denied.test/"))
	if !strings.HasSuffix(output, "403") || !strings.Contains(output, "refused a connection to denied.test") {
		t.Fatalf("a host not allowed = %q, %v, want 403 and the refusal named", output, err)
	}
	if output, err := attached(t, driver, spec("/usr/bin/curl", "-q", "-sS", "--max-time", "5", "--noproxy", "*", server.URL)); err == nil || strings.Contains(output, "reached") {
		t.Fatalf("a connection around the proxy succeeded: %q, %v", output, err)
	}
}

// TestSeatbeltDetachedStageKeepsItsNetwork launches an allowlisted stage
// from another process that exits at once, and checks that the stage,
// running on, still reaches its allowed host: the proxy lives with the
// stage, not with whoever launched it.
func TestSeatbeltDetachedStageKeepsItsNetwork(t *testing.T) {
	driver, home := realSeatbelt(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "still reachable") }))
	t.Cleanup(server.Close)
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	spec := stage(t, dir, "/bin/sh", "-c", "sleep 2; /usr/bin/curl -q -sS --max-time 10 http://localhost:"+address.Port()+"/")
	spec.Paths = []Path{{Host: home, Access: ReadWrite}}
	spec.Workdir = home
	spec.Network = Network{Mode: NetworkAllowlist, Domains: []string{"localhost"}}
	spec.Env = coverage(t)
	request := launchRequest{Home: home, Spec: spec, Local: true, Handle: filepath.Join(dir, "handle.json")}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(dir, "request.json")
	if err := os.WriteFile(requestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	launcher := exec.Command(os.Args[0]) //nolint:gosec,noctx // this test binary, as a process that launches and exits
	launcher.Env = append(os.Environ(), launchOnlyVariable+"="+requestPath)
	if output, err := launcher.CombinedOutput(); err != nil {
		t.Fatalf("the launching process failed: %v\n%s", err, output)
	}
	encoded, err := os.ReadFile(request.Handle)
	if err != nil {
		t.Fatal(err)
	}
	var handle StageHandle
	if err := json.Unmarshal(encoded, &handle); err != nil {
		t.Fatal(err)
	}
	if status, err := driver.Observe(context.Background(), handle); err != nil || !status.Running {
		t.Fatalf("the stage was not running once its launching process had exited: %+v, %v", status, err)
	}
	status := waitFor(t, driver, handle)
	if output := readLog(t, driver, handle); !status.Succeeded() || output != "still reachable" {
		t.Fatalf("the detached stage = %+v, output %q", status, output)
	}
}
