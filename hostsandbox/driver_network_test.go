// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestTheDenylistIsDeclaredOnlyWhereItIsEnforced checks Capabilities: the
// deny list is declared under Seatbelt in a program that called Main, and
// nowhere else, and never by default.
func TestTheDenylistIsDeclaredOnlyWhereItIsEnforced(t *testing.T) {
	if modes := seatbelt(t).Capabilities().NetworkModes; !modes[NetworkDenylist] || !modes[NetworkAllowlist] || modes[NetworkOpen] {
		t.Fatalf("Seatbelt with a launcher declares %v", modes)
	}
	if modes := New(Config{Isolation: IsolationSRT}).Capabilities().NetworkModes; modes[NetworkDenylist] {
		t.Fatalf("srt declares %v", modes)
	}
	driver := seatbelt(t)
	withoutLauncher(t)
	if modes := driver.Capabilities().NetworkModes; modes[NetworkDenylist] || modes[NetworkAllowlist] {
		t.Fatalf("Seatbelt without a launcher declares %v", modes)
	}
	var zero StageSpec
	if proxiedStage(zero) || zero.Network.Mode == NetworkDenylist {
		t.Fatal("a stage's zero network reaches the network")
	}
	report := func(string, int) {}
	// withoutLauncher above restores this program's state when the test ends.
	launcherInstalled.Store(true)
	for spec, want := range map[*StageSpec]bool{
		{Network: Network{Mode: NetworkAllowlist}}:                                   false,
		{Network: Network{Mode: NetworkAllowlist}, OnRefused: report}:                true,
		{Network: Network{Mode: NetworkNone}, OnRefused: report}:                     false,
		{Network: Network{Mode: NetworkOpen}, OnRefused: report}:                     false,
		{Network: Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}}}: true,
		{Network: Network{Mode: NetworkDenylist}}:                                    true,
	} {
		if got := proxiedStage(*spec); got != want {
			t.Errorf("proxiedStage(%+v) = %v, want %v", spec.Network, got, want)
		}
	}
	// Without Main, an empty allowlist is no network, reported or not.
	launcherInstalled.Store(false)
	if proxiedStage(StageSpec{Network: Network{Mode: NetworkAllowlist}, OnRefused: report}) {
		t.Error("an empty allowlist needs a launcher a program without Main cannot start")
	}
}

// TestADenylistStageRunsBesideItsProxy checks that a deny-list stage under
// Seatbelt runs under its launcher with the deny list in its stage file,
// even with nothing blocked and nothing named, and is refused without a
// launcher.
func TestADenylistStageRunsBesideItsProxy(t *testing.T) {
	driver := seatbelt(t)
	spec := stage(t, t.TempDir(), "/bin/sh", "-c", `printf 'proxy %s' "$HTTPS_PROXY"`)
	for _, network := range []Network{{Mode: NetworkDenylist}, {Mode: NetworkDenylist, Blocked: []string{"evil.test", "*.bad.test:22"}}} {
		spec.Network = network
		handle, err := driver.Launch(context.Background(), spec)
		if err != nil {
			t.Fatalf("Launch: %v", err)
		}
		status := waitFor(t, driver, handle)
		if output := readLog(t, driver, handle); !status.Succeeded() || !strings.HasPrefix(output, "proxy http://127.0.0.1:") {
			t.Fatalf("status = %+v, output %q", status, output)
		}
		var file stageFile
		body, err := os.ReadFile(sidecar(spec.LogPath, ".stage.json"))
		if err != nil || json.Unmarshal(body, &file) != nil {
			t.Fatalf("the stage file = %q, %v", body, err)
		}
		if file.Profile.Network.Mode != NetworkDenylist || strings.Join(file.Profile.Network.Blocked, ",") != strings.Join(network.Blocked, ",") || file.Refusals {
			t.Fatalf("the stage file's network = %+v, refusals %v", file.Profile.Network, file.Refusals)
		}
	}
	withoutLauncher(t)
	spec.Network = Network{Mode: NetworkDenylist}
	var notReady *NotReadyError
	if _, err := driver.Launch(context.Background(), spec); !errors.As(err, &notReady) || notReady.Condition != ConditionNoLauncher || !strings.Contains(notReady.Remediation, "hostsandbox.Main") {
		t.Fatalf("Launch without a launcher = %v", err)
	}
}

// TestADriverRefusesANetworkItCannotEnforce checks that Launch and Command
// refuse, before anything runs, a deny list under srt, a deny list on a
// stage of another mode, and a deny-list entry they cannot read.
func TestADriverRefusesANetworkItCannotEnforce(t *testing.T) {
	srt := New(Config{Isolation: IsolationSRT, Platform: Darwin, Home: t.TempDir(), Look: shim(t), Lookup: os.LookupEnv})
	belt := seatbelt(t)
	for _, c := range []struct {
		driver  *Driver
		network Network
	}{
		{srt, Network{Mode: NetworkDenylist}},
		{srt, Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}, Blocked: []string{"evil.test"}}},
		{belt, Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}, Blocked: []string{"evil.test"}}},
		{belt, Network{Mode: NetworkNone, Blocked: []string{"evil.test"}}},
		{belt, Network{Mode: NetworkDenylist, Blocked: []string{"evil.test:0"}}},
		{belt, Network{Mode: NetworkDenylist, Blocked: []string{"https://evil.test/"}}},
	} {
		spec := stage(t, t.TempDir(), "/bin/true")
		spec.Network = c.network
		if _, err := c.driver.Launch(context.Background(), spec); !errors.Is(err, ErrUnenforceableNetwork) {
			t.Errorf("Launch(%+v) = %v, want ErrUnenforceableNetwork", c.network, err)
		}
		if _, _, err := c.driver.Command(context.Background(), spec); !errors.Is(err, ErrUnenforceableNetwork) {
			t.Errorf("Command(%+v) = %v, want ErrUnenforceableNetwork", c.network, err)
		}
		entries, err := os.ReadDir(filepath.Dir(spec.LogPath))
		if err != nil || len(entries) != 0 {
			t.Errorf("a refused stage left %v, %v", entries, err)
		}
	}
}

// TestALauncherRefusesANetworkItCannotEnforce checks that a launcher handed
// a stage file whose network it cannot enforce runs nothing.
func TestALauncherRefusesANetworkItCannotEnforce(t *testing.T) {
	fakeSandboxExec(t)
	stderr := &lockedBuffer{}
	path, _ := writeStage(t, stageFile{Profile: Profile{Network: Network{Mode: NetworkDenylist, Blocked: []string{"evil.test:abc"}}}, Argv: []string{"/bin/echo", "ran"}, SandboxExec: sandboxExec})
	if code := runLauncher(path, strings.NewReader(""), stderr, stderr); code != launcherExit || strings.Contains(stderr.String(), "ran") {
		t.Fatalf("the launcher exited %d: %q", code, stderr.String())
	}
}

// TestALaunchThatFailsReleasesItsRefusals checks that a stage whose
// refusals' pipe cannot be opened is refused, and that a launch that fails
// after the pipe is open closes it.
func TestALaunchThatFailsReleasesItsRefusals(t *testing.T) {
	driver := seatbelt(t)
	spec := stage(t, t.TempDir(), "/bin/true")
	spec.Network = Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}}
	spec.OnRefused = func(string, int) {}
	saved := newRefusalPipe
	t.Cleanup(func() { newRefusalPipe = saved })
	newRefusalPipe = func() (*refusalPipe, error) { return nil, errors.New("no pipes left") }
	if _, err := driver.Launch(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "no pipes left") {
		t.Fatalf("Launch = %v, want the pipe's failure", err)
	}
	if _, _, err := driver.Command(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "no pipes left") {
		t.Fatalf("Command = %v, want the pipe's failure", err)
	}
	var opened *refusalPipe
	newRefusalPipe = func() (*refusalPipe, error) {
		pipe, err := saved()
		opened = pipe
		return pipe, err
	}
	// A log that cannot be opened fails the launch after the pipe is open.
	if err := os.MkdirAll(spec.LogPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Launch(context.Background(), spec); err == nil {
		t.Fatal("Launch with a log that is a directory succeeded")
	}
	if opened == nil {
		t.Fatal("the pipe was never opened")
	}
	if _, err := opened.read.Write(nil); err == nil || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("the pipe's read end is still open: %v", err)
	}
	if _, err := opened.write.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("the pipe's write end is still open: %v", err)
	}
}

// lockedBuffer is a buffer two goroutines may write.
type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}
