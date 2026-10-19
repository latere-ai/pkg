// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeSandboxExec writes a stand-in for sandbox-exec that drops
// `-f <profile> --` and runs the command, points the driver at it, and
// returns its path. What is under test is the driver's and the launcher's
// bookkeeping, not Seatbelt's isolation.
func fakeSandboxExec(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandbox-exec")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nshift 3\nexec \"$@\"\n"), 0o700); err != nil {
		t.Fatalf("write the stand-in: %v", err)
	}
	saved := sandboxExec
	sandboxExec = path
	t.Cleanup(func() { sandboxExec = saved })
	return path
}

// writeStage writes a stage file for runLauncher and returns its path and
// where the launcher writes the profile.
func writeStage(t *testing.T, stage stageFile) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if stage.Policy == "" {
		stage.Policy = filepath.Join(dir, "stage.sb")
	}
	body, err := json.Marshal(stage)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "stage.stage.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, stage.Policy
}

// TestLauncherRunsTheStageBesideItsProxy checks that the launcher writes a
// profile that allows the proxy's port, gives the stage the proxy in every
// proxy variable without the stage file or a proxy exemption, passes stdin
// through, and exits with the stage's exit code.
func TestLauncherRunsTheStageBesideItsProxy(t *testing.T) {
	stand := fakeSandboxExec(t)
	t.Setenv(stageFileVariable, "/the/stage/file")
	t.Setenv("NO_PROXY", "*")
	t.Setenv("HTTPS_PROXY", "http://elsewhere:1")
	script := `read line; echo "in: $line"; echo "https: $HTTPS_PROXY"; echo "all: $all_proxy"; ` +
		`echo "file: ${HOSTSANDBOX_STAGE_FILE:-none}"; echo "exempt: ${NO_PROXY:-none}"; exit 3`
	path, policy := writeStage(t, stageFile{
		Profile:     Profile{Home: t.TempDir(), Network: Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}}},
		Argv:        []string{"/bin/sh", "-c", script},
		SandboxExec: stand,
	})
	var stdout, stderr bytes.Buffer
	code := runLauncher(path, strings.NewReader("hello\n"), &stdout, &stderr)
	if code != 3 {
		t.Fatalf("exit = %d, want the stage's 3; stderr %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"in: hello", "https: http://127.0.0.1:", "all: http://127.0.0.1:", "file: none", "exempt: none"} {
		if !strings.Contains(output, want) {
			t.Errorf("the stage printed %q, want %q in it", output, want)
		}
	}
	profile, err := os.ReadFile(policy)
	if err != nil {
		t.Fatalf("the profile was not written: %v", err)
	}
	_, after, _ := strings.Cut(output, "https: http://127.0.0.1:")
	port, _, _ := strings.Cut(after, "\n")
	if !strings.Contains(string(profile), `(remote ip "localhost:`+port+`")`) {
		t.Fatalf("the profile does not allow the proxy's port %s:\n%s", port, profile)
	}
}

// TestLauncherReportsASignalAsTheShellDoes checks that a stage a signal
// ended exits as 128 plus the signal, as the wrapper's status file expects.
func TestLauncherReportsASignalAsTheShellDoes(t *testing.T) {
	path, _ := writeStage(t, stageFile{
		Profile:     Profile{Network: Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}}},
		Argv:        []string{"/bin/sh", "-c", "kill -TERM $$"},
		SandboxExec: fakeSandboxExec(t),
	})
	if code := runLauncher(path, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 143 {
		t.Fatalf("exit = %d, want 143", code)
	}
}

// TestLauncherRefusesWhatItCannotRun checks each way a launcher can fail
// before its stage runs: it exits with launcherExit and says why.
func TestLauncherRefusesWhatItCannotRun(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty, _ := writeStage(t, stageFile{SandboxExec: "/x"})
	control, _ := writeStage(t, stageFile{Profile: Profile{Reads: []string{"/a\nb"}}, Argv: []string{"/bin/true"}, SandboxExec: "/x"})
	unwritable, _ := writeStage(t, stageFile{Argv: []string{"/bin/true"}, SandboxExec: "/x", Policy: filepath.Join(t.TempDir(), "missing", "dir", "stage.sb")})
	missing, _ := writeStage(t, stageFile{Argv: []string{"/bin/true"}, SandboxExec: filepath.Join(t.TempDir(), "no-such-program")})
	for name, path := range map[string]string{
		"no stage file":          filepath.Join(t.TempDir(), "absent.json"),
		"a broken stage file":    broken,
		"an empty stage":         empty,
		"a control character":    control,
		"an unwritable profile":  unwritable,
		"no sandbox-exec to run": missing,
	} {
		var stderr bytes.Buffer
		if code := runLauncher(path, strings.NewReader(""), &bytes.Buffer{}, &stderr); code != launcherExit {
			t.Errorf("%s: exit = %d, want %d", name, code, launcherExit)
		}
		if !strings.HasPrefix(stderr.String(), "hostsandbox: ") {
			t.Errorf("%s: stderr = %q, want the reason", name, stderr.String())
		}
	}
}

// TestProxyEnvironmentReplacesEveryProxySetting checks the stage's
// environment: the launcher's own, less the stage file and every proxy
// setting, with each proxy variable naming the egress proxy.
func TestProxyEnvironmentReplacesEveryProxySetting(t *testing.T) {
	got := proxyEnvironment([]string{"PATH=/usr/bin", stageFileVariable + "=/x", "no_proxy=*", "http_proxy=http://other", "TERM=dumb"}, 4321)
	for _, want := range []string{"PATH=/usr/bin", "TERM=dumb", "HTTP_PROXY=http://127.0.0.1:4321", "https_proxy=http://127.0.0.1:4321", "ALL_PROXY=http://127.0.0.1:4321"} {
		if !slices.Contains(got, want) {
			t.Errorf("environment %q lacks %q", got, want)
		}
	}
	for _, entry := range got {
		if strings.HasPrefix(entry, stageFileVariable) || strings.HasPrefix(strings.ToLower(entry), "no_proxy") || entry == "http_proxy=http://other" {
			t.Errorf("environment kept %q", entry)
		}
	}
}

// TestExitCodeNamesAStageThatDidNotStart checks that a stage that could not
// be started is reported as the launcher's own failure.
func TestExitCodeNamesAStageThatDidNotStart(t *testing.T) {
	var stderr bytes.Buffer
	if code := exitCode(errors.New("no such file"), &stderr); code != launcherExit || !strings.Contains(stderr.String(), "running the stage") {
		t.Fatalf("exitCode = %d, %q", code, stderr.String())
	}
	if code := exitCode(nil, &stderr); code != 0 {
		t.Fatalf("exitCode(nil) = %d", code)
	}
	if code := exitCode(exec.Command("/bin/sh", "-c", "exit 4").Run(), &stderr); code != 4 { //nolint:noctx // a test
		t.Fatalf("exitCode = %d, want 4", code)
	}
}
