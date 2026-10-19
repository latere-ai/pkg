// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

// stageFileVariable names the stage file a launcher process runs. The driver
// sets it on the launcher it starts and the launcher removes it from the
// stage's environment.
const stageFileVariable = "HOSTSANDBOX_STAGE_FILE"

// launcherExit is the exit code of a launcher that could not run its stage
// at all, as a container runtime reports a container it could not start.
const launcherExit = 125

// launcherInstalled records that this program's main called Main, so the
// driver may start this program again as a stage's launcher.
var launcherInstalled atomic.Bool

// localDestinations admits destinations on this machine through the egress
// proxy. Only this package's tests set it; the driver copies it into the
// stage file, so the launcher, another process, sees it.
var localDestinations bool

// executable is this program's path, which the driver starts again as a
// stage's launcher. A test replaces it.
var executable = os.Executable

// Main runs this process as a stage's launcher when the driver started it as
// one, and otherwise returns at once.
//
// A program whose stages run under Seatbelt with a network allowlist calls
// Main as the first statement of its main function. The allowlist is
// enforced by a proxy, and a detached stage outlives the process that
// launched it, so the proxy cannot live in that process: the driver starts
// this program again as the stage's launcher, which serves the proxy on a
// loopback port, renders the stage's profile to allow that port alone, runs
// the stage under sandbox-exec and exits with its exit code. A program that
// does not call Main keeps srt under IsolationAuto; under an explicit
// IsolationSeatbelt its allowlisted stages are refused with a NotReadyError
// and its stages with no network run as before.
func Main() {
	path, ok := os.LookupEnv(stageFileVariable)
	if !ok {
		launcherInstalled.Store(true)
		return
	}
	os.Exit(runLauncher(path, os.Stdin, os.Stdout, os.Stderr))
}

// stageFile is what the driver hands a launcher: the stage's profile and
// argv, the sandbox-exec to run it with, and where to write the rendered
// profile. It holds no environment: the stage's variables, credentials
// among them, reach the launcher in its own environment and never a file.
type stageFile struct {
	Profile     Profile  `json:"profile"`
	Argv        []string `json:"argv"`
	SandboxExec string   `json:"sandbox_exec"`
	Policy      string   `json:"policy"`
	Local       bool     `json:"local,omitempty"`
}

// runLauncher serves the stage's egress proxy, runs the stage under
// sandbox-exec with stdin, stdout and stderr passed through, and returns
// the stage's exit code: 128 plus the signal for a stage a signal ended, as
// a shell reports it, and launcherExit when the stage could not be run.
func runLauncher(path string, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(format string, args ...any) int {
		_, _ = fmt.Fprintf(stderr, "hostsandbox: "+format+"\n", args...)
		return launcherExit
	}
	body, err := os.ReadFile(path) //nolint:gosec // the driver's own stage file
	if err != nil {
		return fail("reading the stage file: %v", err)
	}
	var stage stageFile
	if err := json.Unmarshal(body, &stage); err != nil {
		return fail("reading the stage file %s: %v", path, err)
	}
	if len(stage.Argv) == 0 || stage.SandboxExec == "" || stage.Policy == "" {
		return fail("the stage file %s names no argv, sandbox-exec or profile path", path)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // the launcher has no context; it lives as long as its stage
	if err != nil {
		return fail("opening the egress proxy: %v", err)
	}
	server := &http.Server{
		Handler:           newEgress(stage.Profile.Network.Domains, stderr, stage.Local),
		ReadHeaderTimeout: egressHeaderTimeout,
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			_, _ = fmt.Fprintf(stderr, "hostsandbox: the egress proxy stopped: %v\n", err)
		}
	}()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fail("the egress proxy listens on %v, not a TCP port", listener.Addr())
	}
	port := address.Port
	text, err := RenderSeatbelt(stage.Profile, port)
	if err != nil {
		return fail("%v", err)
	}
	if err := os.WriteFile(stage.Policy, []byte(text), 0o600); err != nil {
		return fail("writing the stage's profile: %v", err)
	}
	// Stop signals the stage's whole process group, this launcher with it.
	// The launcher stays to serve the proxy while the stage shuts down, and
	// exits with it; SIGKILL ends both.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	// The "--" ends sandbox-exec's own options, so an argv that begins with
	// a dash is the stage's.
	command := exec.Command(stage.SandboxExec, append([]string{"-f", stage.Policy, "--"}, stage.Argv...)...) //nolint:gosec,noctx // the driver's stage; it ends with its process group
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	command.Env = proxyEnvironment(os.Environ(), port)
	return exitCode(command.Run(), stderr)
}

// proxyVariables are the variables HTTP clients read their proxy from. The
// stage's own values for them are replaced, and the ones that would exempt
// a host from the proxy are removed, because the sandbox lets no connection
// past it.
var proxyVariables = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}

// proxyEnvironment is the stage's environment: the launcher's own, less the
// stage file and any proxy settings, with every proxy variable naming the
// egress proxy.
func proxyEnvironment(environ []string, port int) []string {
	drop := append([]string{stageFileVariable, "NO_PROXY", "no_proxy"}, proxyVariables...)
	out := make([]string, 0, len(environ)+len(proxyVariables))
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		if !slices.Contains(drop, name) {
			out = append(out, entry)
		}
	}
	address := "http://127.0.0.1:" + strconv.Itoa(port)
	for _, name := range proxyVariables {
		out = append(out, name+"="+address)
	}
	return out
}

// exitCode is the code the launcher exits with for the stage's end.
func exitCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exit.ExitCode()
	}
	_, _ = fmt.Fprintf(stderr, "hostsandbox: running the stage: %v\n", err)
	return launcherExit
}
