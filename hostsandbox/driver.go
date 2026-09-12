// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Config is what a composition root passes to New. Every field has a usable
// zero value except Home, which the profile needs, and Lookup, without which
// no stage can launch.
type Config struct {
	// Platform is the operating system. It is a parameter rather than a call
	// to runtime.GOOS so that every refusal can be tested on one machine.
	// Empty means CurrentPlatform.
	Platform Platform
	// Home is the operator's home directory. The whole directory is denied
	// to every stage; only the paths a StageSpec names are allowed back.
	Home string
	// Requires are executables a stage needs beyond srt and what srt needs,
	// such as the program the stage runs. Preflight resolves each one and
	// reports a missing one with its install lines, and the profile grants
	// read access to the directory each resolves to, so a program installed
	// under the home directory can still run.
	Requires []string
	// Remedies adds install rows to DefaultRemedies, or replaces them. A
	// consumer lists here how each entry in Requires is installed.
	Remedies Remedies
	// Alternative is the consumer's own text naming what to do instead of
	// this driver. It is attached to every refusal Preflight returns.
	Alternative string
	// StopGrace is how long Stop waits after SIGTERM before it sends SIGKILL
	// to the stage's process group. Zero selects DefaultStopGrace.
	StopGrace time.Duration
	// Look resolves an executable. Nil means exec.LookPath.
	Look func(string) (string, error)
	// Lookup reads one variable of the process environment; a composition
	// root passes os.LookupEnv. A stage inherits only what Environment
	// admits through it. There is no way to pass the whole environment.
	Lookup func(string) (string, bool)
}

// DefaultStopGrace is how long Stop waits after SIGTERM before it sends
// SIGKILL to a stage that has not exited.
const DefaultStopGrace = 10 * time.Second

// Driver is the srt sandbox. It holds no state between calls: everything a
// call needs is in the handle or in the files beside the stage log.
type Driver struct{ config Config }

// New composes the driver.
func New(config Config) *Driver {
	if config.Platform == "" {
		config.Platform = CurrentPlatform()
	}
	if config.Look == nil {
		config.Look = exec.LookPath
	}
	if config.StopGrace <= 0 {
		config.StopGrace = DefaultStopGrace
	}
	return &Driver{config: config}
}

// Name is the driver's canonical name.
func (d *Driver) Name() DriverName { return Host }

// dependencies returns the executables srt itself needs on a platform. macOS
// uses Seatbelt, which is part of the operating system; Linux needs bubblewrap
// and a socket relay. Both need ripgrep.
func dependencies(platform Platform) []string {
	if platform == Linux {
		return []string{"bubblewrap", "socat", "rg"}
	}
	return []string{"rg"}
}

func (d *Driver) remedies() Remedies { return DefaultRemedies().With(d.config.Remedies) }

func (d *Driver) notReady(condition Condition, components ...string) *NotReadyError {
	err := d.remedies().NotReady(d.config.Platform, Host, condition, components...)
	err.Alternative = d.config.Alternative
	return err
}

// Preflight reports whether this machine can run the driver, and names what to
// install when it cannot. Windows is refused because srt marks its Windows
// support as alpha, which is not an isolation boundary.
func (d *Driver) Preflight(context.Context) error {
	if d.config.Platform == Windows {
		return d.notReady(ConditionUnsupported, "srt")
	}
	if _, err := d.config.Look("srt"); err != nil {
		return d.notReady(ConditionMissing, "srt")
	}
	for _, group := range [][]string{dependencies(d.config.Platform), d.config.Requires} {
		var missing []string
		for _, name := range group {
			if _, err := d.config.Look(strings.TrimSpace(name)); err != nil {
				missing = append(missing, strings.TrimSpace(name))
			}
		}
		if len(missing) > 0 {
			return d.notReady(ConditionMissing, missing...)
		}
	}
	return nil
}

// Capabilities declares the two egress policies srt enforces. There is no open
// mode: srt is allow-only and refuses a wildcard, so this driver can neither
// enforce nor express unrestricted egress. PackageManagers and
// MaxAttachmentBytes are left to the consumer.
func (d *Driver) Capabilities() Capabilities {
	return Capabilities{NetworkModes: map[string]bool{NetworkNone: true, NetworkAllowlist: true}}
}

// Profile is the access policy Launch renders for a stage. Inside the home
// directory it grants what the StageSpec carries and the directories of the
// executables in Config.Requires, and nothing else. It is exported so that a
// consumer can assert the policy a stage would run under without launching it.
func (d *Driver) Profile(spec StageSpec) Profile {
	profile := Profile{Home: d.config.Home, Network: spec.Network}
	for _, name := range d.config.Requires {
		resolved, err := d.config.Look(strings.TrimSpace(name))
		if err != nil {
			continue
		}
		profile.Reads = append(profile.Reads, filepath.Dir(resolved))
		if real, err := filepath.EvalSymlinks(resolved); err == nil {
			profile.Reads = append(profile.Reads, filepath.Dir(real))
		}
	}
	for _, path := range spec.Paths {
		profile.Reads = append(profile.Reads, path.Host)
		if path.Access == ReadWrite {
			profile.Writes = append(profile.Writes, path.Host)
		}
	}
	profile.Denies = append(profile.Denies, spec.Denied...)
	profile.DenyWrites = append(profile.DenyWrites, spec.DeniedWrites...)
	// The log directory holds the log, the settings file and the status
	// file. It is never in Paths, so it is already outside every allowWrite
	// entry; it is denied explicitly so that a writable parent granted later
	// cannot include it.
	if spec.LogPath != "" {
		profile.DenyWrites = append(profile.DenyWrites, filepath.Dir(spec.LogPath))
	}
	return profile
}

// Launch starts one stage under srt, detached, with its output written to a
// file the stage cannot write. A wrapper script records the exit status in a
// second file, because the exit status of a reaped child is lost and this
// process may have exited before anyone asks for it.
func (d *Driver) Launch(ctx context.Context, spec StageSpec) (StageHandle, error) {
	if err := d.Preflight(ctx); err != nil {
		return StageHandle{}, err
	}
	if len(spec.Argv) == 0 {
		return StageHandle{}, errors.New("launch stage: argv is empty")
	}
	if strings.TrimSpace(spec.LogPath) == "" {
		return StageHandle{}, errors.New("launch stage: log path is empty")
	}
	// A stage with no PATH resolves nothing, not even srt, whose shebang
	// needs node. It fails with exit code 127 and an empty log, which is the
	// kind of unexplained failure this driver must not produce.
	base := Environment(d.config.Lookup)
	if !hasPath(base) {
		return StageHandle{}, fmt.Errorf("%w: the driver was composed with no PATH, so a stage could run nothing", ErrNotReady)
	}
	srt, err := d.config.Look("srt")
	if err != nil {
		return StageHandle{}, d.notReady(ConditionMissing, "srt")
	}
	logDir := filepath.Dir(spec.LogPath)
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return StageHandle{}, fmt.Errorf("launch stage %s: %w", spec.Name, err)
	}
	settingsPath := sidecar(spec.LogPath, ".srt.json")
	body, err := Render(d.Profile(spec)).Encode()
	if err != nil {
		return StageHandle{}, err
	}
	if err := os.WriteFile(settingsPath, body, 0o600); err != nil {
		return StageHandle{}, fmt.Errorf("launch stage %s: %w", spec.Name, err)
	}
	statusPath := sidecar(spec.LogPath, ".status")
	_ = os.Remove(statusPath)
	_ = os.Remove(statusPath + ".part")

	// The "--" is required. srt parses options anywhere in its arguments
	// unless they are separated, so an argv containing -d, -s, -c, -V or -h
	// would have them consumed by srt.
	command := append([]string{srt, "--settings", settingsPath, "--"}, spec.Argv...)
	launcher := exec.Command("/bin/sh", "-c", wrapperScript(command, statusPath)) //nolint:gosec,noctx // a quoted argv; the stage outlives this context by design
	launcher.Dir = spec.Workdir
	launcher.Env = d.environment(base, spec)
	log, err := os.OpenFile(spec.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // the consumer's own log path
	if err != nil {
		return StageHandle{}, fmt.Errorf("launch stage %s: open log: %w", spec.Name, err)
	}
	defer func() { _ = log.Close() }()
	// Stdin stays nil, which gives the stage the null device. A program that
	// reads an inherited stdin waits on it, and a detached stage whose stdin
	// is a pipe that nobody closes waits forever.
	launcher.Stdout, launcher.Stderr = log, log
	launcher.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := launcher.Start(); err != nil {
		return StageHandle{}, fmt.Errorf("launch stage %s: %w", spec.Name, err)
	}
	pid := launcher.Process.Pid
	// The start time is read before the child is reaped. A stage that has
	// already exited is a zombie at this point, and a zombie still reports
	// its start time; a reaped process reports nothing.
	start, err := startTime(pid)
	if err != nil {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = launcher.Wait()
		return StageHandle{}, fmt.Errorf("launch stage %s: %w", spec.Name, err)
	}
	// The child is reaped in a goroutine rather than released. A released
	// child stays a zombie for the life of this process, and a long-running
	// server would accumulate one per stage. The wait only reaps; it sends no
	// signal, so the stage stays detached and is reparented to init when this
	// process exits first.
	go func() { _ = launcher.Wait() }()
	return StageHandle{Driver: Host, ID: formatHandle(pid, start, spec.LogPath)}, nil
}

// wrapperScript returns the shell script the driver runs: the stage's command
// followed by a record of its exit status. The status is written to a
// temporary file and renamed, so it appears whole or not at all. Written in
// place, it could be observed empty, with the process exited and the file
// present but not yet written, which would read as a stage the driver lost.
func wrapperScript(command []string, statusPath string) string {
	part := ShellQuote(statusPath + ".part")
	return fmt.Sprintf("%s\ncode=$?\nprintf %%s $code > %s\nmv -f %s %s\n",
		ShellJoin(command), part, part, ShellQuote(statusPath))
}

// hasPath reports whether an environment has a non-empty PATH.
func hasPath(environ []string) bool {
	for _, entry := range environ {
		if name, value, found := strings.Cut(entry, "="); found && name == "PATH" && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// environment returns the environment the stage runs with: the allowlisted
// base, the HOME and TERM this driver sets, and the stage's own variables.
// Credentials named in EnvFile travel here rather than on a command line, so
// they never appear in the process table.
func (d *Driver) environment(base []string, spec StageSpec) []string {
	environment := append([]string(nil), base...)
	environment = append(environment, "HOME="+d.config.Home, "TERM=dumb")
	for name, value := range spec.Env {
		environment = append(environment, name+"="+value)
	}
	return environment
}

// Observe reports whether the stage is alive. A stage is finished once its
// wrapper has written the status file. Otherwise it is running only if the pid
// is alive and started when the handle says it did; a pid the operating system
// has reused fails that test.
func (d *Driver) Observe(_ context.Context, handle StageHandle) (StageStatus, error) {
	pid, start, logPath, err := parseHandle(handle)
	if err != nil {
		return StageStatus{}, err
	}
	statusPath := sidecar(logPath, ".status")
	if code, ok := readStatus(statusPath); ok {
		return StageStatus{ExitCode: code}, nil
	}
	if isStage(pid, start) {
		return StageStatus{Running: true}, nil
	}
	// The process is not observably alive and there is no status yet. The
	// wrapper records its status before it exits, so the two observations
	// race: the process can be gone before the rename has completed. Wait a
	// bounded time rather than report a finished stage as lost, because an
	// exit read as gone fails a run that succeeded.
	for range 10 {
		time.Sleep(20 * time.Millisecond)
		if code, ok := readStatus(statusPath); ok {
			return StageStatus{ExitCode: code}, nil
		}
		if isStage(pid, start) {
			return StageStatus{Running: true}, nil
		}
	}
	return StageStatus{Gone: true}, nil
}

// Output streams the stage's log from an offset. The driver writes the log
// into a directory no stage may write, so a stage cannot rewrite its own
// transcript.
func (d *Driver) Output(_ context.Context, handle StageHandle, offset int64) (io.ReadCloser, error) {
	_, _, logPath, err := parseHandle(handle)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(logPath) //nolint:gosec // the path comes from this package's own handle
	if errors.Is(err, os.ErrNotExist) {
		return io.NopCloser(strings.NewReader("")), nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// Stop ends a running stage together with its whole process group. srt starts
// helper processes, and killing only the wrapper would leave the stage
// running. Stop sends SIGTERM, waits for the status file for the grace period,
// then sends SIGKILL to the group. The status file, not the leader's liveness,
// is the signal that the stage has finished, because a leader can exit on
// SIGTERM while a child it started keeps running.
func (d *Driver) Stop(ctx context.Context, handle StageHandle) error {
	pid, start, logPath, err := parseHandle(handle)
	if err != nil {
		return err
	}
	statusPath := sidecar(logPath, ".status")
	if _, done := readStatus(statusPath); done {
		return nil
	}
	if !isStage(pid, start) {
		return nil
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	deadline := time.Now().Add(d.config.StopGrace)
	for time.Now().Before(deadline) {
		if _, done := readStatus(statusPath); done {
			return nil
		}
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	return nil
}

// Discard stops the stage. There is nothing else to remove: this driver
// creates no image, container or volume, and the log directory is the
// consumer's.
func (d *Driver) Discard(ctx context.Context, handle StageHandle) error {
	return d.Stop(ctx, handle)
}

// sidecar names a file the driver keeps beside the log: the log path with its
// extension replaced. The settings file is ".srt.json" and the status file is
// ".status", so a handle, which carries only the log path, locates both.
func sidecar(logPath, ext string) string {
	return strings.TrimSuffix(logPath, filepath.Ext(logPath)) + ext
}

// formatHandle renders the handle id: the pid, the start time in Unix seconds,
// and the log path, which may itself contain colons and therefore comes last.
func formatHandle(pid int, start int64, logPath string) string {
	return fmt.Sprintf("pid:%d@%d:%s", pid, start, logPath)
}

func parseHandle(handle StageHandle) (int, int64, string, error) {
	if err := MatchHandle(Host, handle); err != nil {
		return 0, 0, "", err
	}
	rest, ok := strings.CutPrefix(handle.ID, "pid:")
	if !ok {
		return 0, 0, "", fmt.Errorf("%w: %q has no pid prefix", ErrInvalidHandle, handle.ID)
	}
	identity, logPath, ok := strings.Cut(rest, ":")
	if !ok || logPath == "" {
		return 0, 0, "", fmt.Errorf("%w: %q names no log", ErrInvalidHandle, handle.ID)
	}
	pidText, startText, ok := strings.Cut(identity, "@")
	if !ok {
		return 0, 0, "", fmt.Errorf("%w: %q carries no start time", ErrInvalidHandle, handle.ID)
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 {
		return 0, 0, "", fmt.Errorf("%w: %q has a malformed pid", ErrInvalidHandle, handle.ID)
	}
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil {
		return 0, 0, "", fmt.Errorf("%w: %q has a malformed start time", ErrInvalidHandle, handle.ID)
	}
	return pid, start, logPath, nil
}

func readStatus(path string) (int, bool) {
	body, err := os.ReadFile(path) //nolint:gosec // the path comes from this package's own handle
	if err != nil {
		return 0, false
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		return 0, false
	}
	return code, true
}

// isStage reports whether the process under pid is alive and is the stage
// the handle names: alive by signal zero, and started when the handle says.
func isStage(pid int, start int64) bool {
	if pid <= 0 || syscall.Kill(pid, 0) != nil {
		return false
	}
	observed, err := startTime(pid)
	return err == nil && observed == start
}

// psStartLayout is the lstart format ps prints under the C locale on macOS
// and on procps: "Sat Sep 12 21:17:31 2026".
const psStartLayout = "Mon Jan _2 15:04:05 2006"

// startTime is the process start time in Unix seconds, read through ps so
// that one code path serves macOS and Linux. The locale is pinned so the date
// parses the same on every machine.
var startTime = func(pid int) (int64, error) {
	command := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "lstart=") //nolint:gosec,noctx // a fixed command over an integer pid
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.Output()
	if err != nil {
		return 0, fmt.Errorf("read start time of pid %d: %w", pid, err)
	}
	text := strings.Join(strings.Fields(string(output)), " ")
	started, err := time.ParseInLocation(psStartLayout, text, time.Local)
	if err != nil {
		return 0, fmt.Errorf("read start time of pid %d: ps printed %q: %w", pid, text, err)
	}
	return started.Unix(), nil
}
