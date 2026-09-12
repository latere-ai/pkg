// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// DriverName identifies one isolation mechanism. A consumer records it beside
// every handle, so a stage started under one driver is never observed through
// another, whose handles have a different meaning.
type DriverName string

// Host is the srt driver's name.
const Host DriverName = "host"

// Access is how a stage may use one path.
type Access string

// The path access modes. A path not named in a StageSpec is denied; there is
// no implicit read inside the home directory.
const (
	ReadOnly  Access = "ro"
	ReadWrite Access = "rw"
)

// Path is one filesystem path a stage may use, given as a host path. A driver
// maps it to what the stage sees: the same path under the srt driver, or a
// mount destination under a container driver.
type Path struct {
	// Host is the absolute path on the machine running the stage.
	Host string
	// Guest is the path the stage sees. Empty means the same as Host.
	Guest string
	// Access is read-only or read-write.
	Access Access
}

// Destination is where the stage sees this path: Guest when the driver remaps
// it and Host when it does not.
func (p Path) Destination() string {
	if strings.TrimSpace(p.Guest) != "" {
		return p.Guest
	}
	return p.Host
}

// The network modes a StageSpec can carry. A driver declares in its
// Capabilities which of them it enforces; the srt driver cannot express
// NetworkOpen, because srt refuses a wildcard.
const (
	NetworkNone      = "none"
	NetworkAllowlist = "allowlist"
	NetworkOpen      = "open"
)

// Network is a stage's egress policy.
type Network struct {
	// Mode is NetworkNone, NetworkAllowlist or NetworkOpen.
	Mode string
	// Domains is the allowlist. It is meaningful only in allowlist mode.
	Domains []string
	// Passthrough lists domains reached without the sandbox terminating TLS.
	// They remain subject to the allowlist; only the inspection is skipped,
	// for clients that do not trust an injected certificate authority.
	Passthrough []string
}

// StageSpec is one unit of work a driver runs. Everything in it is computed
// by the consumer; a driver translates it into a Seatbelt profile, a
// bubblewrap invocation or engine arguments, and adds nothing of its own.
type StageSpec struct {
	// Name is a short label such as "worker-0", used in error messages.
	Name string
	// Argv is the command. It is never a shell fragment.
	Argv []string
	// Env is the stage's own environment, added after the inherited
	// allowlist.
	Env map[string]string
	// EnvFile names the keys in Env whose values are credentials. A driver
	// must not place these on a command line.
	EnvFile []string
	// Workdir is the directory the stage starts in.
	Workdir string
	// Paths is every path the stage may read or write inside the home
	// directory. A path not listed is denied.
	Paths []Path
	// Denied are paths that stay unreadable even though an entry in Paths
	// covers them, so that one file can be withheld from a directory that
	// must be readable for another.
	Denied []string
	// DeniedWrites are paths that stay read-only even though a ReadWrite
	// entry in Paths covers them. The directory holding LogPath is denied
	// whether or not it is listed.
	DeniedWrites []string
	// Network is the egress policy.
	Network Network
	// LogPath is the host file the driver writes the stage's combined
	// output to. The driver keeps the settings file and the exit status
	// beside it, named after it with another extension. It is never granted
	// to the stage, so the stage cannot rewrite its own transcript.
	LogPath string
}

// StageHandle is a driver's durable reference to one launched stage. It is
// opaque to the consumer, which stores it and passes it back to the driver,
// so it survives JSON encoding and carries no credential.
type StageHandle struct {
	// Driver is which driver launched the stage.
	Driver DriverName `json:"driver"`
	// ID is the driver's own reference: a pid, start time and log path for
	// the srt driver, a container name for a container driver.
	ID string `json:"id"`
}

// Valid reports whether the handle names something a driver could look up.
func (h StageHandle) Valid() bool {
	return strings.TrimSpace(string(h.Driver)) != "" && strings.TrimSpace(h.ID) != ""
}

// StageStatus is one observation of a launched stage.
type StageStatus struct {
	// Running reports whether the stage is still alive.
	Running bool
	// ExitCode is meaningful only once Running is false. A stage killed by a
	// signal reports the shell's convention of 128 plus the signal number.
	ExitCode int
	// Gone reports that the driver has no record of the stage: the process
	// is not alive and no exit status was recorded. Running is false and
	// ExitCode is not meaningful.
	Gone bool
}

// Succeeded reports whether the stage finished and exited zero.
func (s StageStatus) Succeeded() bool { return !s.Running && !s.Gone && s.ExitCode == 0 }

// Capabilities is what a driver can enforce and install. A driver declares
// only what it enforces; there is no best-effort mode in which an allowlist
// silently becomes open egress.
type Capabilities struct {
	// PackageManagers are the managers a stage under this driver can install
	// with. The srt driver declares none: what the host toolchain provides
	// is the consumer's knowledge.
	PackageManagers map[string]bool
	// NetworkModes are the egress policies this driver enforces.
	NetworkModes map[string]bool
	// MaxAttachmentBytes bounds a single file written into the stage's
	// workspace before launch. Zero means the consumer's default applies.
	MaxAttachmentBytes int64
}

// Sandbox is one isolation mechanism that can run a stage. Every
// implementation is held to the contract in hostsandboxtest.
type Sandbox interface {
	// Name is the driver's canonical name. It is recorded in every handle
	// the driver issues, and every call that takes a handle checks it.
	Name() DriverName

	// Preflight reports whether this machine can run the driver at all. When
	// it cannot, Preflight returns a *NotReadyError carrying remediation.
	Preflight(context.Context) error

	// Capabilities reports what this driver can enforce and install.
	Capabilities() Capabilities

	// Launch starts one stage detached and returns a handle that survives
	// the calling process.
	Launch(context.Context, StageSpec) (StageHandle, error)

	// Observe reports whether a launched stage is still running, and its
	// exit status once it is not.
	Observe(context.Context, StageHandle) (StageStatus, error)

	// Output streams the stage's raw bytes from an offset, out of a location
	// the stage itself cannot write. A stage that has written nothing yet
	// yields an empty stream rather than an error, because callers poll.
	Output(context.Context, StageHandle, int64) (io.ReadCloser, error)

	// Stop terminates a running stage with a grace period. Stopping a stage
	// that has already exited is not an error.
	Stop(context.Context, StageHandle) error

	// Discard removes whatever the driver created for the stage. It never
	// touches the log or the directory holding it, which are the consumer's.
	Discard(context.Context, StageHandle) error
}

// Errors this package returns.
var (
	// ErrNotReady reports a machine that cannot run a driver. It is a
	// refusal with instructions attached; the driver never starts partially.
	ErrNotReady = errors.New("sandbox is not ready")
	// ErrMismatch reports a stage handle routed to a driver that did not
	// launch it.
	ErrMismatch = errors.New("stage handle belongs to another driver")
	// ErrInvalidHandle reports a stage handle no driver could look up: one
	// with no driver or no id, or one whose id does not parse.
	ErrInvalidHandle = errors.New("invalid stage handle")
	// ErrGone reports a stage the driver no longer holds.
	ErrGone = errors.New("stage is gone")
)

// MismatchError names both drivers of a misrouted handle.
type MismatchError struct {
	Expected DriverName
	Actual   DriverName
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf("%v: expected %q, got %q", ErrMismatch, e.Expected, e.Actual)
}

func (e *MismatchError) Unwrap() error { return ErrMismatch }

// MatchHandle returns an error for a handle routed to the wrong driver, or
// for one that is not Valid. Handles from two drivers are both opaque strings
// and would otherwise be interchangeable, so a pid could be looked up as a
// container name.
func MatchHandle(driver DriverName, handle StageHandle) error {
	if !handle.Valid() {
		return fmt.Errorf("%w: empty driver or id", ErrInvalidHandle)
	}
	if handle.Driver != driver {
		return &MismatchError{Expected: driver, Actual: handle.Driver}
	}
	return nil
}
