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

// Host is the host sandbox's name, under Seatbelt and under srt alike.
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
// maps it to what the stage sees: the same path under the host sandbox, or a
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
// Capabilities which of them it enforces; the host sandbox does not express
// NetworkOpen, because srt refuses a wildcard and Seatbelt allows a stage no
// destination but its egress proxy.
//
// NetworkDenylist admits any host except those Network.Blocked names. It is
// never a default: a stage gets it only when its Mode says so. With it, any
// server on the internet is reachable, so everything the stage can read, the
// whole of every folder it is granted, can be sent there; a consumer
// offering it says so to the person before turning it on. The host sandbox
// enforces it only under Seatbelt, through the egress proxy, which refuses
// this machine, its local networks and every address that is not public
// whatever the name. On a Mac whose proxy or VPN app answers names with
// fake addresses (198.18.0.0/15) to carry the connection itself, a deny-list
// stage reaches nothing until that mode is turned off, since where such a
// connection goes cannot be checked.
const (
	NetworkNone      = "none"
	NetworkAllowlist = "allowlist"
	NetworkDenylist  = "denylist"
	NetworkOpen      = "open"
)

// Network is a stage's egress policy. It is fixed when the stage starts: no
// driver call changes the network of a running stage. To admit a host a
// stage was refused, start the next stage with it.
type Network struct {
	// Mode is NetworkNone, NetworkAllowlist, NetworkDenylist or NetworkOpen.
	Mode string
	// Domains is the allowlist. In allowlist mode it is every host the stage
	// may reach. In deny-list mode it adds the ports an entry names as
	// host:port to the standard ones every host is admitted on, and an entry
	// Blocked matches stays refused.
	Domains []string
	// Blocked is the deny list, meaningful only in deny-list mode; a stage of
	// another mode that names one is refused. An entry matches the host a
	// stage asks for as an allowlist entry does: exact, or every name below
	// it for "*.example.com", which does not match example.com itself, so
	// blocking a domain and its subdomains takes both entries. A host named
	// alone is blocked on every port, and host:port on that port alone. An
	// entry that is neither a host name, an address nor a wildcard over one,
	// or names a port that is not a number from 1 to 65535, is refused
	// rather than blocking nothing.
	//
	// The deny list is about the names a stage asks for, not the servers
	// behind them: another name for the same server, or its address, is not
	// blocked by a name. An entry that is an address is blocked in every
	// spelling of it, its form under the well-known NAT64 prefix
	// (64:ff9b::/96) among them, and also whatever name the stage reaches it
	// through, since the address each connection dials is checked against
	// it. Under a NAT64 prefix of a network's own, an IPv4 entry is not
	// recognized. This machine, its local networks and the addresses that
	// are not public are refused by address, whatever name reaches them.
	Blocked []string
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
	// beside it, named after it with another extension. The driver denies
	// writes to the directory that holds it, so a writable path granted
	// around it does not let the stage rewrite or remove its own
	// transcript. Reading it is the consumer's to grant: a ReadOnly entry
	// for LogPath in Paths lets a command stat and read its own output,
	// which macOS's seatbelt checks against the file's path even on an
	// open descriptor, and grants nothing beside it.
	LogPath string
	// OnRefused, when set, is called with the host and port of each
	// connection the stage's network refuses by name or port: a host the
	// allowlist does not admit or the deny list blocks, or a port neither
	// admits. The host is the one the stage asked for, lower case and
	// without a trailing dot: a host name of ASCII letters, digits, hyphens
	// and underscores whose last label is not a number, an IDN in its xn--
	// form, or an address in the canonical form of the address it reaches,
	// which a prompt says is an address; a request for anything else is
	// refused without a call. So an address spelled otherwise, in its
	// IPv4-mapped or NAT64 form among them, is refused unreported, though an
	// allowlist entry of that exact spelling would admit it. The call
	// carries nothing else of the request: no request line, header, path or
	// body. Refusals no Allow could lift are not reported when the
	// proxy can tell without looking a name up: one by the address a name
	// resolves to, one of a localhost name, and one of an address the
	// network refuses whatever its names say. A name refused for its port is
	// reported whatever it resolves to, so an Allow of a name whose
	// addresses the network refuses still reaches nothing.
	//
	// The host is chosen by whatever runs in the stage, so a prompt that
	// offers to allow it shows it exactly, and allowing it is the person's
	// decision. Allowing it applies to the next stage: a running stage's
	// network does not change. The call does not say why the host was
	// refused; under a deny list, it was blocked when an entry of Blocked
	// matches it, by the rule above, and its port was refused otherwise. A
	// host a wildcard entry blocks is allowed only by narrowing or removing
	// that entry, since a blocked host stays refused whatever Domains says.
	//
	// A refusal repeated within a minute on the same host and port is
	// reported once, and at most 256 hosts and ports are reported a minute.
	// The reports are the stage's to shape: one that asks for host after
	// host can use that bound up, and the refusals after it in the minute
	// are not reported, though they stay refused; a prompt coalesces what
	// arrives together. Delivery never holds up the stage's network: past a
	// small buffer, refusals are dropped. Calls for one stage come one at a
	// time, from a goroutine of the driver's in the process that called
	// Launch or Command; a function shared by several stages is called
	// concurrently. For a detached stage, refusals are reported for as long
	// as that process runs: after it exits, the stage's log still notes each.
	// For an attached command, the cleanup waits up to two seconds for the
	// refusals still on their way; once it returns, no call begins, while one
	// that began before may still be running. OnRefused may call the
	// cleanup.
	//
	// It is called only under Seatbelt, for a stage whose network goes
	// through the egress proxy: an allowlist, which with OnRefused set runs
	// the proxy even when it names no host, in a program that calls Main, so
	// its refusals are reported, or a deny list. srt and a stage with
	// NetworkNone never call it.
	OnRefused func(host string, port int) `json:"-"`
}

// StageHandle is a driver's durable reference to one launched stage. It is
// opaque to the consumer, which stores it and passes it back to the driver,
// so it survives JSON encoding and carries no credential.
type StageHandle struct {
	// Driver is which driver launched the stage.
	Driver DriverName `json:"driver"`
	// ID is the driver's own reference: a pid, start time and log path for
	// the host sandbox, a container name for a container driver.
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
	// with. The host sandbox declares none: what the host toolchain provides
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

	// Stop terminates the stage with a grace period, together with every
	// process it started that is still running, including one left running
	// after the stage's main process exited. Stop leaves the exit status
	// already recorded as it is. Stopping a stage that has exited and left
	// nothing running is not an error.
	Stop(context.Context, StageHandle) error

	// Discard ends whatever of the stage is still running, as Stop does, and
	// removes whatever the driver created for the stage. It never touches
	// the log or the directory holding it, which are the consumer's.
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
	// ErrUnenforceableNetwork reports a stage network the driver will not
	// run, since it cannot enforce it as written: a deny list under srt,
	// which is allow-only, a deny-list entry it cannot read, or a deny list
	// on a stage of another mode.
	ErrUnenforceableNetwork = errors.New("stage network cannot be enforced")
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
