// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package hostsandbox runs a process on the operator's own machine inside an
// srt sandbox (Seatbelt on macOS, bubblewrap with seccomp on Linux), detached
// from the process that started it, with its output written where the
// sandboxed process cannot reach.
//
// # The stage vocabulary
//
// A StageSpec is one unit of work: an argv, an environment, the paths the
// process may read or write, its egress policy, and the file its output goes
// to. A StageHandle is the durable reference Launch returns; it survives JSON
// encoding and carries no credential, so a consumer stores it and hands it to
// a driver built in another process. A StageStatus is one observation of a
// launched stage. Capabilities is what a driver can enforce. Sandbox is the
// interface a driver satisfies. Any isolation mechanism that can run a
// StageSpec, a container engine or a remote executor as much as srt,
// implements Sandbox and is held to the same contract by hostsandboxtest.
//
// # The srt driver
//
// New builds the Driver. Launch renders the StageSpec into srt's settings file
// (Render, Profile, Settings), starts the stage in its own session with
// setsid so that it outlives the launching process, and runs it under a
// wrapper script that records the exit status in a file beside the log. The
// handle is "pid:<pid>@<start>:<log>": the pid, the process start time in
// Unix seconds as the operating system reports it, and the log path. Observe
// answers from the status file first, then from the pid and start time, so a
// pid the operating system has reused is not mistaken for the stage and a
// driver built after a restart recovers the stage from the handle alone.
// Output reads the log from an offset. Stop signals the whole process group
// with SIGTERM, waits for the status file for the grace period, then sends
// SIGKILL. Discard is Stop: the driver creates nothing else.
//
// # The path policy
//
// srt allows reads everywhere by default and treats allowRead as an exception
// to denyRead, so the driver denies the operator's whole home directory and
// AlwaysDenyRead, then allows back exactly the paths in StageSpec.Paths and
// the directories of the executables in Config.Requires. Writes run the other
// way: allowWrite is narrow and denyWrite makes exceptions to it, so only the
// ReadWrite paths are writable and StageSpec.DeniedWrites and the directory
// holding LogPath are denied inside them. StageSpec.Denied withholds a path
// from a read grant that would otherwise cover it; srt honours a denial that
// is more specific than the allowance it falls inside.
//
// # The network policy
//
// srt is allow-only and refuses a wildcard, so the driver declares
// NetworkNone and NetworkAllowlist and no open mode. TLS termination is
// declared whenever a domain is allowed, because srt publishes its certificate
// authority to the per-tool trust variables only then, and without them every
// HTTPS client in the sandbox rejects the proxy. Network.Passthrough names the
// domains excluded from inspection, for clients that do not read those
// variables.
//
// # The environment
//
// A stage inherits AllowedEnvironment from the launching process through the
// Lookup function in Config, then HOME set to Config.Home and TERM=dumb, then
// StageSpec.Env. A process environment is never copied wholesale, so a
// credential exported in the operator's shell does not reach a process that
// runs with its permission prompts bypassed. A stage whose environment has no
// PATH is refused: srt is a script whose shebang resolves node, and without a
// PATH it exits 127 with an empty log.
//
// # Readiness
//
// Preflight resolves srt, the executables srt needs on the platform
// (bubblewrap, socat and ripgrep on Linux, ripgrep on macOS), and
// Config.Requires. When one is missing it returns a *NotReadyError whose
// Remediation holds the install commands for the platform and whose
// Alternative is Config.Alternative verbatim, so the consumer names its own
// fallback. Windows is refused: srt marks its Windows support as alpha.
// Remedies is the install table; DefaultRemedies covers srt and its
// dependencies, and a consumer adds rows for the programs it requires.
// NotReady builds the same error as a pure function of platform, condition
// and components, so every message is reachable from a test on a machine with
// nothing installed.
package hostsandbox
