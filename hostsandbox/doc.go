// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package hostsandbox runs a process on the operator's own machine inside the
// operating system's sandbox, detached from the process that started it, with
// its output written where the sandboxed process cannot reach. On macOS, in
// a program whose main calls Main, it uses Seatbelt directly, through
// /usr/bin/sandbox-exec and a profile this package renders; otherwise it uses
// srt, Anthropic's sandbox runtime (Seatbelt on macOS, bubblewrap with
// seccomp on Linux). Config.Isolation chooses either explicitly.
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
// # The driver
//
// New builds the Driver. Under srt, Launch renders the StageSpec into srt's
// settings file (Render, Profile, Settings); under Seatbelt, into a Seatbelt
// profile (RenderSeatbelt). Either way it starts the stage in its own session with
// setsid so that it outlives the launching process, and runs it under a
// wrapper script that records the exit status in a file beside the log. The
// handle is "pid:<pid>@<start>:<log>": the pid, the process start time in
// Unix seconds as the operating system reports it, and the log path. Observe
// answers from the status file first, then from the pid and start time, so a
// pid the operating system has reused is not mistaken for the stage and a
// driver built after a restart recovers the stage from the handle alone.
// Both isolations keep the same handles, status files and process groups, and
// the driver's name, Host, is the same under both, so a stage launched under
// one is observed, read, stopped and discarded by a driver composed with the
// other. Output reads the log from an offset. Stop signals the whole process group
// with SIGTERM, waits for the grace period for the group to empty, then sends
// SIGKILL, so it also ends a process the stage left running after its main
// process exited. The group is signaled only while it provably is the
// stage's: its leader is alive with the handle's start time, or the leader is
// gone and a member started no later than the stage was last known to run,
// when Stop last saw its leader or when it recorded its exit status. A group
// formed later under a reused pid has only members started after that, so it
// is never signaled; a group whose leader died without recording a status
// before Stop was called is left alone for the same reason. A process that
// left the group itself, by starting its own session, is not reached. Discard
// is Stop: the driver creates nothing else.
//
// Command is the attached form: the same rendering as Launch, returned as an
// exec.Cmd whose pipes the caller sets, with a cleanup for its settings file.
// It is for a stage that reads stdin from its caller, and it ends with the
// caller: its pipes close when the calling process exits, and its context
// ending kills its whole process group. It records no status and no handle.
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
// from a read grant that would otherwise cover it; srt honors a denial that
// is more specific than the allowance it falls inside.
//
// # Seatbelt
//
// The profile denies everything, then allows what a program needs to run at
// all (starting processes, and among Mach services the user and group
// database, the system log, its temporary directory's lookup and certificate
// trust evaluation, each listed with why), then the path policy above, written
// from the broadest rule to the narrowest because the last rule that matches
// decides. Preferences are not a service a stage reaches: it reads them only
// from files it is granted, so the operator's preferences stay with the home
// directory they live in.
//
// The path policy is srt's, with these differences. Seatbelt matches the
// resolved path a process opens, so a denial is written both as given and
// with its symbolic links resolved. A grant is written as given, and its
// resolution kept only when it stays inside the granted tree (macOS's /tmp,
// /var and /etc are the same trees under /private): a link that leads out of
// a grant, which a stage can leave in place of a directory it may write,
// grants nothing beyond its own spelling, and a writable grant that is itself
// a link is refused. The directories above a grant inside the home directory
// may be examined but not listed. Read denials are also denied writing.
// Writes are also allowed to the null and zero devices and the controlling
// terminal.
//
// Inside every writable grant, at any depth and in any case, a stage may not
// write, move, create or replace what a shell, git or an editor's agent acts
// on once the operator runs it: shell startup files, .gitconfig,
// .gitmodules, .mcp.json and .ripgreprc; .vscode, .idea and an agent's
// .claude/commands and .claude/agents with everything in them; in each
// gitdir of git's layout (.git, a submodule's under .git/modules at any
// depth, a worktree's under .git/worktrees) its config, config.worktree and
// hooks; and the directories that layout and those paths depend on: .git
// itself, whether a directory or a file pointing git at a gitdir,
// .git/modules, .git/worktrees and each gitdir in them, and .claude. Each is
// named by its path, so a rename is refused at its source and at its
// destination, and a directory holding a repository may still be moved,
// since the protection follows the name .git. Ordinary git work goes on:
// objects, refs, the index and logs stay writable, so add, commit, branch,
// checkout and fetch work. What it costs, as srt's default costs it: git
// init, git clone, git config, git submodule and git worktree add inside a
// grant fail, since each writes what is protected. Its limit: a .git file
// the operator already pointed at a gitdir outside git's layout leaves that
// gitdir's config and hooks unprotected, unless they lie in another
// protected place. srt protects the same kinds of path at its working
// directory.
//
// A stage with no network runs straight under sandbox-exec and may connect
// to nothing: no address, no name lookup, no local socket. A stage with a
// network allowlist reaches the network only through an egress proxy on a
// loopback port, the one destination its profile allows. The proxy admits a
// CONNECT by its target host and port and a plain request by its absolute
// URL's, the host matched as hostmatch matches: a host named alone is
// admitted for a CONNECT to 443 and a plain request to 80, a host named as
// host:port on that port alone, and every other port is refused. It never
// terminates TLS: there is no certificate authority and nothing to inspect,
// so Network.Passthrough has nothing to exempt, and unlike srt it does not
// see inside a tunnel. A destination on this machine or its link-local network
// is refused on the address it resolves to, even when its name is allowed.
// The stage's proxy variables name the proxy; a client that ignores them
// cannot connect at all.
//
// A detached stage outlives the process that launched it, so its proxy
// cannot live there. The driver starts the consumer's own program again as
// the stage's launcher, which serves the proxy, renders the profile once the
// proxy's port is known, runs the stage under sandbox-exec and exits with
// its exit code. That needs the consumer's main to call Main as its first
// statement, which is also what makes IsolationAuto pick Seatbelt: a program
// that has not called it keeps srt. Under an explicit IsolationSeatbelt
// without Main, an allowlisted stage is refused with a NotReadyError of
// ConditionNoLauncher, Capabilities declares no allowlist, and stages with
// no network run as before. The cost is one launcher
// process per allowlisted stage, the consumer's binary, which holds the
// stage's environment and runs outside the sandbox.
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
// Under Seatbelt, Preflight needs /usr/bin/sandbox-exec, which is part of
// macOS, and Config.Requires; nothing is installed. Under srt, Preflight
// resolves srt, the executables srt needs on the platform (bwrap,
// which the bubblewrap package installs, socat and ripgrep on Linux, ripgrep
// on macOS), and
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
