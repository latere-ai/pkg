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
// a link is refused. Only a path that does not exist yet is resolved through
// its deepest existing ancestor; a path whose links cannot be resolved for
// another reason, a loop of links, a path longer than macOS opens or a
// directory that may not be searched, is refused rather than written only as
// given. The directories above a grant inside the home directory
// may be examined but not listed. Read denials are also denied writing. A
// denial inside a writable grant, of reading or of writing, also keeps the
// grant and every directory between them in place: a stage may not rename,
// swap or remove them, and may not create one that does not exist yet, while
// it still creates, writes and removes files inside the ones that do, so the
// denial stays on the path it names. So when the home directory is granted
// writable and ~/.docker or ~/.config does not exist, the always-deny
// table's entries below them (~/.docker/config.json and ~/.config/gcloud)
// keep a stage from creating either directory, and a tool that writes its
// settings under ~/.config fails; create them before granting the home
// directory. A denial whose path runs through a symbolic link that leads
// nowhere is refused, since a write through it would land on a name the
// stage can create. Cloning a directory is denied
// everywhere, so a stage cannot copy a tree holding files it may not read
// into a grant it may; cloning a file and an ordinary recursive copy still
// work. Writes are also allowed to the null and zero devices and the
// controlling terminal.
//
// Inside every writable grant, at any depth and in any case, a stage may not
// write, move, create or replace what a shell, direnv, git, an editor or an
// agent acts on once the operator runs it. By name, at any depth: shell
// startup files, .envrc, .gitconfig, .gitmodules, .mcp.json, .ripgreprc and
// any *.code-workspace. As whole trees, the directory included: .vscode,
// .idea, and an agent's .claude and .cursor, which name commands and
// servers. And git's layout: every .git, whether a directory or a file
// pointing git at a gitdir, with everything below it, so a gitdir and git's
// layout of them (.git/modules, .git/worktrees and the gitdirs they hold)
// can be neither written nor moved, created, replaced or repointed.
//
// Inside a gitdir, what everyday git writes is allowed back, and nothing
// else: a gitdir is denied, then objects (but not objects/info/alternates or
// objects/info/http-alternates, which make git read another repository),
// refs, logs, rebase-merge, rebase-apply and sequencer with everything in
// them; the index with its .lock and temporary companions; HEAD, ORIG_HEAD,
// FETCH_HEAD, MERGE_HEAD, MERGE_MSG, MERGE_MODE, AUTO_MERGE, CHERRY_PICK_HEAD,
// REVERT_HEAD, REBASE_HEAD, COMMIT_EDITMSG, SQUASH_MSG, TAG_EDITMSG,
// packed-refs, gc.pid, gc.log and shallow, each with its .lock companion; the
// index with its split-index sharedindex.<hash>; and the BISECT_ files. A
// submodule's gitdir is under .git/modules at any depth, since git stores a
// submodule at a/b under .git/modules/a/b, and a worktree's under
// .git/worktrees; everything in each is allowed back the same way, except
// that a protected name nested below a writable subdir (a .git, a .claude,
// .cursor, .vscode or .idea, or a protected file) is denied again, so the
// allowance opens no repository or settings hidden inside objects, refs or
// logs. Because the allowance lists what everyday git writes rather than what
// is dangerous, a control file the list does not name, config, config.worktree,
// hooks, commondir, gitdir, info, an alternates file or a name git adds later,
// stays denied by default. So add, commit, branch, checkout, merge, rebase,
// cherry-pick, revert, stash, tag, bisect, gc, fetch and work in a submodule
// work, while a stage cannot point git at a hook, object store or common
// directory of its own. A bare repository, a directory whose name ends in
// .git with its gitdir at the top level, is protected the same way: its config
// and hooks are denied and a push into it, which writes its objects and refs,
// works. Its folder is pinned too: no name ending in .git may be removed,
// renamed away or created inside a grant, except a branch or tag of that name
// in git's refs and logs, so a stage cannot swap a repository the
// operator later pushes to for one carrying hooks of its own. Moving the
// ordinary folder that holds one carries it along, still pinned.
//
// Each path is named by its path, so a rename is refused at its source and at
// its destination, and a directory holding a repository may still be moved,
// since the protection follows the name .git. What it costs, as srt's default
// costs it: git init, git clone, git config, git remote, git submodule and
// git worktree add inside a grant fail, since each writes what is protected;
// and, because no file or folder whose name ends in .git can be created
// outside git's refs and logs, a stage can neither make a bare repository
// with git init --bare, git clone --bare or git clone --mirror nor write a
// bundle under such a name, and a checkout cannot write a tracked path of
// that name (git reports it but may still exit 0). Its limits: a .git file
// the operator already pointed at a gitdir outside git's layout leaves that
// gitdir's control files unprotected, unless they lie in another protected
// place; a bare repository whose name does not end in .git is not recognized
// as a gitdir, so its config and hooks are writable, and a local remote that
// names a bare repository without its .git suffix may reach a folder of that
// shorter name, so name a local remote in a grant by its full .git path; and
// a stage may write .git/rebase-merge, .git/rebase-apply and .git/sequencer,
// so it can fake an in-progress rebase, cherry-pick or revert whose todo or
// sequencer/opts holds an exec line, which runs only if the operator later
// continues it outside the sandbox (git rebase, cherry-pick or revert
// --continue). srt protects the same kinds of path at its working directory.
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
// A stage with a deny list, NetworkDenylist, goes through the same proxy,
// which admits any host on the standard ports, and a host Domains names as
// host:port on that port, unless Network.Blocked matches it; a blocked name
// is refused before it is looked up. The deny list matches the names a
// stage asks for, as an allowlist does. A host that is not a well-formed
// name or address is refused, as is a name whose last label is a number,
// which a resolver reads as an address, and an address is matched in its
// canonical form, so no spelling of a blocked name or address gets past it.
// An address the deny list names is also refused when a name resolves to
// it. What a deny list cannot block by name is refused by address: before
// each connection is opened, the address a name resolved to is checked, so
// a name that resolves elsewhere on its next lookup is checked again, and
// this machine, the networks of its Wi-Fi and Ethernet (for IPv6, the /48
// holding each address it has there), its own addresses, the private,
// carrier-grade NAT, link-local, unique local, multicast, reserved,
// benchmarking and documentation ranges and every IPv6 address outside
// global unicast are refused, an IPv4 address carried in IPv6 (mapped,
// NAT64 under its well-known prefix, or 6to4) by the address it carries.
// Every failure to reach a host is answered alike, so the answer says
// neither what a name resolved to nor whether a local name exists. What an
// address cannot show is not refused: a server inside the person's network
// reached at a public address, such as the router's own through its port
// forwarding, or a local or blocked address behind a NAT64 prefix of the
// network's own.
// The mode is a choice the person makes, never a default: any server on the
// internet can then receive whatever the stage can read.
//
// A stage's network is fixed when it starts. The proxy runs in the stage's
// launcher, a process of its own that outlives a detached stage's caller,
// and reads the network once, from the stage file the driver wrote, before
// the stage runs; there is no channel through which a running stage's
// network widens. Such a channel would have to reach the launcher from
// outside the sandbox while the stage runs, and would be one more thing a
// stage must never write; srt could not honor it at all; and Profile would
// no longer show what a stage may reach. A consumer that lets the person
// allow a refused host widens its own record of the session's network, and
// the next stage it starts gets it.
//
// A detached stage outlives the process that launched it, so its proxy
// cannot live there. The driver starts the consumer's own program again as
// the stage's launcher, which serves the proxy, renders the profile once the
// proxy's port is known, runs the stage under sandbox-exec and exits with
// its exit code. That needs the consumer's main to call Main as its first
// statement, which is also what makes IsolationAuto pick Seatbelt: a program
// that has not called it keeps srt. Under an explicit IsolationSeatbelt
// without Main, an allowlisted stage is refused with a NotReadyError of
// ConditionNoLauncher, as is a stage with a deny list, Capabilities declares
// neither, and stages with no network run as before. The cost is one
// launcher process per stage with a network, the consumer's binary, which
// holds the stage's environment and runs outside the sandbox.
//
// # The network policy
//
// srt is allow-only and refuses a wildcard, so the driver declares
// NetworkNone and NetworkAllowlist and no open mode, and under Seatbelt with
// a launcher NetworkDenylist as well; a deny list under srt is refused with
// ErrUnenforceableNetwork. TLS termination is
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
