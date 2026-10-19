// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// sandboxExec is macOS's own program that runs a command under a Seatbelt
// profile. It is named by its absolute path and never looked up on PATH: a
// program of that name planted earlier on PATH would run the stage under no
// sandbox at all. A test points it at a stand-in.
var sandboxExec = "/usr/bin/sandbox-exec"

// seatbeltServices are the Mach services a stage may look up, each for one
// thing a program needs in order to run. Everything else a Mach lookup could
// reach stays denied: preferences (cfprefsd answers for every domain of the
// user, whatever the file policy says, so a stage reads preferences only from
// files it is granted), the pasteboard, the keychain's user interface, file
// system events naming paths outside the grants, and other applications.
var seatbeltServices = []string{
	// confstr's per-user temporary and cache directories, which Apple's
	// developer tools ask for before they run (git, python3 and clang are
	// xcrun shims that fail without it).
	"com.apple.bsd.dirhelper",
	// os_log, which a system framework writes to; without it the framework
	// blocks or aborts.
	"com.apple.logd",
	"com.apple.system.logger",
	// The notification center libSystem consults for time zone and
	// network configuration changes.
	"com.apple.system.notification_center",
	// The user and group database: id, whoami, ls -l and getpwuid.
	"com.apple.system.opendirectoryd.libinfo",
	// Certificate trust evaluation, through which a TLS client on macOS's
	// own verifier checks a server; Go's crypto/x509 fails without it.
	// Apple's curl and git read their own certificate file and need none.
	"com.apple.trustd.agent",
}

// seatbeltDevices are the device files a stage may open for writing and
// control: the null and zero devices, the controlling terminal, and the
// device the JavaScript and Python runtimes open for their probes. Another
// terminal of the same user is not among them.
var seatbeltDevices = []string{"/dev/dtracehelper", "/dev/null", "/dev/tty", "/dev/zero"}

// writeProtectedFiles are files inside a writable grant that a stage may not
// write, move, create or replace: each is read and acted on by a program the
// operator runs later, a shell, git or an editor's agent, so writing one is
// running code outside the sandbox. Each is protected at any depth below the
// grant, in any case.
var writeProtectedFiles = []string{
	".bash_login", ".bash_profile", ".bashrc", ".profile",
	".zlogin", ".zprofile", ".zshenv", ".zshrc",
	".gitconfig", ".gitmodules",
	".mcp.json", ".ripgreprc",
}

// writeProtectedDirs are directories inside a writable grant that a stage may
// neither write into nor move, create or replace, for the same reason: an
// editor's settings and an agent's commands.
var writeProtectedDirs = []string{".vscode", ".idea", ".claude/commands", ".claude/agents"}

// pinnedNames are directories inside a writable grant that hold protected
// paths: a stage may write inside them, but may not move, create, replace or
// otherwise write the directory itself, so it cannot move one away, write
// into it under another name and move it back. A .git that is a file,
// pointing git at a gitdir, is held the same way, so it can be neither
// written nor put in place.
var pinnedNames = []string{".git", ".claude"}

// RenderSeatbelt turns a profile into the Seatbelt profile sandbox-exec runs
// a stage under.
//
// Everything is denied unless a rule allows it, and where rules overlap the
// last one that matches decides, so the rules are written from the broadest
// to the narrowest. Reads are allowed everywhere, then the home directory is
// denied, then the profile's reads are allowed back, then the always-deny
// table and the profile's denials are denied again, so a denial wins inside
// any grant. The directories above a grant inside the home directory may be
// examined but not listed, so a program can resolve the grant's path. Writes
// are allowed only in the profile's writes, then DenyWrites, every denied
// read, and what protectedPatterns names at any depth are denied inside
// them.
//
// proxyPort is the loopback port of the stage's egress proxy, the one
// network destination the stage may reach. Zero renders no network at all:
// no connection, no name lookup and no local socket.
//
// Seatbelt matches the resolved path a process opens. A denial is written
// both as given and with its symbolic links resolved, so it holds whichever
// way the path is reached. A grant is written as given, and resolved only
// when the resolution stays inside the granted tree (macOS's /tmp and /var
// are the same trees under /private): a link that leads elsewhere, which a
// stage can put in place of a directory it may write, grants nothing beyond
// its own spelling. A writable grant that is itself a symbolic link is
// refused, as is a path holding a control character, which the profile
// language has no safe way to write.
func RenderSeatbelt(profile Profile, proxyPort int) (string, error) {
	for _, path := range profile.Writes {
		if info, err := lstat(filepath.Clean(path)); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("render seatbelt profile: the writable grant %s is a symbolic link; grant the directory it names", path)
		}
	}
	var homes []string
	if profile.Home != "" {
		homes = canonicalAll([]string{profile.Home})
	}
	denyRead := canonicalAll(expandAll(profile.Home, append(append([]string(nil), AlwaysDenyRead...), profile.Denies...)))
	reads := allowAll(profile.Reads)
	writes := allowAll(profile.Writes)
	denyWrites := canonicalAll(append(append([]string(nil), profile.DenyWrites...), denyRead...))
	var protected []string
	for _, write := range writes {
		protected = append(protected, protectedPatterns(write)...)
	}
	var ancestors []string
	for _, home := range homes {
		ancestors = append(ancestors, home)
		for _, path := range append(append([]string(nil), reads...), writes...) {
			ancestors = append(ancestors, above(home, path)...)
		}
	}
	for _, path := range concat(homes, denyRead, reads, writes, denyWrites) {
		if strings.ContainsFunc(path, isControl) {
			return "", fmt.Errorf("render seatbelt profile: the path %q holds a control character", path)
		}
	}

	var b strings.Builder
	b.WriteString(";; A stage's Seatbelt profile, rendered by latere.ai/x/pkg/hostsandbox.\n")
	b.WriteString(";; Where rules overlap, the last one that matches decides.\n")
	b.WriteString("(version 1)\n(deny default)\n")
	b.WriteString("(allow process-exec)\n(allow process-fork)\n")
	b.WriteString("(allow signal (target same-sandbox))\n(allow process-info* (target same-sandbox))\n")
	b.WriteString("(allow sysctl-read)\n(allow file-map-executable)\n")
	b.WriteString("(allow ipc-posix-sem)\n(allow ipc-posix-shm)\n")
	rule(&b, "allow", "mach-lookup", "global-name", seatbeltServices)

	b.WriteString(";; Reads: everywhere but the home directory, then the grants, then the denials.\n")
	b.WriteString("(allow file-read*)\n")
	rule(&b, "deny", "file-read*", "subpath", homes)
	rule(&b, "allow", "file-read-metadata", "literal", sorted(ancestors))
	rule(&b, "allow", "file-read*", "subpath", reads)
	rule(&b, "deny", "file-read*", "subpath", denyRead)

	b.WriteString(";; Writes: only the grants, less what stays read-only inside them.\n")
	rule(&b, "allow", "file-write*", "subpath", writes)
	rule(&b, "deny", "file-write*", "subpath", denyWrites)
	rule(&b, "deny", "file-write*", "regex", protected)
	rule(&b, "allow", "file-write*", "literal", seatbeltDevices)
	rule(&b, "allow", "file-ioctl", "literal", seatbeltDevices)

	if proxyPort > 0 {
		b.WriteString(";; Network: the stage's egress proxy on the loopback interface, and nothing else.\n")
		fmt.Fprintf(&b, "(allow network-outbound (remote ip %s))\n", sbString("localhost:"+strconv.Itoa(proxyPort)))
	}
	return b.String(), nil
}

// rule writes one rule naming every value as a filter, or nothing when there
// are no values: a rule with no filter would apply to every path.
func rule(b *strings.Builder, action, operation, filter string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "(%s %s", action, operation)
	for _, value := range values {
		fmt.Fprintf(b, "\n  (%s %s)", filter, sbString(value))
	}
	b.WriteString(")\n")
}

// sbString writes a value as a string of the profile language: in double
// quotes, with a backslash and a double quote escaped.
func sbString(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// evalSymlinks resolves a path's symbolic links, and lstat describes a path
// without following its last link. A test replaces them.
var (
	evalSymlinks = filepath.EvalSymlinks
	lstat        = os.Lstat
)

// allowSpellings returns a grant as written and, when the resolution stays
// inside the granted tree, with its symbolic links resolved. The resolution
// stays inside when it is the path itself, the same path under /private for
// macOS's /tmp, /var and /etc, or a path below either. Any other resolution
// (the home directory, the root, a sibling) is a link that leads out of the
// grant, and only the spelling is kept: Seatbelt then matches nothing
// through the link.
func allowSpellings(path string) []string {
	spellings := canonical(path)
	if len(spellings) < 2 {
		return spellings
	}
	given, resolved := spellings[0], spellings[1]
	inside := func(tree string) bool {
		return resolved == tree || strings.HasPrefix(resolved, tree+string(filepath.Separator))
	}
	if inside(given) {
		return spellings
	}
	for _, firm := range []string{"/tmp", "/var", "/etc"} {
		if given == firm || strings.HasPrefix(given, firm+string(filepath.Separator)) {
			if inside("/private" + given) {
				return spellings
			}
		}
	}
	return spellings[:1]
}

// allowAll is allowSpellings over every grant, trimmed, without empties or
// duplicates, and sorted.
func allowAll(paths []string) []string {
	var out []string
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		out = append(out, allowSpellings(strings.TrimSpace(path))...)
	}
	return sorted(out)
}

// protectedPatterns are the regular expressions, for the profile's regex
// filter, of what a stage may not write below the writable grant write:
// writeProtectedFiles, writeProtectedDirs and everything in them, the
// pinnedNames directories themselves, and git's own: in a gitdir (.git, a
// submodule's under .git/modules at any depth, or a worktree's under
// .git/worktrees), its config, its config.worktree and its hooks with
// everything in them, and the .git/modules and .git/worktrees directories
// and each gitdir they hold, so none can be moved out of git's layout and
// back. The grant's own path is matched literally, and each protected name
// in any case, since a name on a case-insensitive volume reaches the same
// file whatever its case. Each pattern names the path itself and so covers
// a rename's source and destination as well as a write.
func protectedPatterns(write string) []string {
	base := "^" + regexLiteral(write) + "(/.*)?/"
	var out []string
	for _, name := range writeProtectedFiles {
		out = append(out, base+anyCase(name)+"$")
	}
	for _, name := range writeProtectedDirs {
		out = append(out, base+anyCase(name)+"(/.*)?$")
	}
	for _, name := range pinnedNames {
		out = append(out, base+anyCase(name)+"$")
	}
	nested := "(/" + anyCase("modules") + "/[^/]+)*"
	gitdirs := base + anyCase(".git") + nested
	worktree := "(/" + anyCase("worktrees") + "/[^/]+)?"
	out = append(out,
		gitdirs+"/("+anyCase("modules")+"|"+anyCase("worktrees")+")(/[^/]+)?$",
		gitdirs+worktree+"/"+anyCase("config")+"("+anyCase(".worktree")+")?$",
		gitdirs+worktree+"/"+anyCase("hooks")+"(/.*)?$",
	)
	return out
}

// regexLiteral escapes every character a regular expression gives meaning.
func regexLiteral(value string) string {
	var b strings.Builder
	for _, r := range value {
		if strings.ContainsRune(`\.^$|?*+()[]{}`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// anyCase writes a name as a pattern matching it in any case: each letter a
// class of its two cases, everything else escaped.
func anyCase(name string) string {
	var b strings.Builder
	for _, r := range name {
		lower, upper := strings.ToLower(string(r)), strings.ToUpper(string(r))
		if lower != upper {
			b.WriteString("[" + lower + upper + "]")
			continue
		}
		b.WriteString(regexLiteral(string(r)))
	}
	return b.String()
}

// canonical returns a path as written and, when it differs, with its
// symbolic links resolved: /tmp/x is also /private/tmp/x. A path that does
// not exist yet is resolved through its deepest existing ancestor, so a
// grant made before its directory is created still matches once it is.
func canonical(path string) []string {
	clean := filepath.Clean(path)
	out := []string{clean}
	dir, rest := clean, ""
	for {
		if real, err := evalSymlinks(dir); err == nil {
			if resolved := filepath.Join(real, rest); resolved != clean {
				out = append(out, resolved)
			}
			return out
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return out
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

// canonicalAll is canonical over every path, trimmed, without empties or
// duplicates, and sorted, so two equal profiles render the same text.
func canonicalAll(paths []string) []string {
	var out []string
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		out = append(out, canonical(strings.TrimSpace(path))...)
	}
	return sorted(out)
}

// above lists the directories between home and path, from path's parent up
// to the directory just below home, for a path inside home; nothing for a
// path outside it. Home itself is examinable separately.
func above(home, path string) []string {
	if !strings.HasPrefix(path, home+string(filepath.Separator)) {
		return nil
	}
	var out []string
	for dir := filepath.Dir(path); dir != home && strings.HasPrefix(dir, home); dir = filepath.Dir(dir) {
		out = append(out, dir)
	}
	return out
}

func concat(lists ...[]string) []string {
	var out []string
	for _, list := range lists {
		out = append(out, list...)
	}
	return out
}
