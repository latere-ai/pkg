// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
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
// operator runs later, a shell, direnv, git, an editor or an agent, so
// writing one is running code outside the sandbox. Each is protected at any
// depth below the grant, in any case; writeProtectedSuffixes are protected
// the same way by the end of their name.
var (
	writeProtectedFiles = []string{
		".bash_login", ".bash_profile", ".bashrc", ".profile",
		".zlogin", ".zprofile", ".zshenv", ".zshrc",
		".envrc", ".gitconfig", ".gitmodules", ".mcp.json", ".ripgreprc",
	}
	writeProtectedSuffixes = []string{".code-workspace"}
)

// writeProtectedTrees are directories inside a writable grant that a stage
// may not write at all, the directory itself included: an editor's or an
// agent's settings, which name commands it runs and servers it starts. A
// Latere session has no reason to write them.
var writeProtectedTrees = []string{".claude", ".cursor", ".idea", ".vscode"}

// A gitdir is denied every write except what everyday git writes, so a name
// git reads and this list forgets, or one git adds later, stays denied.
// gitWritableDirs and everything in them, and gitWritableFiles with their
// .lock companions, are written back by commit, branch, checkout, merge,
// rebase, cherry-pick, revert, stash, tag, fetch, bisect and gc; nothing in
// them names a command git runs. gitDeniedInWritable are the exceptions
// inside an allowed directory: an alternates file makes git read objects
// from another repository.
var (
	gitWritableDirs  = []string{"objects", "refs", "logs", "rebase-merge", "rebase-apply", "sequencer"}
	gitWritableFiles = []string{
		"HEAD", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "MERGE_MSG", "MERGE_MODE",
		"AUTO_MERGE", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD", "COMMIT_EDITMSG",
		"SQUASH_MSG", "TAG_EDITMSG", "packed-refs", "gc.pid", "gc.log", "shallow",
	}
	// Prefixes cover a family of files git writes under one name: BISECT_*,
	// git's index and the temporary indexes it writes beside it (index.lock,
	// index.stash.<pid>), and the split index's sharedindex.<hash>, all of
	// which hold tracked content, never a command.
	gitWritablePrefixes = []string{"BISECT_", "index", "sharedindex"}
	gitDeniedInWritable = []string{"objects/info/alternates", "objects/info/http-alternates"}
)

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
// are allowed only in the profile's writes; then what protectedPatterns
// names at any depth is denied inside them, every gitdir among it; then what
// everyday git writes in a gitdir is allowed back and its exceptions denied
// again; then DenyWrites and every denied read are denied, last, so a
// consumer's denial wins over every allowance. A denial inside a writable
// grant also pins the grant and every directory between them, which a stage
// may not rename or remove, and, where one does not exist yet, may not
// create, so the denial stays on the path it names. Cloning a directory is
// denied everywhere, so no stage copies a tree of files it may not read into
// a grant it may.
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
// language has no safe way to write, a path, as given or resolved, longer
// than seatbeltStringMax, a path whose links cannot be resolved for any
// reason but that it does not exist yet, and a denial whose path runs
// through a symbolic link that leads nowhere.
func RenderSeatbelt(profile Profile, proxyPort int) (string, error) {
	for _, path := range profile.Writes {
		if info, err := lstat(filepath.Clean(path)); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("render seatbelt profile: the writable grant %s is a symbolic link; grant the directory it names", path)
		}
	}
	var homes []string
	var err error
	if profile.Home != "" {
		if homes, err = canonicalAll([]string{profile.Home}); err != nil {
			return "", fmt.Errorf("render seatbelt profile: %w", err)
		}
	}
	denyRead, err := canonicalAll(expandAll(profile.Home, append(append([]string(nil), AlwaysDenyRead...), profile.Denies...)))
	if err != nil {
		return "", fmt.Errorf("render seatbelt profile: %w", err)
	}
	reads, err := allowAll(profile.Reads)
	if err != nil {
		return "", fmt.Errorf("render seatbelt profile: %w", err)
	}
	writes, err := allowAll(profile.Writes)
	if err != nil {
		return "", fmt.Errorf("render seatbelt profile: %w", err)
	}
	denyWrites, err := canonicalAll(append(append([]string(nil), profile.DenyWrites...), denyRead...))
	if err != nil {
		return "", fmt.Errorf("render seatbelt profile: %w", err)
	}
	var protected, gitAllowed, gitDenied []string
	for _, write := range writes {
		protected = append(protected, protectedPatterns(write)...)
		allowed, denied := gitPatterns(write)
		gitAllowed = append(gitAllowed, allowed...)
		gitDenied = append(gitDenied, denied...)
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
		if len(path) > seatbeltStringMax {
			return "", fmt.Errorf("render seatbelt profile: the path %q is %d bytes, longer than the %d a path on macOS may have", path, len(path), seatbeltStringMax)
		}
	}
	pins := pinned(writes, denyWrites)
	absent, err := absentPins(pins)
	if err != nil {
		return "", fmt.Errorf("render seatbelt profile: %w", err)
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
	rule(&b, "deny", "file-write*", "regex", protected)
	rule(&b, "allow", "file-write*", "regex", gitAllowed)
	rule(&b, "deny", "file-write*", "regex", gitDenied)
	rule(&b, "deny", "file-write*", "subpath", denyWrites)
	rule(&b, "deny", "file-write-unlink", "literal", pins)
	rule(&b, "deny", "file-write-create", "literal", absent)
	// A directory clone copies every file below it, the ones a stage may not
	// read among them, into the clone, which it may. Cloning a directory is
	// denied everywhere, so the read denials hold; cloning a file and an
	// ordinary recursive copy, which falls back to copying when a clone is
	// refused, still work.
	b.WriteString("(deny file-clone (vnode-type DIRECTORY))\n")
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

// seatbeltStringMax is the most bytes one string literal of the profile
// language holds, counted after its escapes are read: sandbox-exec's reader
// refuses a longer literal with "Error reading string", and with it the
// whole profile, so no command runs. A literal of 1023 bytes loads and one of
// 1024 does not. A protection pattern repeats its writable grant's path, so
// a grant with a long path reaches it, and sbString splits such a value.
//
// It is also the longest path macOS opens: PATH_MAX, 1024 bytes, less the
// terminating NUL. RenderSeatbelt refuses a longer path rather than split
// it, since lstat answers such a path with ENAMETOOLONG, so its symbolic
// links cannot be resolved, and a denial written only as given denies
// nothing a stage reaches through a link.
const seatbeltStringMax = 1023

// sbString writes a value as a string of the profile language: in double
// quotes, with a backslash and a double quote escaped. A value longer than
// seatbeltStringMax is written as (string-append ...) of literals that each
// fit, split between characters, which the profile language evaluates to the
// same value; a value that fits is written as one literal.
func sbString(value string) string {
	quote := func(piece string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(piece) + `"`
	}
	if len(value) <= seatbeltStringMax {
		return quote(value)
	}
	var b strings.Builder
	b.WriteString("(string-append")
	for value != "" {
		cut := min(len(value), seatbeltStringMax)
		// Back off to the start of a character, at most the bytes one
		// character spans, so a piece never ends inside a character's
		// encoding and a value that is not valid UTF-8 still advances.
		for back := 0; cut < len(value) && back < utf8.UTFMax-1 && !utf8.RuneStart(value[cut]); back++ {
			cut--
		}
		b.WriteString(" " + quote(value[:cut]))
		value = value[cut:]
	}
	b.WriteString(")")
	return b.String()
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
func allowSpellings(path string) ([]string, error) {
	spellings, err := canonical(path)
	if err != nil || len(spellings) < 2 {
		return spellings, err
	}
	given, resolved := spellings[0], spellings[1]
	inside := func(tree string) bool {
		return resolved == tree || strings.HasPrefix(resolved, tree+string(filepath.Separator))
	}
	if inside(given) {
		return spellings, nil
	}
	for _, firm := range []string{"/tmp", "/var", "/etc"} {
		if given == firm || strings.HasPrefix(given, firm+string(filepath.Separator)) {
			if inside("/private" + given) {
				return spellings, nil
			}
		}
	}
	return spellings[:1], nil
}

// allowAll is allowSpellings over every grant, trimmed, without empties or
// duplicates, and sorted.
func allowAll(paths []string) ([]string, error) {
	var out []string
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		spellings, err := allowSpellings(strings.TrimSpace(path))
		if err != nil {
			return nil, err
		}
		out = append(out, spellings...)
	}
	return sorted(out), nil
}

// protectedPatterns are the regular expressions, for the profile's regex
// filter, of what a stage may not write below the writable grant write:
// writeProtectedFiles and writeProtectedSuffixes, writeProtectedTrees with
// the directories themselves, and every .git, whether a directory or a file
// pointing git at a gitdir, with everything below it, so a gitdir and
// git's layout of them (.git/modules, .git/worktrees and the gitdirs they
// hold) can be neither written nor moved, created, replaced or repointed.
// gitPatterns allows back what everyday git writes. The grant's own path is
// matched literally, and each protected name in any case, since a name on a
// case-insensitive volume reaches the same file whatever its case. Each
// pattern names the path itself and so covers a rename's source and
// destination as well as a write.
func protectedPatterns(write string) []string {
	base := "^" + regexLiteral(write) + "(/.*)?/"
	var out []string
	for _, name := range writeProtectedFiles {
		out = append(out, base+anyCase(name)+"$")
	}
	for _, suffix := range writeProtectedSuffixes {
		out = append(out, base+"[^/]*"+anyCase(suffix)+"$")
	}
	for _, name := range writeProtectedTrees {
		out = append(out, base+anyCase(name)+"(/.*)?$")
	}
	// Every .git, a directory or a file pointing git at a gitdir, with its
	// contents: the node is pinned and the tree denied, then gitPatterns
	// allows back what everyday git writes.
	out = append(out, base+anyCase(".git")+"(/.*)?$")
	// A bare repository is a directory whose name ends in .git, its gitdir at
	// the top level. Its contents are denied here (its config and hooks among
	// them), and gitPatterns allows back the same everyday-git paths. The
	// node itself is not pinned, so a file simply named *.git stays writable.
	return append(out, base+"[^/]+"+anyCase(".git")+"/.*$")
}

// pinned lists, for every denial inside a writable grant, the grant and the
// directories between it and the denial, without the denial itself, which
// its own denial already covers. Seatbelt matches a path, so a denial holds
// only while the directories above it stay where they are; denying
// file-write-unlink on each keeps it from being renamed, swapped or removed,
// while files are still created, written and removed inside it and the
// denial's path stays free to be created. Every spelling of a grant is
// paired with every spelling of a denial below it.
func pinned(writes, denials []string) []string {
	var out []string
	for _, write := range writes {
		prefix := strings.TrimSuffix(write, string(filepath.Separator)) + string(filepath.Separator)
		for _, denial := range denials {
			if !strings.HasPrefix(denial, prefix) {
				continue
			}
			// The walk stops at the grant, and never climbs above it.
			for dir := filepath.Dir(denial); strings.HasPrefix(dir+string(filepath.Separator), prefix); dir = filepath.Dir(dir) {
				out = append(out, dir)
				if dir == write {
					break
				}
			}
		}
	}
	return sorted(out)
}

// absentPins splits the pinned directories, reporting those that do not
// exist at render time, which a stage must be stopped from creating. A pin
// is held in place against renaming and removal only once it exists; a name
// on the path to a denial that does not exist yet could otherwise be created
// as a link, or have a prepared directory renamed into it, to move the
// denial off the path it names, so file-write-create is denied on each. A
// pin that is a symbolic link leading nowhere is refused instead: a write
// through it lands on the name it points at, which the stage may create, so
// no rule on the link's own name would hold.
func absentPins(pins []string) ([]string, error) {
	var absent []string
	for _, dir := range pins {
		info, err := lstat(dir)
		if err != nil {
			// No name here yet; deny creating one.
			absent = append(absent, dir)
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			// A directory that exists, held by its unlink pin.
			continue
		}
		if _, err := evalSymlinks(dir); err != nil {
			return nil, fmt.Errorf("the denied path runs through %q, a symbolic link that leads nowhere; create the directory it points at, or point it at one that exists", dir)
		}
	}
	return absent, nil
}

// gitPatterns are the regular expressions of what everyday git writes in
// each gitdir below the writable grant write, allowed back inside the
// protection of .git, and of the exceptions denied again inside those. A
// gitdir is .git, a submodule's under .git/modules at any depth, or a
// worktree's under .git/worktrees; what the list leaves out (config,
// config.worktree, hooks, commondir, gitdir, info, alternates and any name
// git adds later) stays denied.
func gitPatterns(write string) (allowed, denied []string) {
	names := func(list []string) string {
		out := make([]string, len(list))
		for i, name := range list {
			out[i] = anyCase(name)
		}
		return "(" + strings.Join(out, "|") + ")"
	}
	// A gitdir is .git, a bare repository (a directory whose name ends in
	// .git), or a submodule's or worktree's gitdir within either. git stores
	// a submodule at a/b under .git/modules/a/b, so a submodule name carries
	// any depth of segments; a worktree name is one segment. The anchor is a
	// component ending in .git and, optionally, that layout down to the inner
	// gitdir, so the allowance applies in each without opening the layout's
	// own config or hooks.
	gitdir := "^" + regexLiteral(write) + "(/.*)?/[^/]*" + anyCase(".git") +
		"(/" + anyCase("modules") + "(/[^/]+)+)?(/" + anyCase("worktrees") + "/[^/]+)?/"
	allowed = []string{
		gitdir + names(gitWritableDirs) + "(/.*)?$",
		gitdir + names(gitWritableFiles) + "(" + anyCase(".lock") + ")?$",
		gitdir + names(gitWritablePrefixes) + "[^/]*$",
	}
	for _, path := range gitDeniedInWritable {
		denied = append(denied, gitdir+anyCase(path)+"$")
	}
	// A writable subdir of a gitdir holds data, not a repository or an
	// agent's or editor's settings. The allowance above would re-open a
	// protected name nested in one (git never writes such a name there, since
	// its refs, logs and objects carry no path component beginning with a
	// dot), so each is denied again below a writable subdir, scoped there so
	// the layout's own refs, logs and objects stay allowed.
	below := gitdir + names(gitWritableDirs) + "/(.*/)?"
	for _, name := range append([]string{".git"}, writeProtectedTrees...) {
		denied = append(denied, below+anyCase(name)+"(/.*)?$")
	}
	for _, name := range writeProtectedFiles {
		denied = append(denied, below+anyCase(name)+"$")
	}
	for _, suffix := range writeProtectedSuffixes {
		denied = append(denied, below+"[^/]*"+anyCase(suffix)+"$")
	}
	return allowed, denied
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
// not exist yet, or does not because an ancestor of it is a file, is
// resolved through its deepest existing ancestor, so a grant made before its
// directory is created still matches once it is. Any other failure to
// resolve a path, a loop of links, a path too long or a directory that may
// not be searched, is an error: a denial written without its resolved
// spelling would deny nothing reached through a link.
func canonical(path string) ([]string, error) {
	clean := filepath.Clean(path)
	out := []string{clean}
	dir, rest := clean, ""
	for {
		real, err := evalSymlinks(dir)
		if err == nil {
			if resolved := filepath.Join(real, rest); resolved != clean {
				out = append(out, resolved)
			}
			return out, nil
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
			return nil, fmt.Errorf("the path %q cannot be resolved: %w", clean, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return out, nil
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

// canonicalAll is canonical over every path, trimmed, without empties or
// duplicates, and sorted, so two equal profiles render the same text.
func canonicalAll(paths []string) ([]string, error) {
	var out []string
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		spellings, err := canonical(strings.TrimSpace(path))
		if err != nil {
			return nil, err
		}
		out = append(out, spellings...)
	}
	return sorted(out), nil
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
