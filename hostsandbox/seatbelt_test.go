// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// dirInfo is what lstat returns, in a rendering test, for a path the test
// treats as an existing directory: named after the path's last element, of
// size zero, a directory, with no modification time and no system data.
type dirInfo struct{ name string }

var _ os.FileInfo = dirInfo{}

func (d dirInfo) Name() string     { return d.name }
func (dirInfo) Size() int64        { return 0 }
func (dirInfo) Mode() os.FileMode  { return os.ModeDir | 0o700 }
func (dirInfo) ModTime() time.Time { return time.Time{} }
func (dirInfo) IsDir() bool        { return true }
func (dirInfo) Sys() any           { return nil }

// literalPaths makes canonical return every path as written and every path an
// existing directory, so a rendering test reads the same on every machine and
// no path it names looks absent or linked.
func literalPaths(t *testing.T) {
	t.Helper()
	savedEval, savedLstat := evalSymlinks, lstat
	evalSymlinks = func(path string) (string, error) { return path, nil }
	lstat = func(path string) (os.FileInfo, error) { return dirInfo{name: filepath.Base(path)}, nil }
	t.Cleanup(func() { evalSymlinks, lstat = savedEval, savedLstat })
}

// position is where a rule naming value as a filter of kind appears in
// text, under the rule's action and operation, or -1.
func position(text, action, operation, filter, value string) int {
	head := "(" + action + " " + operation
	for at := 0; ; {
		start := strings.Index(text[at:], head)
		if start < 0 {
			return -1
		}
		start += at
		// A rule with filters ends where its last filter and the rule
		// itself close together.
		end := strings.Index(text[start:], "))\n")
		if end < 0 {
			return -1
		}
		body := text[start : start+end+2]
		if strings.Contains(body, "("+filter+" "+sbString(value)+")") {
			return start
		}
		at = start + len(head)
	}
}

// TestSeatbeltProfileFollowsThePathPolicy checks each path rule srt's
// renderer documents, in the order Seatbelt needs: since the last matching
// rule decides, the home directory is denied after reads are allowed
// everywhere, the grants come after that denial, and the denials come after
// the grants, so a denial wins inside any grant.
func TestSeatbeltProfileFollowsThePathPolicy(t *testing.T) {
	literalPaths(t)
	profile := Profile{
		Home:       "/Users/op",
		Reads:      []string{"/Users/op/project", "/Users/op/.local/bin", "/opt/tools"},
		Writes:     []string{"/Users/op/project"},
		Denies:     []string{"~/project/.env.local"},
		DenyWrites: []string{"/Users/op/project/.git", "/Users/op/logs"},
	}
	text, err := RenderSeatbelt(profile, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	if !strings.HasPrefix(text, ";;") || !strings.Contains(text, "(version 1)\n(deny default)\n") {
		t.Fatalf("the profile does not start from deny default:\n%s", text)
	}
	everywhere := strings.Index(text, "(allow file-read*)\n")
	home := position(text, "deny", "file-read*", "subpath", "/Users/op")
	grant := position(text, "allow", "file-read*", "subpath", "/Users/op/project")
	alwaysDenied := position(text, "deny", "file-read*", "subpath", "/Users/op/.ssh")
	denied := position(text, "deny", "file-read*", "subpath", "/Users/op/project/.env.local")
	for name, at := range map[string]int{"reads everywhere": everywhere, "the home denial": home, "the grant": grant, "the always-deny table": alwaysDenied, "the stage's denial": denied} {
		if at < 0 {
			t.Fatalf("%s is missing:\n%s", name, text)
		}
	}
	if everywhere >= home || home >= grant || grant >= alwaysDenied || grant >= denied {
		t.Fatalf("the read rules are out of order (everywhere %d, home %d, grant %d, always-deny %d, denial %d):\n%s",
			everywhere, home, grant, alwaysDenied, denied, text)
	}
	for _, path := range AlwaysDenyRead {
		if position(text, "deny", "file-read*", "subpath", expand("/Users/op", path)) < 0 {
			t.Errorf("%s is not denied", path)
		}
	}
	// A program resolves a grant's path by examining the directories above
	// it, which may be examined but not listed.
	for _, dir := range []string{"/Users/op", "/Users/op/.local"} {
		if position(text, "allow", "file-read-metadata", "literal", dir) < 0 {
			t.Errorf("%s above a grant cannot be examined", dir)
		}
	}
	if position(text, "allow", "file-read*", "subpath", "/Users/op/.local") >= 0 {
		t.Error("the directory above a grant is readable, not only examinable")
	}

	writable := position(text, "allow", "file-write*", "subpath", "/Users/op/project")
	if writable < 0 || position(text, "allow", "file-write*", "subpath", "/opt/tools") >= 0 {
		t.Fatalf("writes are not exactly the profile's writes:\n%s", text)
	}
	for _, path := range []string{"/Users/op/project/.git", "/Users/op/logs", "/Users/op/project/.env.local", "/Users/op/.ssh"} {
		if at := position(text, "deny", "file-write*", "subpath", path); at < writable {
			t.Errorf("%s is not denied writing after the writable grant (at %d, grant at %d)", path, at, writable)
		}
	}
	if position(text, "allow", "file-write*", "literal", "/dev/null") < 0 || strings.Contains(text, "ttys") {
		t.Errorf("the devices are not exactly the null device, the controlling terminal and their kin:\n%s", text)
	}
	if strings.Contains(text, "network") {
		t.Errorf("a profile with no proxy names the network:\n%s", text)
	}
}

// TestSeatbeltProfileReachesOnlyTheProxy checks that a stage with an egress
// proxy may connect to the proxy's port on the loopback interface and to
// nothing else.
func TestSeatbeltProfileReachesOnlyTheProxy(t *testing.T) {
	literalPaths(t)
	text, err := RenderSeatbelt(Profile{Home: "/Users/op", Network: Network{Mode: NetworkAllowlist, Domains: []string{"example.com"}}}, 51234)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	if !strings.Contains(text, `(allow network-outbound (remote ip "localhost:51234"))`) {
		t.Fatalf("the proxy's port is not reachable:\n%s", text)
	}
	if strings.Count(text, "(allow network") != 1 || strings.Contains(text, "example.com") {
		t.Fatalf("the profile allows more than the proxy, or names a host the proxy decides:\n%s", text)
	}
}

// TestSeatbeltProfileWritesResolvedPaths checks that a path is written both
// as given and resolved, because Seatbelt matches the resolved path, that a
// path not created yet, or under an ancestor that is a file, resolves
// through its deepest existing ancestor, and that a path that fails to
// resolve for any other reason is an error rather than written only as
// given.
func TestSeatbeltProfileWritesResolvedPaths(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	resolvedReal, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonical(filepath.Join(link, "later", "file"))
	want := filepath.Join(resolvedReal, "later", "file")
	if err != nil || len(got) != 2 || got[0] != filepath.Join(link, "later", "file") || got[1] != want {
		t.Fatalf("canonical = %q, %v, want the path as given and %q", got, err, want)
	}
	if got, err := canonical("/"); err != nil || len(got) != 1 || got[0] != "/" {
		t.Fatalf("canonical(/) = %q, %v", got, err)
	}
	// An ancestor that is a file: the path names nothing, so it resolves
	// through the directory holding the file.
	file := filepath.Join(real, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := canonical(filepath.Join(link, "file", "below")); err != nil || len(got) != 2 || got[1] != filepath.Join(resolvedReal, "file", "below") {
		t.Fatalf("canonical below a file = %q, %v, want it resolved through the file's directory", got, err)
	}
	saved := evalSymlinks
	t.Cleanup(func() { evalSymlinks = saved })
	for name, failure := range map[string]error{
		"does not exist":    &fs.PathError{Op: "lstat", Path: "/a", Err: syscall.ENOENT},
		"is below a file":   &fs.PathError{Op: "lstat", Path: "/a", Err: syscall.ENOTDIR},
		"is too long":       &fs.PathError{Op: "lstat", Path: "/a", Err: syscall.ENAMETOOLONG},
		"may not be read":   &fs.PathError{Op: "lstat", Path: "/a", Err: syscall.EACCES},
		"loops":             errors.New("EvalSymlinks: too many links"),
		"fails another way": errors.New("nothing resolves"),
	} {
		evalSymlinks = func(string) (string, error) { return "", failure }
		got, err := canonical("/a/b")
		walks := errors.Is(failure, fs.ErrNotExist) || errors.Is(failure, syscall.ENOTDIR)
		if walks && (err != nil || len(got) != 1 || got[0] != "/a/b") {
			t.Errorf("canonical of a path that %s = %q, %v, want the path as given", name, got, err)
		}
		if !walks && err == nil {
			t.Errorf("canonical of a path that %s = %q, want an error", name, got)
		}
	}
}

// TestSeatbeltProfileKeepsTheFoldersAboveTheDefaultDenials renders, on the
// real file system, a profile granting the home directory writable, and
// checks that ~/.docker and ~/.config, which hold always-denied paths, may
// not be created while they do not exist, and that once they exist no
// folder is kept from being created, as the package documents.
func TestSeatbeltProfileKeepsTheFoldersAboveTheDefaultDenials(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	profile := Profile{Home: home, Reads: []string{home}, Writes: []string{home}}
	text, err := RenderSeatbelt(profile, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	want := "(deny file-write-create\n" +
		"  (literal " + sbString(filepath.Join(home, ".config")) + ")\n" +
		"  (literal " + sbString(filepath.Join(home, ".docker")) + "))\n"
	if !strings.Contains(text, want) {
		t.Fatalf("the missing folders above the default denials may be created:\n%s", text)
	}
	for _, dir := range []string{".config", ".docker"} {
		if err := os.Mkdir(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if text, err = RenderSeatbelt(profile, 0); err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	// Only the absent-folder pins, which take the literal form, go away once
	// the folders exist; the writable grant's *.git node pin, in the regex
	// form, stays.
	if strings.Contains(text, "(deny file-write-create\n  (literal") {
		t.Fatalf("with the folders in place a folder is still kept from being created:\n%s", text)
	}
}

// TestSeatbeltProfileRefusesADenialThroughADanglingLink renders, on the
// real file system, a write denial inside a writable grant whose path runs
// through a directory that is a symbolic link leading nowhere, and checks it
// is refused; and that once the link points at a directory that exists, the
// same profile renders, so the refusal is specific to a link that leads
// nowhere.
func TestSeatbeltProfileRefusesADenialThroughADanglingLink(t *testing.T) {
	grant, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(grant, "real")
	link := filepath.Join(grant, ".secrets")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	profile := Profile{Home: filepath.Dir(grant), Writes: []string{grant}, DenyWrites: []string{filepath.Join(link, "config")}}
	if _, err := RenderSeatbelt(profile, 0); err == nil || !strings.Contains(err.Error(), "leads nowhere") {
		t.Fatalf("a denial through a dangling link was not refused: %v", err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderSeatbelt(profile, 0); err != nil {
		t.Fatalf("with the link's target in place the profile was refused: %v", err)
	}
}

// TestSeatbeltProfileRefusesAPathItCannotResolve renders, on the real file
// system, a profile naming a path through two links that point at each
// other, in each list a profile names, and checks every one is refused.
func TestSeatbeltProfileRefusesAPathItCannotResolve(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	if err := os.Symlink(second, first); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(first, second); err != nil {
		t.Fatal(err)
	}
	looped := filepath.Join(first, "secret")
	for name, profile := range map[string]Profile{
		"home":         {Home: looped},
		"read":         {Home: dir, Reads: []string{looped}},
		"write":        {Home: dir, Writes: []string{looped}},
		"denial":       {Home: dir, Denies: []string{looped}},
		"write denial": {Home: dir, DenyWrites: []string{looped}},
	} {
		if _, err := RenderSeatbelt(profile, 0); err == nil || !strings.Contains(err.Error(), "cannot be resolved") {
			t.Errorf("a path through a loop of links as the %s was not refused: %v", name, err)
		}
	}
}

// TestSeatbeltProfileRefusesARootWritableGrant checks that a writable grant of
// the file system root is refused, since the per-grant protections are regexes
// anchored on the grant and would match nothing at the root, so granting it
// would silently drop every one of them. A read of the root is unaffected.
func TestSeatbeltProfileRefusesARootWritableGrant(t *testing.T) {
	literalPaths(t)
	// Each of these cleans to the root, including the whitespace spellings that
	// the grant rendering trims before it anchors a rule on them.
	for _, path := range []string{"/", "//", "/.", "/..", "///", " /", "/ ", "\t/\n"} {
		if _, err := RenderSeatbelt(Profile{Home: "/Users/op", Writes: []string{path}}, 0); err == nil || !strings.Contains(err.Error(), "file system root") {
			t.Errorf("a writable grant of %q was not refused: %v", path, err)
		}
	}
	if _, err := RenderSeatbelt(Profile{Home: "/Users/op", Reads: []string{"/"}}, 0); err != nil {
		t.Errorf("a read-only grant of the root was refused: %v", err)
	}
}

// TestSeatbeltProfileRefusesAControlCharacter checks that a path the profile
// language cannot write safely is refused rather than written.
func TestSeatbeltProfileRefusesAControlCharacter(t *testing.T) {
	literalPaths(t)
	for _, profile := range []Profile{
		{Home: "/Users/op", Reads: []string{"/Users/op/a\nb"}},
		{Home: "/Users/op", Denies: []string{"/x\x7f"}},
	} {
		if _, err := RenderSeatbelt(profile, 0); err == nil {
			t.Errorf("a path with a control character was rendered: %+v", profile)
		}
	}
}

// TestSeatbeltProfileRefusesAPathLongerThanMacOSOpens checks that a path of
// 1024 bytes or more, whose links cannot be resolved, is refused in each
// list a profile names, and also when only its resolved spelling is that
// long, while a path of exactly seatbeltStringMax bytes is rendered.
func TestSeatbeltProfileRefusesAPathLongerThanMacOSOpens(t *testing.T) {
	literalPaths(t)
	long := "/" + strings.Repeat("a", seatbeltStringMax)
	for name, profile := range map[string]Profile{
		"home":         {Home: long},
		"read":         {Home: "/Users/op", Reads: []string{long}},
		"write":        {Home: "/Users/op", Writes: []string{long}},
		"denial":       {Home: "/Users/op", Denies: []string{long}},
		"write denial": {Home: "/Users/op", DenyWrites: []string{long}},
	} {
		if _, err := RenderSeatbelt(profile, 0); err == nil || !strings.Contains(err.Error(), "is 1024 bytes") {
			t.Errorf("a %d-byte path as the %s was not refused: %v", len(long), name, err)
		}
	}
	fits := "/" + strings.Repeat("a", seatbeltStringMax-1)
	if _, err := RenderSeatbelt(Profile{Home: "/Users/op", Reads: []string{fits}, Writes: []string{fits}, Denies: []string{fits}}, 0); err != nil {
		t.Fatalf("a path of %d bytes was refused: %v", len(fits), err)
	}
	// /tmp/x is also /private/tmp/x, eight bytes longer once resolved.
	evalSymlinks = func(path string) (string, error) { return "/private" + path, nil }
	if _, err := RenderSeatbelt(Profile{Home: "/Users/op", Denies: []string{"/tmp/" + strings.Repeat("a", seatbeltStringMax-5)}}, 0); err == nil {
		t.Error("a path longer than macOS opens only once resolved was not refused")
	}
}

// TestSeatbeltProfilePinsTheDirectoriesAboveADenial checks that a denial
// inside a writable grant, of reading or of writing, pins the grant and each
// directory between them against unlinking, after every allowance, and pins
// nothing else: not the denial, not a directory above the grant, not another
// grant; and that a profile with no denial inside a writable grant has no
// such rule.
func TestSeatbeltProfilePinsTheDirectoriesAboveADenial(t *testing.T) {
	literalPaths(t)
	text, err := RenderSeatbelt(Profile{Home: "/Users/op", Reads: []string{"/Users/op/project"}, Writes: []string{"/Users/op/project"}}, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	// The directory pins take the literal form; a writable grant's *.git node
	// pin, which every writable grant carries, takes the regex form and is not
	// one of them.
	if strings.Contains(text, "(deny file-write-unlink\n  (literal") {
		t.Fatalf("a profile with no denial inside a writable grant pins a directory:\n%s", text)
	}
	text, err = RenderSeatbelt(Profile{
		Home:       "/Users/op",
		Reads:      []string{"/Users/op/project", "/Users/op/other"},
		Writes:     []string{"/Users/op/project", "/Users/op/other"},
		Denies:     []string{"~/project/a/b/secret"},
		DenyWrites: []string{"/Users/op/project/c/keep"},
	}, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	want := "(deny file-write-unlink\n" +
		"  (literal \"/Users/op/project\")\n" +
		"  (literal \"/Users/op/project/a\")\n" +
		"  (literal \"/Users/op/project/a/b\")\n" +
		"  (literal \"/Users/op/project/c\"))\n"
	if !strings.Contains(text, want) {
		t.Fatalf("the pinned directories are not exactly the grant and those between it and each denial:\n%s", text)
	}
	if pin, denial := strings.Index(text, want), position(text, "deny", "file-write*", "subpath", "/Users/op/project/c/keep"); denial < 0 || pin < denial {
		t.Fatalf("the pins come before the denials (pins at %d, denials at %d):\n%s", pin, denial, text)
	}
	for _, c := range []struct {
		writes, denials, want []string
	}{
		{[]string{"/"}, []string{"/x/y"}, []string{"/", "/x"}},
		{[]string{"/a/b"}, []string{"/a/bc/d", "/a/b", "/a"}, nil},
		{[]string{"/a/b", "/a/b/c"}, []string{"/a/b/c/d/e"}, []string{"/a/b", "/a/b/c", "/a/b/c/d"}},
	} {
		if got := pinned(c.writes, c.denials); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("pinned(%q, %q) = %q, want %q", c.writes, c.denials, got, c.want)
		}
	}
}

// createAllowedIn reports whether a stage may create or remove a regular file
// at path inside the writable grant, deciding as Seatbelt does from the rules
// RenderSeatbelt writes for those operations, in that order, the last that
// matches deciding: the grant allows, the protection denies, git's
// allow-backs allow, the *.git pin denies, its allowance in git's writable
// directories allows, and git's exceptions deny. The *.git allowance is held
// to a regular file by a vnode-type filter this does not model, so the
// directory-versus-file distinction is checked by the real-Seatbelt tests, not
// here; this reads the path rules alone, as for a regular file.
func createAllowedIn(grant, path string) bool {
	allowed, denied := gitPatterns(grant)
	pinned, allowedBack := bareRepoPins(grant)
	decision := path == grant || strings.HasPrefix(path, grant+"/")
	for _, step := range []struct {
		patterns []string
		allow    bool
	}{{protectedPatterns(grant), false}, {allowed, true}, {pinned, false}, {allowedBack, true}, {denied, false}} {
		for _, pattern := range step.patterns {
			if regexp.MustCompile(pattern).MatchString(path) {
				decision = step.allow
			}
		}
	}
	return decision
}

// TestSeatbeltProfilePinsBareRepositoryNodes checks that every writable grant
// pins each node named *.git inside it against unlinking and creation, after
// every file-write* allowance, with the same names allowed back inside git's
// refs and logs, before git's exceptions and the consumer's denials,
// which still win there; what that decides for creating or removing a node;
// that a grant's own name ending in .git is not pinned by its own rule while
// one nested in another writable grant is pinned by that grant's; and that a
// profile with no writable grant carries no such rule.
func TestSeatbeltProfilePinsBareRepositoryNodes(t *testing.T) {
	literalPaths(t)
	readOnly, err := RenderSeatbelt(Profile{Home: "/Users/op", Reads: []string{"/Users/op/project"}}, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	for _, rule := range []string{"file-write-unlink", "file-write-create"} {
		if strings.Contains(readOnly, rule) {
			t.Fatalf("a read-only profile carries %q:\n%s", rule, readOnly)
		}
	}

	// A grant whose own name ends in .git, a second grant nested in it, and a
	// consumer's write denial inside the first.
	grants := []string{"/Users/op/work.git", "/Users/op/work.git/vendor"}
	text, err := RenderSeatbelt(Profile{
		Home: "/Users/op", Reads: grants[:1], Writes: grants, DenyWrites: []string{"/Users/op/work.git/keep"},
	}, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	denial := position(text, "deny", "file-write*", "subpath", "/Users/op/work.git/keep")
	for _, grant := range grants {
		allowed, denied := gitPatterns(grant)
		pinned, allowedBack := bareRepoPins(grant)
		// Both allowances are held to a regular file, so each is written under
		// its own operation's head as a require-all of the regex and the node
		// type rather than a bare regex. The search is bound to the operation's
		// rule, which runs from its head to the next top-level form, so a clause
		// rendered under the wrong operation would not satisfy it.
		allowanceUnder := func(operation string) int {
			start := strings.Index(text, "(allow "+operation+"\n")
			if start < 0 {
				return -1
			}
			end := strings.Index(text[start+1:], "\n(")
			if end < 0 {
				end = len(text)
			} else {
				end += start + 1
			}
			clause := "(require-all (regex " + sbString(allowedBack[0]) + ") (vnode-type REGULAR-FILE))"
			if rel := strings.Index(text[start:end], clause); rel >= 0 {
				return start + rel
			}
			return -1
		}
		at := map[string]int{
			"the grant":            position(text, "allow", "file-write*", "subpath", grant),
			"git's allow-backs":    position(text, "allow", "file-write*", "regex", allowed[0]),
			"the unlink pin":       position(text, "deny", "file-write-unlink", "regex", pinned[0]),
			"the create pin":       position(text, "deny", "file-write-create", "regex", pinned[0]),
			"the unlink allowance": allowanceUnder("file-write-unlink"),
			"the create allowance": allowanceUnder("file-write-create"),
			"git's exceptions":     position(text, "deny", "file-write*", "regex", denied[0]),
			"the write denial":     denial,
		}
		for name, position := range at {
			if position < 0 {
				t.Fatalf("%s of %s is missing:\n%s", name, grant, text)
			}
		}
		for _, order := range [][2]string{
			{"the grant", "the unlink pin"}, {"git's allow-backs", "the unlink pin"}, {"git's allow-backs", "the create pin"},
			{"the unlink pin", "the unlink allowance"}, {"the create pin", "the create allowance"},
			{"the unlink allowance", "git's exceptions"}, {"the create allowance", "git's exceptions"},
			{"the create allowance", "the write denial"},
		} {
			if at[order[0]] >= at[order[1]] {
				t.Errorf("for %s, %s (at %d) does not come before %s (at %d)", grant, order[0], at[order[0]], order[1], at[order[1]])
			}
		}
	}

	// What the rules decide for creating or removing a node.
	const grant = "/g"
	for relative, want := range map[string]bool{
		"notes.txt": true, "x.gitx": true, "agit": true,
		".git/refs/heads/topic.git": true, ".git/logs/refs/heads/topic.git": true, ".git/refs/tags/v1.GIT": true,
		"origin.git/refs/heads/feature.git": true, ".git/modules/a/b/refs/heads/x.git": true,
		".git/worktrees/wt/logs/HEAD.git": true, ".git/refs/heads/team.git/topic": true,
		"origin.git": false, "sub/origin.git": false, "x.GIT": false, "..git": false, ".git.git": false,
		".git": false, "sub/.git": false, "origin.git/config": false, "origin.git/hooks/post-receive": false,
		".git/refs/heads/.git": false, ".git/refs/heads/.claude": false, ".git/objects/info/alternates": false,
		".git/hooks/x.git": false, ".git/x.git": false, "refs/heads/x.git": false,
		".git/objects/x.git": false, ".git/rebase-merge/x.git": false, "origin.git/objects/pack/x.git": false,
	} {
		if got := createAllowedIn(grant, grant+"/"+relative); got != want {
			t.Errorf("creating or removing %s is allowed = %v, want %v", relative, got, want)
		}
	}

	// A grant's own name is not pinned by its own rule; one nested in a
	// writable grant is pinned by that grant's.
	if pinned, _ := bareRepoPins("/g/inner.git"); regexp.MustCompile(pinned[0]).MatchString("/g/inner.git") {
		t.Error("a grant whose name ends in .git is pinned by its own rule")
	}
	if createAllowedIn("/g", "/g/inner.git") {
		t.Error("a grant nested in a writable grant, its name ending in .git, is not pinned by the outer grant")
	}
}

// TestSeatbeltProfileEscapesQuotes checks that a double quote or a backslash
// in a path cannot end the profile's string.
func TestSeatbeltProfileEscapesQuotes(t *testing.T) {
	literalPaths(t)
	text, err := RenderSeatbelt(Profile{Home: "/Users/op", Reads: []string{`/Users/op/a"b\c`}}, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	if !strings.Contains(text, `(subpath "/Users/op/a\"b\\c")`) {
		t.Fatalf("the quote and backslash are not escaped:\n%s", text)
	}
}

// TestAboveListsTheDirectoriesBetween checks the directories that may be
// examined above a grant: those between the home directory and the grant,
// and none for a path outside the home directory.
func TestAboveListsTheDirectoriesBetween(t *testing.T) {
	got := above("/Users/op", "/Users/op/a/b/c")
	if strings.Join(got, ",") != "/Users/op/a/b,/Users/op/a" {
		t.Fatalf("above = %q", got)
	}
	if got := above("/Users/op", "/Users/opx/a"); got != nil {
		t.Fatalf("above for a path beside home = %q", got)
	}
	if got := above("/Users/op", "/opt/a"); got != nil {
		t.Fatalf("above for a path outside home = %q", got)
	}
}

// readProfileStrings reads every string value out of profile text as the
// profile language reads it, each as the literals it is written in: one
// literal in double quotes, its backslash escapes read, or (string-append
// ...) of literals. It fails on a literal longer than seatbeltStringMax,
// which sandbox-exec refuses, on a literal that does not end, and on a
// string-append holding anything but literals.
func readProfileStrings(text string) ([][]string, error) {
	literal := func(at int) (string, int, error) {
		var b strings.Builder
		for i := at + 1; i < len(text); i++ {
			switch text[i] {
			case '\\':
				i++
				if i == len(text) {
					return "", 0, errors.New("a literal ends in an escape")
				}
				b.WriteByte(text[i])
			case '"':
				if b.Len() > seatbeltStringMax {
					return "", 0, fmt.Errorf("a literal holds %d bytes, over %d", b.Len(), seatbeltStringMax)
				}
				return b.String(), i + 1, nil
			default:
				b.WriteByte(text[i])
			}
		}
		return "", 0, errors.New("a literal does not end")
	}
	const join = "(string-append"
	var values [][]string
	for i := 0; i < len(text); {
		switch {
		case text[i] == ';':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case text[i] == '"':
			piece, next, err := literal(i)
			if err != nil {
				return nil, err
			}
			values, i = append(values, []string{piece}), next
		case strings.HasPrefix(text[i:], join):
			var pieces []string
			for i += len(join); ; {
				if i < len(text) && text[i] == ' ' {
					i++
				}
				if i < len(text) && text[i] == ')' {
					i++
					break
				}
				if i >= len(text) || text[i] != '"' {
					return nil, fmt.Errorf("a string-append holds something other than a literal at byte %d", i)
				}
				piece, next, err := literal(i)
				if err != nil {
					return nil, err
				}
				pieces, i = append(pieces, piece), next
			}
			values = append(values, pieces)
		default:
			i++
		}
	}
	return values, nil
}

// FuzzSeatbeltString checks that any value without a control character is
// written as one string of the profile language that reads back as itself:
// one literal when it fits in one, and otherwise literals that each fit,
// none ending inside a character of a value that is valid UTF-8. The fuzzed
// input is checked alone and behind fillers that end shift bytes short of
// the first and of the second cut, so a cut falls inside the input at any
// offset while the input stays short, at most 64 bytes: the fuzzer then
// explores instead of spending its time shrinking inputs a kilobyte long.
func FuzzSeatbeltString(f *testing.F) {
	for _, seed := range []struct {
		input string
		shift uint8
	}{
		{"", 0}, {"/a", 1}, {`a"b`, 1}, {`a\b`, 1}, {`\"`, 0}, {`\"`, 1}, {`a\\`, 2}, {"/Users/op/My Files", 4},
		{"项目", 0}, {"项目", 1}, {"项目", 2}, {"项目", 3}, {"\x80\x80\x80\x80\x80", 2},
	} {
		f.Add(seed.input, seed.shift)
	}
	f.Fuzz(func(t *testing.T, input string, shift uint8) {
		// A cut falls in the input's first 32 bytes, so a longer input adds
		// nothing but bytes for the fuzzer to shrink.
		if strings.ContainsFunc(input, isControl) || len(input) > 64 {
			return
		}
		behind := func(cuts int) string {
			return strings.Repeat("a", cuts*seatbeltStringMax-int(shift%32)) + input
		}
		for _, value := range []string{input, behind(1), behind(2)} {
			quoted := sbString(value)
			values, err := readProfileStrings(quoted)
			if err != nil {
				t.Fatalf("sbString(%.80q) = %.80q does not read: %v", value, quoted, err)
			}
			if len(values) != 1 || strings.Join(values[0], "") != value {
				t.Fatalf("sbString(%.80q) = %.80q reads back as %.80q", value, quoted, values)
			}
			if fits := len(value) <= seatbeltStringMax; fits != strings.HasPrefix(quoted, `"`) || fits != (len(values[0]) == 1) {
				t.Fatalf("sbString(%.80q) = %.80q: a value of %d bytes is written in %d literals", value, quoted, len(value), len(values[0]))
			}
			if utf8.ValidString(value) {
				for _, piece := range values[0] {
					if !utf8.ValidString(piece) {
						t.Fatalf("sbString(%.80q) splits a character: %.80q", value, piece)
					}
				}
			}
		}
	})
}

// TestSeatbeltProfileSplitsALongPattern renders a writable grant whose path
// makes its protection patterns longer than one string literal holds, and
// checks that no literal in the profile is over the limit and that every
// pattern still reads back whole.
func TestSeatbeltProfileSplitsALongPattern(t *testing.T) {
	literalPaths(t)
	grant := "/Users/op/" + strings.Repeat("Customer Projects (2026)/", 12) + "app.v2"
	text, err := RenderSeatbelt(Profile{Home: "/Users/op", Reads: []string{grant}, Writes: []string{grant}}, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	values, err := readProfileStrings(text)
	if err != nil {
		t.Fatalf("the profile does not read: %v\n%s", err, text)
	}
	read, split := map[string]bool{}, 0
	for _, pieces := range values {
		read[strings.Join(pieces, "")] = true
		if len(pieces) > 1 {
			split++
		}
	}
	allowed, denied := gitPatterns(grant)
	pinned, allowedBack := bareRepoPins(grant)
	for _, pattern := range concat(protectedPatterns(grant), pinned, allowedBack, allowed, denied) {
		if !read[pattern] {
			t.Errorf("the pattern %q does not read back whole", pattern)
		}
	}
	if split == 0 || !strings.Contains(text, "(regex (string-append ") {
		t.Fatalf("no value over %d bytes was split, so this checks nothing:\n%s", seatbeltStringMax, text)
	}
}

// TestSeatbeltReadsAStringAtItsLimit loads, under the real Seatbelt,
// values around the longest literal sandbox-exec reads: one of exactly
// seatbeltStringMax bytes, which sbString writes as one literal, and longer
// ones it splits, one of them where a character straddles the limit. Should
// macOS's reader come to hold fewer bytes, this fails here rather than every
// stage whose grant has a long path.
func TestSeatbeltReadsAStringAtItsLimit(t *testing.T) {
	realSeatbelt(t)
	if quoted := sbString("/" + strings.Repeat("a", seatbeltStringMax-1)); strings.Contains(quoted, "string-append") {
		t.Fatalf("a value of exactly %d bytes was split", seatbeltStringMax)
	}
	for _, value := range []string{
		"/" + strings.Repeat("a", seatbeltStringMax-1),
		"/" + strings.Repeat("a", seatbeltStringMax),
		"/" + strings.Repeat("a", seatbeltStringMax-2) + "项目",
		"/" + strings.Repeat(`a\"`, seatbeltStringMax),
	} {
		profile := filepath.Join(t.TempDir(), "limit.sb")
		text := "(version 1)\n(allow default)\n(deny file-write*\n  (literal " + sbString(value) + "))\n"
		if err := os.WriteFile(profile, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command(sandboxExec, "-f", profile, "/usr/bin/true").CombinedOutput() //nolint:gosec,noctx // sandbox-exec over a profile this test wrote
		if err != nil {
			t.Errorf("a value of %d bytes did not load: %v\n%s", len(value), err, output)
		}
	}
}
