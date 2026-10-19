// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// literalPaths makes canonical return every path as written, so a rendering
// test reads the same on every machine.
func literalPaths(t *testing.T) {
	t.Helper()
	saved := evalSymlinks
	evalSymlinks = func(path string) (string, error) { return path, nil }
	t.Cleanup(func() { evalSymlinks = saved })
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
// as given and resolved, because Seatbelt matches the resolved path, and
// that a path not created yet resolves through its deepest existing parent.
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
	got := canonical(filepath.Join(link, "later", "file"))
	want := filepath.Join(resolvedReal, "later", "file")
	if len(got) != 2 || got[0] != filepath.Join(link, "later", "file") || got[1] != want {
		t.Fatalf("canonical = %q, want the path as given and %q", got, want)
	}
	if got := canonical("/"); len(got) != 1 || got[0] != "/" {
		t.Fatalf("canonical(/) = %q", got)
	}
	saved := evalSymlinks
	evalSymlinks = func(string) (string, error) { return "", errors.New("nothing resolves") }
	t.Cleanup(func() { evalSymlinks = saved })
	if got := canonical("/a/b"); len(got) != 1 || got[0] != "/a/b" {
		t.Fatalf("canonical with nothing resolving = %q, want the path as given", got)
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

// FuzzSeatbeltString checks that any value without a control character is
// written as one string of the profile language that reads back as itself.
func FuzzSeatbeltString(f *testing.F) {
	for _, seed := range []string{"", "/a", `a"b`, `a\b`, `\"`, "/Users/op/My Files"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if strings.ContainsFunc(value, isControl) {
			return
		}
		quoted := sbString(value)
		if !strings.HasPrefix(quoted, `"`) || !strings.HasSuffix(quoted, `"`) || len(quoted) < 2 {
			t.Fatalf("sbString(%q) = %q", value, quoted)
		}
		var b strings.Builder
		inner := quoted[1 : len(quoted)-1]
		for i := 0; i < len(inner); i++ {
			switch inner[i] {
			case '\\':
				i++
				if i == len(inner) {
					t.Fatalf("sbString(%q) = %q ends in an escape", value, quoted)
				}
				b.WriteByte(inner[i])
			case '"':
				t.Fatalf("sbString(%q) = %q holds an unescaped quote", value, quoted)
			default:
				b.WriteByte(inner[i])
			}
		}
		if b.String() != value {
			t.Fatalf("sbString(%q) reads back as %q", value, b.String())
		}
	})
}
