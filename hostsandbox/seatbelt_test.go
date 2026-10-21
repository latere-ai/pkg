// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
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
	if strings.Contains(text, "file-write-unlink") {
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
	for _, pattern := range concat(protectedPatterns(grant), allowed, denied) {
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
