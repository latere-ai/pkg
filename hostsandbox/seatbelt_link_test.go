// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A grant must not widen through a symbolic link a stage leaves in place of
// a directory it may write, or a required program reached through one.

// fakeResolve makes canonical resolve each path through links, a path not
// listed resolving to itself.
func fakeResolve(t *testing.T, links map[string]string) {
	t.Helper()
	saved := evalSymlinks
	evalSymlinks = func(path string) (string, error) {
		if target, ok := links[path]; ok {
			return target, nil
		}
		return path, nil
	}
	t.Cleanup(func() { evalSymlinks = saved })
}

// TestAGrantKeepsOnlyResolutionsInsideItsTree checks which resolved
// spellings a grant keeps: its own tree, the same tree under /private for
// /tmp, /var and /etc, or deeper; never the home directory, the root, an
// ancestor or a sibling a link leads to. A denial keeps every spelling.
func TestAGrantKeepsOnlyResolutionsInsideItsTree(t *testing.T) {
	fakeResolve(t, map[string]string{
		"/tmp/stage":        "/private/tmp/stage",
		"/var/folders/x":    "/private/var/folders/x",
		"/data/w":           "/Users/op",
		"/data/root":        "/",
		"/data/a/b":         "/data/a",
		"/data/sibling":     "/data/other",
		"/data/deeper":      "/data/deeper/inside",
		"/tmp/escape":       "/private/var/elsewhere",
		"/Users/op/project": "/Volumes/work/project",
	})
	for given, want := range map[string][]string{
		"/tmp/stage":        {"/tmp/stage", "/private/tmp/stage"},
		"/var/folders/x":    {"/var/folders/x", "/private/var/folders/x"},
		"/data/deeper":      {"/data/deeper", "/data/deeper/inside"},
		"/data/w":           {"/data/w"},
		"/data/root":        {"/data/root"},
		"/data/a/b":         {"/data/a/b"},
		"/data/sibling":     {"/data/sibling"},
		"/tmp/escape":       {"/tmp/escape"},
		"/Users/op/project": {"/Users/op/project"},
	} {
		if got := allowSpellings(given); !slices.Equal(got, want) {
			t.Errorf("allowSpellings(%s) = %q, want %q", given, got, want)
		}
	}
	text, err := RenderSeatbelt(Profile{Home: "/Users/op", Writes: []string{"/data/w"}, Denies: []string{"/data/w"}}, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	if position(text, "allow", "file-write*", "subpath", "/Users/op") >= 0 {
		t.Fatalf("a grant that is a link to the home directory granted the home directory:\n%s", text)
	}
	if position(text, "deny", "file-read*", "subpath", "/Users/op") < 0 {
		t.Fatalf("a denial lost its resolved spelling:\n%s", text)
	}
}

// TestAWritableGrantThatIsALinkIsRefused checks that a writable grant whose
// own path is a symbolic link is refused, where it does not resolve inside
// its tree as much as where it does: the link is what a stage leaves in
// place of the directory it was granted.
func TestAWritableGrantThatIsALinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "grant")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderSeatbelt(Profile{Writes: []string{link}}, 0); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a writable grant that is a link = %v, want it refused", err)
	}
	if _, err := RenderSeatbelt(Profile{Reads: []string{link}, Writes: []string{target}}, 0); err != nil {
		t.Fatalf("a read grant that is a link, or a writable real directory, was refused: %v", err)
	}
}

// TestASwappedGrantGrantsNothing runs the attack under the real Seatbelt: a
// stage replaces the directory it may write with a link to the home
// directory, and the next stage over the same grants is refused, or reads
// nothing through the link.
func TestASwappedGrantGrantsNothing(t *testing.T) {
	driver, home := realSeatbelt(t)
	secret := filepath.Join(home, ".config", "latere", "auth-token.json")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("the operator's token"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	grant := filepath.Join(data, "workspace")
	inner := filepath.Join(grant, "inner")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	spec := func(paths []Path, argv ...string) StageSpec {
		return StageSpec{Name: "swap", Argv: argv, Workdir: data, Paths: paths, Network: Network{Mode: NetworkNone}}
	}
	writable := []Path{{Host: grant, Access: ReadWrite}}

	// A read grant inside the writable one, swapped for a link home.
	swapInner := "rm -rf " + ShellQuote(inner) + " && ln -s " + ShellQuote(home) + " " + ShellQuote(inner)
	if output, err := attached(t, driver, spec(writable, "/bin/sh", "-c", swapInner)); err != nil {
		t.Fatalf("the first stage could not swap its own directory: %q, %v", output, err)
	}
	readOnly := []Path{{Host: inner, Access: ReadOnly}}
	if output, err := attached(t, driver, spec(readOnly, "/bin/cat", filepath.Join(inner, ".config", "latere", "auth-token.json"))); err == nil || strings.Contains(output, "the operator's token") {
		t.Fatalf("the next stage read the home directory through a swapped read grant: %q, %v", output, err)
	}

	// The writable grant itself, swapped for a link home.
	swapGrant := "cd / && rm -rf " + ShellQuote(grant) + " && ln -s " + ShellQuote(home) + " " + ShellQuote(grant)
	if output, err := attached(t, driver, spec(writable, "/bin/sh", "-c", swapGrant)); err != nil {
		t.Fatalf("the first stage could not swap its grant: %q, %v", output, err)
	}
	if _, _, err := driver.Command(context.Background(), spec(writable, "/bin/sh", "-c", "echo planted > "+ShellQuote(filepath.Join(grant, "planted")))); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("the next stage over a swapped writable grant = %v, want it refused", err)
	}
	if _, err := os.Stat(filepath.Join(home, "planted")); err == nil {
		t.Fatal("a stage wrote into the home directory through a swapped grant")
	}
}

// TestProfileNeverGrantsTheHomeThroughARequiredProgram checks that the
// directory of a required program is granted only when it is not the root
// and does not hold the home directory, as it would through a link a stage
// planted for the program.
func TestProfileNeverGrantsTheHomeThroughARequiredProgram(t *testing.T) {
	for resolved, granted := range map[string]bool{
		"/Users/op/tool":         false,
		"/tool":                  false,
		"/Users/tool":            false,
		"/Users/op/bin/tool":     true,
		"/opt/homebrew/bin/tool": true,
	} {
		driver := New(Config{Isolation: IsolationSRT, Home: "/Users/op", Requires: []string{"tool"},
			Look: func(string) (string, error) { return resolved, nil }})
		reads := driver.Profile(StageSpec{}).Reads
		if got := slices.Contains(reads, filepath.Dir(resolved)); got != granted {
			t.Errorf("a program at %s: its directory granted = %v, want %v (reads %q)", resolved, got, granted, reads)
		}
	}
}
