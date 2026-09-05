// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package relpath

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestClean(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"a/b", "a/b", true},
		{"a/./b", "a/b", true},
		{"a/../b", "b", true},
		{"..foo", "..foo", true},
		{".", ".", true},
		{"a/", "a", true},
		{"", "", false},
		{"a\x00b", "", false},
		{"/a", "", false},
		{"..", "", false},
		{"../a", "", false},
		{"a/../..", "", false},
		{"a/../../b", "", false},
	}
	for _, c := range cases {
		got, err := Clean(c.in)
		if (err == nil) != c.ok {
			t.Errorf("Clean(%q) err = %v, want ok=%v", c.in, err, c.ok)
			continue
		}
		if got != c.want {
			t.Errorf("Clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func FuzzClean(f *testing.F) {
	for _, s := range []string{"a/b", "../a", "a/../..", "/x", "..foo", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := Clean(in)
		if err != nil {
			return
		}
		if !filepath.IsLocal(filepath.FromSlash(got)) {
			t.Fatalf("Clean(%q) = %q, which filepath.IsLocal rejects", in, got)
		}
		if _, err := Join(t.TempDir(), filepath.FromSlash(got)); err != nil {
			t.Fatalf("Join rejected Clean's output %q: %v", got, err)
		}
	})
}

func TestJoin(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "base")
	cases := []struct {
		rel  string
		want string
		ok   bool
	}{
		{"a", filepath.Join(base, "a"), true},
		{".", base, true},
		{"", base, true},
		{"a/../b", filepath.Join(base, "b"), true},
		{"..", "", false},
		{"../x", "", false},
		{"a/../../x", "", false},
	}
	for _, c := range cases {
		got, err := Join(base, filepath.FromSlash(c.rel))
		if (err == nil) != c.ok {
			t.Errorf("Join(%q) err = %v, want ok=%v", c.rel, err, c.ok)
			continue
		}
		if got != c.want {
			t.Errorf("Join(%q) = %q, want %q", c.rel, got, c.want)
		}
	}
}

func TestJoinCleansBase(t *testing.T) {
	got, err := Join("/base/", "a")
	if err != nil || got != filepath.Clean("/base/a") {
		t.Fatalf("Join(/base/, a) = %q, %v", got, err)
	}
	if _, err := Join("/base/", "../x"); err == nil {
		t.Fatal("escape through an unclean base was accepted")
	}
}

func TestContains(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink layout is unix-specific")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	outside := filepath.Join(dir, "outside")
	for _, d := range []string{root, outside, filepath.Join(root, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// rootlink -> root, escape -> outside (inside root), and a file link.
	rootlink := filepath.Join(dir, "rootlink")
	if err := os.Symlink(root, rootlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		root, target string
		want         bool
	}{
		{root, root, true},
		{root, filepath.Join(root, "sub"), true},
		{root, filepath.Join(root, "file"), true},
		{root, filepath.Join(root, "sub", "new-file"), true},
		{root, filepath.Join(root, "new", "deep", "file"), true},
		{root, filepath.Join(root, "file", "under-a-file"), true},
		{root, outside, false},
		{root, dir, false},
		{root, filepath.Join(root, "..", "outside"), false},
		{root, filepath.Join(root, "escape"), false},
		{root, filepath.Join(root, "escape", "new-file"), false},
		{root, root + "-sibling", false},
		{rootlink, filepath.Join(root, "sub"), true},
		{root, filepath.Join(rootlink, "sub"), true},
		{rootlink, filepath.Join(rootlink, "escape"), false},
	}
	for _, c := range cases {
		got, err := Contains(c.root, c.target)
		if err != nil {
			t.Errorf("Contains(%q, %q): %v", c.root, c.target, err)
			continue
		}
		if got != c.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", c.root, c.target, got, c.want)
		}
	}
}

func TestContainsRelativeArguments(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("root", 0o755); err != nil {
		t.Fatal(err)
	}
	ok, err := Contains("root", filepath.Join("root", "x"))
	if err != nil || !ok {
		t.Fatalf("Contains(root, root/x) = %v, %v", ok, err)
	}
	ok, err = Contains("root", "elsewhere")
	if err != nil || ok {
		t.Fatalf("Contains(root, elsewhere) = %v, %v", ok, err)
	}
}

func TestContainsMissingRootIsAnError(t *testing.T) {
	if _, err := Contains(filepath.Join(t.TempDir(), "missing"), "x"); err == nil {
		t.Fatal("missing root was accepted")
	}
}

func TestContainsUnreadableTargetIsAnError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a permission failure that root does not get")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := Contains(dir, filepath.Join(locked, "inner", "file")); err == nil {
		t.Fatal("permission error was swallowed")
	}
}

func TestJoinRootBases(t *testing.T) {
	for _, base := range []string{".", "", string(filepath.Separator)} {
		t.Run(base, func(t *testing.T) {
			got, err := Join(base, "child")
			if want := filepath.Join(base, "child"); err != nil || got != want {
				t.Fatalf("Join(%q, child) = %q, %v; want %q", base, got, err, want)
			}
		})
	}
	for _, base := range []string{".", ""} {
		if _, err := Join(base, "../outside"); err == nil {
			t.Fatalf("Join(%q, ../outside) accepted escape", base)
		}
	}
}

func TestContainsFilesystemRoot(t *testing.T) {
	target := t.TempDir()
	root := filepath.VolumeName(target) + string(filepath.Separator)
	if got, err := Contains(root, target); err != nil || !got {
		t.Fatalf("Contains(%q, %q) = %v, %v; want true", root, target, got, err)
	}
}

func TestContainsDanglingSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []bool{false, true} {
		name := "absolute"
		linkTarget := filepath.Join(dir, "outside")
		if relative {
			name = "relative"
			linkTarget = "../outside"
		}
		t.Run(name, func(t *testing.T) {
			link := filepath.Join(root, name)
			if err := os.Symlink(linkTarget, link); err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{link, filepath.Join(link, "child")} {
				if inside, err := Contains(root, target); err == nil && inside {
					t.Fatalf("Contains accepted dangling escape %q", target)
				}
			}
		})
	}
}
