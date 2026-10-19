// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// A stage must not write, inside a writable grant, what a shell, git or an
// editor's agent acts on once the operator runs it.

// TestProtectedPatternsMatchAnyCaseAtAnyDepth checks the patterns that keep
// a stage from writing what runs code later: each protected name at any
// depth below the grant and in any case, a protected directory's contents,
// nothing that only resembles a name, and nothing beside the grant.
func TestProtectedPatternsMatchAnyCaseAtAnyDepth(t *testing.T) {
	grant := "/data/my.repo+(1)"
	var compiled []*regexp.Regexp
	for _, pattern := range protectedPatterns(grant) {
		compiled = append(compiled, regexp.MustCompile(pattern))
	}
	matches := func(path string) bool {
		return slices.ContainsFunc(compiled, func(r *regexp.Regexp) bool { return r.MatchString(path) })
	}
	for _, path := range []string{
		grant + "/.zshrc", grant + "/deep/er/.ZshRC", grant + "/.gitconfig", grant + "/sub/.gitmodules",
		grant + "/.git/config", grant + "/vendor/x/.git/config", grant + "/.git/hooks", grant + "/.git/hooks/pre-commit",
		grant + "/.GIT/Hooks/post-checkout", grant + "/.vscode/settings.json", grant + "/.idea/workspace.xml",
		grant + "/.claude/commands/run.md", grant + "/.claude/agents/a.md", grant + "/.mcp.json", grant + "/.bash_profile",
		grant + "/.git", grant + "/sub/.GIT", grant + "/.claude", grant + "/.git/config.worktree",
		grant + "/.git/modules", grant + "/.git/modules/sub", grant + "/.git/modules/sub/config", grant + "/.git/modules/sub/hooks/pre-commit",
		grant + "/.git/modules/a/modules/b/config", grant + "/.git/modules/a/modules/b", grant + "/.git/worktrees", grant + "/.git/worktrees/w",
		grant + "/.git/worktrees/w/config.worktree", grant + "/.git/worktrees/w/hooks/post-checkout",
	} {
		if !matches(path) {
			t.Errorf("%s is writable", path)
		}
	}
	for _, path := range []string{
		grant + "/notes.zshrc", grant + "/.git/objects/ab/cd", grant + "/.git/hooksx", grant + "/.git/configs",
		grant + "/.claude/settings.json", "/data/my.repo+(1)x/.zshrc", "/data/myXrepo+(1)/.zshrc", "/data/.zshrc", grant,
		grant + "/.git/refs/heads/config", grant + "/.git/refs/heads/hooks", grant + "/.git/refs/heads/modules", grant + "/.git/HEAD",
		grant + "/.git/index", grant + "/.git/modules/sub/objects/ab/cd", grant + "/.gitx", grant + "/x.git",
	} {
		if matches(path) {
			t.Errorf("%s is protected, though it is not on the list or not in the grant", path)
		}
	}
}

// TestAStageCannotWriteWhatRunsCodeLater writes, under the real Seatbelt,
// each kind of file a shell, git or an editor's agent acts on, inside a
// writable grant, and checks that none is written while an ordinary file
// and git's objects are, and that the protected files stay readable.
func TestAStageCannotWriteWhatRunsCodeLater(t *testing.T) {
	driver, _ := realSeatbelt(t)
	repo, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".git/hooks", ".git/objects", "sub"} {
		if err := os.MkdirAll(filepath.Join(repo, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(relative string) error {
		path := filepath.Join(repo, relative)
		_, err := attached(t, driver, StageSpec{
			Name: "protected", Workdir: repo, Network: Network{Mode: NetworkNone},
			Argv:  []string{"/bin/sh", "-c", "mkdir -p " + ShellQuote(filepath.Dir(path)) + " && echo planted >> " + ShellQuote(path)},
			Paths: []Path{{Host: repo, Access: ReadWrite}},
		})
		return err
	}
	for _, relative := range []string{
		".git/hooks/pre-commit", ".git/config", ".zshrc", ".ZSHRC", "sub/.gitconfig", ".bashrc",
		".vscode/settings.json", ".claude/commands/run.md", ".mcp.json",
	} {
		if err := write(relative); err == nil {
			t.Errorf("%s was written", relative)
		}
	}
	if body, err := os.ReadFile(filepath.Join(repo, ".git", "config")); err != nil || string(body) != "[core]\n" {
		t.Errorf(".git/config changed: %q, %v", body, err)
	}
	for _, relative := range []string{"notes.txt", ".git/objects/ab", "sub/main.go"} {
		if err := write(relative); err != nil {
			t.Errorf("%s, an ordinary file, could not be written: %v", relative, err)
		}
	}
	if output, err := attached(t, driver, StageSpec{
		Name: "protected", Workdir: repo, Network: Network{Mode: NetworkNone},
		Argv: []string{"/bin/cat", filepath.Join(repo, ".git", "config")}, Paths: []Path{{Host: repo, Access: ReadWrite}},
	}); err != nil || output != "[core]\n" {
		t.Errorf("a protected file is not readable: %q, %v", output, err)
	}
}
