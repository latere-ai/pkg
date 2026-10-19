// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// A stage must not write, inside a writable grant, what a shell, git or an
// editor's agent acts on once the operator runs it.

// writableIn reports whether a stage may write path inside the writable
// grant, deciding as Seatbelt does from the rules RenderSeatbelt writes in
// that order, the last that matches deciding: the grant allows, the
// protection denies, git's allow-backs allow, their exceptions deny.
func writableIn(grant, path string) bool {
	compile := func(patterns []string) []*regexp.Regexp {
		out := make([]*regexp.Regexp, len(patterns))
		for i, pattern := range patterns {
			out[i] = regexp.MustCompile(pattern)
		}
		return out
	}
	matches := func(rules []*regexp.Regexp) bool {
		return slices.ContainsFunc(rules, func(r *regexp.Regexp) bool { return r.MatchString(path) })
	}
	allowed, denied := gitPatterns(grant)
	writable := path == grant || strings.HasPrefix(path, grant+"/")
	for _, step := range []struct {
		rules []*regexp.Regexp
		allow bool
	}{{compile(protectedPatterns(grant)), false}, {compile(allowed), true}, {compile(denied), false}} {
		if matches(step.rules) {
			writable = step.allow
		}
	}
	return writable
}

// TestTheProtectionDecidesAsSeatbeltDoes checks what a stage may write in a
// grant, under the rules in their order: shell, direnv, git, editor and
// agent files and trees denied at any depth and in any case; every gitdir
// denied but for what everyday git writes, so commondir, gitdir, info and a
// name nobody listed stay denied; and nothing beside the grant matched.
func TestTheProtectionDecidesAsSeatbeltDoes(t *testing.T) {
	grant := "/data/my.repo+(1)"
	for _, relative := range []string{
		".zshrc", "deep/er/.ZshRC", ".bash_profile", ".envrc", "sub/.ENVRC", "team.code-workspace", "a/b/X.CODE-WORKSPACE",
		".gitconfig", "sub/.gitmodules", ".mcp.json", ".ripgreprc",
		".claude", ".claude/settings.json", ".claude/settings.local.json", ".claude/commands/run.md", ".cursor", ".cursor/mcp.json",
		".vscode", ".vscode/settings.json", ".idea/workspace.xml",
		".git", "sub/.git", ".GIT/CONFIG", ".git/config", ".git/config.worktree", ".git/hooks", ".git/hooks/pre-commit",
		".git/commondir", ".git/info/exclude", ".git/description", ".git/newcontrol", ".git/objects/info/alternates",
		".git/objects/info/http-alternates", ".git/modules", ".git/modules/sub", ".git/modules/sub/config", ".git/modules/sub/commondir",
		".git/modules/a/modules/b/hooks/post-checkout", ".git/worktrees", ".git/worktrees/wt", ".git/worktrees/wt/commondir",
		".git/worktrees/wt/gitdir", ".git/worktrees/wt/config.worktree", ".git/worktrees/wt/locked",
		"origin.git/config", "origin.git/hooks/post-receive", "origin.git/commondir", "sub/bare.GIT/hooks/update",
	} {
		if writableIn(grant, grant+"/"+relative) {
			t.Errorf("%s is writable", relative)
		}
	}
	for _, relative := range []string{
		"notes.txt", ".gitignore", "sub/.gitattributes", ".github/workflows/ci.yml", ".gitx", "x.git", "code-workspace.md",
		".git/objects/ab/cd", ".git/objects/pack/p.pack", ".git/objects/info/commit-graph", ".git/refs/heads/config",
		".git/refs/heads/hooks", ".git/refs/stash", ".git/logs/HEAD", ".git/HEAD", ".git/HEAD.lock", ".git/index", ".git/index.lock",
		".git/packed-refs", ".git/packed-refs.lock", ".git/ORIG_HEAD", ".git/FETCH_HEAD", ".git/MERGE_HEAD", ".git/MERGE_MSG",
		".git/AUTO_MERGE", ".git/CHERRY_PICK_HEAD", ".git/REBASE_HEAD", ".git/COMMIT_EDITMSG", ".git/TAG_EDITMSG", ".git/BISECT_LOG",
		".git/rebase-merge/git-rebase-todo", ".git/sequencer/todo", ".git/gc.pid", ".git/shallow.lock",
		".git/modules/sub/objects/ab/cd", ".git/modules/sub/HEAD", ".git/worktrees/wt/HEAD", ".git/worktrees/wt/index",
		".git/worktrees/wt/logs/HEAD", ".git/modules/a/modules/b/refs/heads/main",
		"origin.git/objects/pack/p.pack", "origin.git/refs/heads/main", "origin.git/packed-refs", "origin.git/HEAD",
		"x.git", ".gitx", "my.github/workflows/ci.yml",
	} {
		if !writableIn(grant, grant+"/"+relative) {
			t.Errorf("%s, which everyday work writes, is not writable", relative)
		}
	}
	for _, pattern := range protectedPatterns(grant) {
		for _, beside := range []string{"/data/my.repo+(1)x/.zshrc", "/data/myXrepo+(1)/.git/config", "/data/.claude/settings.json"} {
			if regexp.MustCompile(pattern).MatchString(beside) {
				t.Errorf("%s, beside the grant, matches %s", beside, pattern)
			}
		}
	}
}

// TestAStageCannotWriteWhatRunsCodeLater writes, under the real Seatbelt,
// each kind of file a shell, direnv, git, an editor or an agent acts on,
// inside a writable grant, an agent's settings among them while its
// directory exists, and a name in .git nobody listed, and checks that none
// is written while an ordinary file and git's objects and refs are, and that
// the protected files stay readable.
func TestAStageCannotWriteWhatRunsCodeLater(t *testing.T) {
	driver, _ := realSeatbelt(t)
	repo, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".git/hooks", ".git/objects/info", ".claude", "sub"} {
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
		".vscode/settings.json", ".claude/commands/run.md", ".claude/settings.json", ".claude/settings.local.json",
		".cursor/mcp.json", ".mcp.json", ".envrc", "team.code-workspace", ".git/newcontrol", ".git/info/exclude",
		".git/objects/info/alternates", ".git/objects/info/http-alternates",
	} {
		if err := write(relative); err == nil {
			t.Errorf("%s was written", relative)
		}
	}
	if body, err := os.ReadFile(filepath.Join(repo, ".git", "config")); err != nil || string(body) != "[core]\n" {
		t.Errorf(".git/config changed: %q, %v", body, err)
	}
	for _, relative := range []string{"notes.txt", ".git/objects/ab", ".git/objects/info/commit-graph", ".git/refs/heads/main", "sub/main.go"} {
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
