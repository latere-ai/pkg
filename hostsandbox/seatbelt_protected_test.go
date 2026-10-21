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
		".git/refs/heads/.git/config", ".git/refs/heads/.git/hooks/pre-commit", ".git/objects/.git/hooks/pre-commit",
		".git/refs/heads/.gitconfig", ".git/logs/.claude/settings.json", "origin.git/refs/.claude/settings.json",
		".git/refs/heads/sub/.vscode/settings.json", ".git/modules/a/b/config", ".git/modules/a/b/hooks/pre-commit",
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
		".git/sharedindex.0e2f", ".git/modules/a/b/refs/heads/main", ".git/modules/a/b/objects/ab/cd", ".git/modules/a/b/HEAD",
		".git/refs/heads/feature/my.git.work", ".git/refs/tags/v1.2.3",
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

// longGrant makes a writable grant below parent whose escaped path alone is
// longer than one string literal of the profile language holds, so every
// protection pattern of it, the shortest included, is split, and the first
// cut of each falls inside the path, between the backslash and the dot of an
// escaped "." in its last name. It also makes sibling, a directory whose path
// differs from the grant's by that dot alone. The grant's names hold dots,
// parentheses and a plus, which the patterns escape, and, well before the
// cut, characters beyond ASCII; the names repeat as often as parent's length
// leaves room for, and the whole stays short enough that macOS opens every
// file a test writes in it.
func longGrant(t *testing.T, parent string) (grant, sibling string) {
	t.Helper()
	const segment = "v1.2+(rc.3)"
	path := filepath.Join(parent, "项目文档 (第二阶段)")
	// A pattern is "^" and then the escaped path, and its first piece is its
	// first seatbeltStringMax bytes, so the dot's backslash is that piece's
	// last byte when the escaped path before it is this long.
	before := seatbeltStringMax - 2
	for len(regexLiteral(path))+len("/"+regexLiteral(segment)) < before-16 {
		path += "/" + segment
	}
	pad := before - len(regexLiteral(path)) - len("/")
	if pad < 1 {
		t.Fatalf("the temporary directory %s leaves no room below the limit for a grant to cross it", parent)
	}
	name := strings.Repeat("x", pad)
	grant, sibling = path+"/"+name+".cut", path+"/"+name+"_cut"
	if len(grant)+64 > seatbeltStringMax {
		t.Fatalf("the grant is %d bytes, too long for macOS to open the files a test writes in it", len(grant))
	}
	allowed, denied := gitPatterns(grant)
	for _, pattern := range concat(protectedPatterns(grant), allowed, denied) {
		values, err := readProfileStrings(sbString(pattern))
		if err != nil || len(values) != 1 || len(values[0]) < 2 ||
			!strings.HasSuffix(values[0][0], `\`) || !strings.HasPrefix(values[0][1], ".cut") {
			t.Fatalf("the pattern %.120q... of %d bytes is not cut inside the grant's escaped dot: %v", pattern, len(pattern), err)
		}
	}
	for _, dir := range []string{grant, filepath.Join(sibling, ".git", "refs", "heads")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return grant, sibling
}

// stageWrite appends a line to path, making its directory first, from a
// stage whose one writable grant is grant, and returns the stage's error.
func stageWrite(t *testing.T, driver *Driver, grant, path string) error {
	t.Helper()
	_, err := attached(t, driver, StageSpec{
		Name: "protected", Workdir: grant, Network: Network{Mode: NetworkNone},
		Argv:  []string{"/bin/sh", "-c", "mkdir -p " + ShellQuote(filepath.Dir(path)) + " && echo planted >> " + ShellQuote(path)},
		Paths: []Path{{Host: grant, Access: ReadWrite}},
	})
	return err
}

// TestAStageCannotWriteWhatRunsCodeLater writes, under the real Seatbelt,
// each kind of file a shell, direnv, git, an editor or an agent acts on,
// inside a writable grant, an agent's settings among them while its
// directory exists, and a name in .git nobody listed, and checks that none
// is written while an ordinary file and git's objects, refs, HEAD and index
// are, and that the protected files stay readable. It does so in a grant
// with a short path, and in one whose every pattern the profile writes split
// inside the grant's path, where the denials must still deny and the
// allowances allow; there it also writes the files git's allowances allow
// in a sibling that differs from the grant by the byte at the cut alone, and
// checks none is written, so a split allowance matches no more than whole.
func TestAStageCannotWriteWhatRunsCodeLater(t *testing.T) {
	driver, _ := realSeatbelt(t)
	short, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	long, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("a short path", func(t *testing.T) { cannotWriteWhatRunsCodeLater(t, driver, short) })
	t.Run("a long path", func(t *testing.T) {
		grant, sibling := longGrant(t, long)
		cannotWriteWhatRunsCodeLater(t, driver, grant)
		for _, relative := range []string{".git/HEAD", ".git/index", ".git/refs/heads/main", "notes.txt"} {
			path := filepath.Join(sibling, relative)
			if err := stageWrite(t, driver, grant, path); err == nil {
				t.Errorf("%s, in the sibling beside the grant, was written", relative)
			}
			if _, err := os.Stat(path); err == nil {
				t.Errorf("%s, in the sibling beside the grant, exists", relative)
			}
		}
	})
}

// cannotWriteWhatRunsCodeLater is TestAStageCannotWriteWhatRunsCodeLater in
// the writable grant repo.
func cannotWriteWhatRunsCodeLater(t *testing.T, driver *Driver, repo string) {
	for _, dir := range []string{".git/hooks", ".git/objects/info", ".claude", "sub"} {
		if err := os.MkdirAll(filepath.Join(repo, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(relative string) error { return stageWrite(t, driver, repo, filepath.Join(repo, relative)) }
	for _, relative := range []string{
		".git/hooks/pre-commit", ".git/config", ".zshrc", ".ZSHRC", "sub/.gitconfig", ".bashrc",
		".vscode/settings.json", ".claude/commands/run.md", ".claude/settings.json", ".claude/settings.local.json",
		".cursor/mcp.json", ".mcp.json", ".envrc", "team.code-workspace", ".git/newcontrol", ".git/info/exclude",
		".git/objects/info/alternates", ".git/objects/info/http-alternates",
		".git/refs/heads/.git/config", ".git/refs/heads/.git/hooks/pre-commit", ".git/objects/.git/hooks/pre-commit",
		".git/refs/heads/.gitconfig", ".git/logs/.claude/settings.json",
	} {
		if err := write(relative); err == nil {
			t.Errorf("%s was written", relative)
		}
	}
	if body, err := os.ReadFile(filepath.Join(repo, ".git", "config")); err != nil || string(body) != "[core]\n" {
		t.Errorf(".git/config changed: %q, %v", body, err)
	}
	for _, relative := range []string{
		"notes.txt", ".git/objects/ab", ".git/objects/info/commit-graph", ".git/refs/heads/main", ".git/refs/tags/v1.2.3",
		".git/HEAD", ".git/index", "sub/main.go",
	} {
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
