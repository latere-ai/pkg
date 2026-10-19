// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The protection of what runs code later must survive a rename: a stage that
// moves a protected directory away, writes into it under another name and
// moves it back, or moves its own directory into a protected name, or points
// git at a gitdir of its own, writes nothing git or an agent will act on.

// protectedRepo lays out, inside a fresh writable grant, a repository with
// git's config and hooks, a submodule's and a worktree's gitdirs, and an
// agent's and editors' settings, and returns the grant.
func protectedRepo(t *testing.T) string {
	t.Helper()
	grant, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{
		"repo/.git/hooks", "repo/.git/objects", "repo/.git/refs/heads",
		"repo/.git/modules/sub/hooks", "repo/.git/worktrees/wt",
		"repo/sub", "repo/plain",
		"repo/.claude/commands", "repo/.claude/agents", "repo/.vscode", "repo/.idea",
	} {
		if err := os.MkdirAll(filepath.Join(grant, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range map[string]string{
		"repo/.git/config":                 "[core]\n",
		"repo/.git/modules/sub/config":     "[core]\n",
		"repo/.git/worktrees/wt/commondir": "../..\n",
		"repo/sub/.git":                    "gitdir: ../.git/modules/sub\n",
	} {
		if err := os.WriteFile(filepath.Join(grant, path), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return grant
}

// inGrant runs a shell script under the real Seatbelt with grant writable
// and returns its combined output and error.
func inGrant(t *testing.T, driver *Driver, grant, script string) (string, error) {
	t.Helper()
	return attached(t, driver, StageSpec{
		Name: "rename", Argv: []string{"/bin/sh", "-c", script}, Workdir: filepath.Join(grant, "repo"),
		Paths: []Path{{Host: grant, Access: ReadWrite}}, Network: Network{Mode: NetworkNone},
	})
}

// TestAProtectedDirectoryCannotBeMovedAwayOrIntoPlace runs each rename the
// review reproduced, and its kin, under the real Seatbelt, and checks that
// each is refused and that nothing git or an agent reads has changed.
func TestAProtectedDirectoryCannotBeMovedAwayOrIntoPlace(t *testing.T) {
	driver, _ := realSeatbelt(t)
	grant := protectedRepo(t)
	for name, script := range map[string]string{
		"git's directory moved away and back":      `mv .git dotgit && echo '[core] hooksPath=` + grant + `/evilhooks' >> dotgit/config && mv dotgit .git`,
		"an agent's directory moved away and back": `mv .claude .c && echo x > .c/commands/evil.md && mv .c .claude`,
		"git's hooks moved away":                   `mv .git/hooks .git/h`,
		"an agent's commands moved away":           `mv .claude/commands .claude/c`,
		"an agent's agents moved away":             `mv .claude/agents .claude/a`,
		"an editor's settings moved away":          `mv .vscode .v`,
		"another editor's settings moved away":     `mv .idea .i`,
		"a directory moved in as git's":            `mkdir -p ../fake && echo '[core]' > ../fake/config && mv ../fake plain/.git`,
		"a directory moved in as hooks":            `mkdir h2 && echo evil > h2/pre-commit && rm -rf .git/hooks; mv h2 .git/hooks`,
		"a .git file pointing elsewhere":           `echo 'gitdir: ../evil' > plain/.git`,
		"a .git directory where none was":          `mkdir plain/.git`,
		"a submodule's config":                     `echo '[core] hooksPath=/x' >> .git/modules/sub/config`,
		"a submodule's hook":                       `echo evil > .git/modules/sub/hooks/pre-commit`,
		"a worktree's config":                      `echo '[core] hooksPath=/x' > .git/worktrees/wt/config.worktree`,
		"a submodule's .git file replaced":         `echo 'gitdir: ../evil' > sub/.git`,
		"a submodule's gitdir moved out and back":  `mv .git/modules/sub ../s && echo '[core] hooksPath=/x' >> ../s/config && mv ../s .git/modules/sub`,
		"git's modules moved out":                  `mv .git/modules ../m`,
		"a gitdir moved within git's directory":    `mv .git/modules/sub .git/sub`,
		"a worktree's gitdir moved out":            `mv .git/worktrees/wt ../w`,
		"git's config hard-linked to another name": `ln .git/config writable && echo '[core] hooksPath=/x' >> writable`,
	} {
		if output, err := inGrant(t, driver, grant, script); err == nil {
			t.Errorf("%s succeeded: %q", name, output)
		}
	}
	for path, want := range map[string]string{
		"repo/.git/config":             "[core]\n",
		"repo/.git/modules/sub/config": "[core]\n",
		"repo/sub/.git":                "gitdir: ../.git/modules/sub\n",
	} {
		if body, err := os.ReadFile(filepath.Join(grant, path)); err != nil || string(body) != want {
			t.Errorf("%s = %q, %v; want it unchanged", path, body, err)
		}
	}
	for _, path := range []string{"repo/.git/hooks", "repo/.claude/commands", "repo/.vscode", "repo/.idea"} {
		if info, err := os.Stat(filepath.Join(grant, path)); err != nil || !info.IsDir() {
			t.Errorf("%s was moved away: %v", path, err)
		}
	}
	for _, path := range []string{"repo/plain/.git", "repo/.claude/commands/evil.md", "repo/.git/modules/sub/hooks/pre-commit", "repo/.git/worktrees/wt/config.worktree", "evilhooks"} {
		if _, err := os.Lstat(filepath.Join(grant, path)); err == nil {
			t.Errorf("%s was created", path)
		}
	}
}

// TestRenamingARepositoryKeepsItsProtection moves the directory holding a
// repository, which is ordinary work, and checks that its git directory is
// protected under the new name, since the protection follows the name .git.
func TestRenamingARepositoryKeepsItsProtection(t *testing.T) {
	driver, _ := realSeatbelt(t)
	grant := protectedRepo(t)
	if output, err := inGrant(t, driver, grant, "cd .. && mv repo moved"); err != nil {
		t.Fatalf("moving the repository's directory failed: %q, %v", output, err)
	}
	for _, script := range []string{"echo evil > ../moved/.git/hooks/pre-commit", "echo '[core] hooksPath=/x' >> ../moved/.git/config", "mv ../moved/.git ../moved/dotgit"} {
		if output, err := attached(t, driver, StageSpec{
			Name: "rename", Argv: []string{"/bin/sh", "-c", script}, Workdir: filepath.Join(grant, "moved", "plain"),
			Paths: []Path{{Host: grant, Access: ReadWrite}}, Network: Network{Mode: NetworkNone},
		}); err == nil {
			t.Errorf("after the move, %q succeeded: %q", script, output)
		}
	}
}

// gitIn runs git under the real Seatbelt in repo, inside a writable grant,
// with its own home and temporary directory, and returns its output.
func gitIn(t *testing.T, driver *Driver, grant, repo string, args ...string) (string, error) {
	t.Helper()
	home := filepath.Join(grant, "home")
	tmp := filepath.Join(grant, "tmp")
	for _, dir := range []string{home, tmp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := coverage(t)
	maps.Copy(env, map[string]string{
		"HOME": home, "TMPDIR": tmp, "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME": "Stage", "GIT_AUTHOR_EMAIL": "stage@example.com",
		"GIT_COMMITTER_NAME": "Stage", "GIT_COMMITTER_EMAIL": "stage@example.com",
	})
	return attached(t, driver, StageSpec{
		Name: "git", Argv: append([]string{"/usr/bin/git"}, args...), Workdir: repo, Env: env,
		Paths: []Path{{Host: grant, Access: ReadWrite}}, Network: Network{Mode: NetworkNone},
	})
}

// TestEverydayGitStillWorks runs a day's git under the real Seatbelt in a
// repository inside a writable grant: edit, add, commit, branch, commit,
// switch back. None of it touches what the protection covers. It also pins
// what the protection costs, as srt's default costs it: git init and git
// config, which write a .git directory and git's config, fail inside a grant.
func TestEverydayGitStillWorks(t *testing.T) {
	driver, _ := realSeatbelt(t)
	if err := exec.Command("/usr/bin/git", "--version").Run(); err != nil { //nolint:noctx // a probe
		t.Skipf("no git here: %v", err)
	}
	grant, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(grant, "work")
	// The repository is made outside the sandbox, as the operator's clone
	// would be.
	init := exec.Command("/usr/bin/git", "init", "-q", "-b", "main", repo) //nolint:noctx // test setup
	init.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+grant)
	if output, err := init.CombinedOutput(); err != nil {
		t.Fatalf("git init outside the sandbox: %v\n%s", err, output)
	}
	if err := os.WriteFile(filepath.Join(repo, "notes.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, step := range [][]string{
		{"add", "notes.txt"},
		{"commit", "-q", "-m", "first"},
		{"checkout", "-q", "-b", "feature"},
		{"commit", "-q", "--allow-empty", "-m", "second"},
		{"checkout", "-q", "main"},
		{"log", "--oneline", "feature"},
	} {
		if output, err := gitIn(t, driver, grant, repo, step...); err != nil {
			t.Fatalf("git %s failed under Seatbelt: %v\n%s", strings.Join(step, " "), err, output)
		}
	}
	output, _ := gitIn(t, driver, grant, repo, "log", "--format=%s", "feature")
	if !strings.Contains(output, "second") || !strings.Contains(output, "first") {
		t.Fatalf("the branch does not hold both commits: %q", output)
	}
	if _, err := gitIn(t, driver, grant, repo, "config", "user.name", "x"); err == nil {
		t.Error("git config wrote git's config inside a grant")
	}
	if _, err := gitIn(t, driver, grant, grant, "init", "-q", "fresh"); err == nil {
		t.Error("git init made a .git directory inside a grant")
	}
}
