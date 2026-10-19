// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Git under the real Seatbelt: a gitdir is denied every write but what
// everyday git writes, so a stage can neither redirect git to a control file
// of its own nor stop a day's work.

// gitEnv is the environment git runs with in these tests, inside the sandbox
// and out: its own home and temporary directory, no system configuration, a
// fixed author, and a no-op editor so a commit never waits on input.
func gitEnv(grant string) map[string]string {
	return map[string]string{
		"HOME": filepath.Join(grant, "home"), "TMPDIR": filepath.Join(grant, "tmp"), "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME": "Stage", "GIT_AUTHOR_EMAIL": "stage@example.com",
		"GIT_COMMITTER_NAME": "Stage", "GIT_COMMITTER_EMAIL": "stage@example.com",
		"GIT_EDITOR": "true",
	}
}

// requireGit skips where git is not installed, and makes the home and
// temporary directories gitEnv names.
func requireGit(t *testing.T, grant string) {
	t.Helper()
	if err := exec.Command("/usr/bin/git", "--version").Run(); err != nil { //nolint:noctx // a probe
		t.Skipf("no git here: %v", err)
	}
	for _, dir := range []string{"home", "tmp"} {
		if err := os.MkdirAll(filepath.Join(grant, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// gitIn runs git under the real Seatbelt in dir, inside the writable grant,
// and returns its output.
func gitIn(t *testing.T, driver *Driver, grant, dir string, args ...string) (string, error) {
	t.Helper()
	env := coverage(t)
	maps.Copy(env, gitEnv(grant))
	return attached(t, driver, StageSpec{
		Name: "git", Argv: append([]string{"/usr/bin/git"}, args...), Workdir: dir, Env: env,
		Paths: []Path{{Host: grant, Access: ReadWrite}}, Network: Network{Mode: NetworkNone},
	})
}

// gitOut runs git outside the sandbox, as the operator does, and fails the
// test when it fails.
func gitOut(t *testing.T, grant, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("/usr/bin/git", args...) //nolint:noctx // the operator's git in test setup
	command.Dir = dir
	command.Env = os.Environ()
	for name, value := range gitEnv(grant) {
		command.Env = append(command.Env, name+"="+value)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s outside the sandbox: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

// newRepo makes a repository with one commit outside the sandbox, as the
// operator's clone would be, inside a fresh writable grant.
func newRepo(t *testing.T) (driver *Driver, grant, repo string) {
	t.Helper()
	driver, _ = realSeatbelt(t)
	grant, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	requireGit(t, grant)
	repo = filepath.Join(grant, "repo")
	gitOut(t, grant, grant, "init", "-q", "-b", "main", repo)
	if err := os.WriteFile(filepath.Join(repo, "notes.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitOut(t, grant, repo, "add", "notes.txt")
	gitOut(t, grant, repo, "commit", "-q", "-m", "first")
	return driver, grant, repo
}

// redirectScript is the attack the review reproduced: a directory outside
// the gitdir that holds a hook, with the gitdir's commondir pointed at it, so
// git reads its hooks from the stage's directory. The hook only creates a
// marker, which is how the test sees whether git ran it; a real one would run
// anything. The script writes the directory and the marker's path.
func redirectScript(grant, gitdir string) (script, marker string) {
	outside := filepath.Join(grant, "outside")
	marker = filepath.Join(grant, "ran")
	hook := filepath.Join(outside, "hooks", "pre-commit")
	realGit := filepath.Join(grant, "repo", ".git")
	lines := []string{
		"mkdir -p " + ShellQuote(filepath.Join(outside, "hooks")),
		// Link the real objects and refs in, so git still works through the
		// swapped common directory and reaches the hook.
		"for d in objects refs; do ln -s " + ShellQuote(realGit) + "/$d " + ShellQuote(outside) + "/$d; done",
		"printf '%s' '#!/bin/sh' > " + ShellQuote(hook),
		"printf '\\ntouch %s\\n' " + ShellQuote(marker) + " >> " + ShellQuote(hook),
		"chmod +x " + ShellQuote(hook),
		// Point git's common directory at the stage's directory.
		"printf '%s\\n' " + ShellQuote(outside) + " > " + ShellQuote(filepath.Join(gitdir, "commondir")),
	}
	return strings.Join(lines, " && "), marker
}

// TestAGitdirReadsNoControlFileAStagePlanted runs the redirect attack under
// the real Seatbelt, in a plain repository and in a worktree's gitdir: the
// stage's writes are refused, the operator's next commit runs no planted
// hook, and the commit itself still succeeds.
func TestAGitdirReadsNoControlFileAStagePlanted(t *testing.T) {
	driver, grant, repo := newRepo(t)

	run := func(name, gitdir, dir string) {
		before := commondir(filepath.Join(gitdir, "commondir"))
		script, marker := redirectScript(grant, gitdir)
		if output, err := attached(t, driver, StageSpec{
			Name: "redirect", Argv: []string{"/bin/sh", "-c", script}, Workdir: dir,
			Paths: []Path{{Host: grant, Access: ReadWrite}}, Network: Network{Mode: NetworkNone},
		}); err == nil {
			t.Errorf("%s: the redirect was written: %q", name, output)
		}
		if after := commondir(filepath.Join(gitdir, "commondir")); after != before {
			t.Errorf("%s: commondir changed from %q to %q", name, before, after)
		}
		added := strings.ReplaceAll(name, " ", "-") + ".txt"
		if err := os.WriteFile(filepath.Join(dir, added), []byte("two\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		gitOut(t, grant, dir, "add", added)
		gitOut(t, grant, dir, "commit", "-q", "-m", "the operator commits")
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("%s: the operator's commit ran a hook the stage planted", name)
		}
	}

	run("a plain repository", filepath.Join(repo, ".git"), repo)

	tree := filepath.Join(grant, "tree")
	gitOut(t, grant, repo, "worktree", "add", "-q", tree)
	gitdir := strings.TrimSpace(strings.TrimPrefix(readFile(t, filepath.Join(tree, ".git")), "gitdir:"))
	run("a worktree", gitdir, tree)
}

// TestAGitdirControlFilesStayDenied writes each file inside a gitdir that
// names a command or redirects git, under the real Seatbelt, and checks each
// is refused: config, hooks, commondir, gitdir, info/exclude, the objects
// alternates, and a name git might add later.
func TestAGitdirControlFilesStayDenied(t *testing.T) {
	driver, grant, repo := newRepo(t)
	gitOut(t, grant, repo, "worktree", "add", "-q", filepath.Join(grant, "wt"))
	for _, relative := range []string{
		".git/config", ".git/config.worktree", ".git/commondir", ".git/info/exclude", ".git/info/attributes",
		".git/objects/info/alternates", ".git/objects/info/http-alternates", ".git/hooks/pre-commit", ".git/newcontrol",
		".git/worktrees/wt/commondir", ".git/worktrees/wt/gitdir", ".git/worktrees/wt/config.worktree",
	} {
		path := filepath.Join(repo, relative)
		script := fmt.Sprintf("mkdir -p %s && printf x >> %s", ShellQuote(filepath.Dir(path)), ShellQuote(path))
		if output, err := gitShell(t, driver, grant, repo, script); err == nil {
			t.Errorf("%s was written: %q", relative, output)
		}
	}
}

// gitShell runs a shell script under the real Seatbelt in dir, inside the
// writable grant.
func gitShell(t *testing.T, driver *Driver, grant, dir, script string) (string, error) {
	t.Helper()
	return attached(t, driver, StageSpec{
		Name: "git-shell", Argv: []string{"/bin/sh", "-c", script}, Workdir: dir,
		Paths: []Path{{Host: grant, Access: ReadWrite}}, Network: Network{Mode: NetworkNone},
	})
}

// commondir is the content of a commondir file, or "" when there is none.
func commondir(path string) string {
	body, err := os.ReadFile(path) //nolint:gosec // a test path inside the grant
	if err != nil {
		return ""
	}
	return string(body)
}

// readFile reads a file or fails the test.
func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // a test path
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestEverydayGitStillWorks runs a day's git under the real Seatbelt in a
// repository inside a writable grant: edit, add, commit, branch, merge,
// rebase with a conflict and continue, cherry-pick, stash, tag, delete a
// branch, and fetch from a local repository. None of it touches what the
// protection covers. It also pins what the protection costs, as srt's
// default costs it: git init and git config inside a grant fail.
func TestEverydayGitStillWorks(t *testing.T) {
	driver, grant, repo := newRepo(t)
	git := func(args ...string) string {
		t.Helper()
		output, err := gitIn(t, driver, grant, repo, args...)
		if err != nil {
			t.Fatalf("git %s failed under Seatbelt: %v\n%s", strings.Join(args, " "), err, output)
		}
		return output
	}
	edit := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A branch, a commit on it, and a merge back.
	git("checkout", "-q", "-b", "feature")
	edit("feature.txt", "feature\n")
	git("add", "feature.txt")
	git("commit", "-q", "-m", "a feature")
	git("checkout", "-q", "main")
	git("merge", "-q", "--no-edit", "feature")

	// A rebase with a conflict, resolved and continued.
	git("checkout", "-q", "-b", "left")
	edit("notes.txt", "left\n")
	git("commit", "-q", "-am", "left")
	git("checkout", "-q", "main")
	edit("notes.txt", "main\n")
	git("commit", "-q", "-am", "main")
	if _, err := gitIn(t, driver, grant, repo, "rebase", "left"); err == nil {
		t.Fatal("the rebase did not conflict as the test set it up to")
	}
	edit("notes.txt", "resolved\n")
	git("add", "notes.txt")
	git("-c", "core.editor=true", "rebase", "--continue")

	// A commit on main that touches a new file, cherry-picked onto feature,
	// so it applies without a conflict.
	git("checkout", "-q", "main")
	edit("pick.txt", "pick me\n")
	git("add", "pick.txt")
	git("commit", "-q", "-m", "a commit to pick")
	pick := strings.TrimSpace(git("rev-parse", "HEAD"))
	git("checkout", "-q", "feature")
	git("cherry-pick", pick)

	// Stash, a tag, deleting a branch, and gc.
	edit("notes.txt", "work in progress\n")
	git("stash")
	git("stash", "pop")
	git("checkout", "-q", "--", "notes.txt") // drop the restored change, as a day's cleanup would
	git("tag", "v1")
	git("checkout", "-q", "main")
	git("branch", "-D", "left")
	git("gc", "-q")

	// A fetch from a local bare repository, which writes refs and objects.
	bare := filepath.Join(grant, "origin.git")
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, bare)
	gitOut(t, grant, repo, "remote", "add", "origin", bare) // the operator adds the remote; it writes git's config
	if _, err := gitIn(t, driver, grant, repo, "fetch", "-q", "origin"); err != nil {
		t.Fatalf("a fetch from a local repository failed under Seatbelt: %v", err)
	}

	// The cost, as srt's default costs it.
	if _, err := gitIn(t, driver, grant, repo, "config", "user.name", "x"); err == nil {
		t.Error("git config wrote git's config inside a grant")
	}
	if _, err := gitIn(t, driver, grant, grant, "init", "-q", "fresh"); err == nil {
		t.Error("git init made a .git directory inside a grant")
	}
}

// TestABareRepositoryIsProtected treats a directory whose name ends in .git
// as a gitdir: under the real Seatbelt a stage cannot write its config or a
// hook, while a push into it from a working clone, run as the stage, still
// writes its objects and refs.
func TestABareRepositoryIsProtected(t *testing.T) {
	driver, grant, repo := newRepo(t)
	bare := filepath.Join(grant, "origin.git")
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, bare)

	for _, relative := range []string{"hooks/post-receive", "config"} {
		path := filepath.Join(bare, relative)
		script := fmt.Sprintf("mkdir -p %s && printf x >> %s", ShellQuote(filepath.Dir(path)), ShellQuote(path))
		if output, err := gitShell(t, driver, grant, grant, script); err == nil {
			t.Errorf("a bare repository's %s was written: %q", relative, output)
		}
	}
	if body := readFile(t, filepath.Join(bare, "config")); !strings.Contains(body, "bare = true") {
		t.Errorf("the bare repository's config changed: %q", body)
	}

	// The stage commits in the working clone and pushes into the bare
	// repository, which writes its objects and refs.
	if err := os.WriteFile(filepath.Join(repo, "pushed.txt"), []byte("pushed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := gitIn(t, driver, grant, repo, "add", "pushed.txt"); err != nil {
		t.Fatalf("add under Seatbelt: %v", err)
	}
	if _, err := gitIn(t, driver, grant, repo, "commit", "-q", "-m", "a commit to push"); err != nil {
		t.Fatalf("commit under Seatbelt: %v", err)
	}
	if output, err := gitIn(t, driver, grant, repo, "push", "-q", bare, "main"); err != nil {
		t.Fatalf("a push into the bare repository failed under Seatbelt: %v\n%s", err, output)
	}
	if out := gitOut(t, grant, bare, "log", "--format=%s", "-1", "main"); !strings.Contains(out, "a commit to push") {
		t.Fatalf("the push did not reach the bare repository: %q", out)
	}
}
