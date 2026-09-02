// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package gitutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGit puts a stub `git` at the front of PATH for the rest of the test. The
// stub echoes body on stdout and exits 0, which is the only way to drive the
// branches that react to git succeeding while returning output the parser
// cannot use. Real git never emits those shapes on a healthy repository, so
// they are otherwise unreachable from a test.
func fakeGit(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s'\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), fmt.Appendf(nil, script, body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// fakeGitFailing puts a stub `git` at the front of PATH that exits non-zero for
// the one invocation matching guard and succeeds for every other. guard is a
// shell condition over the stub's positional arguments, which arrive as
// "-C <dir> <subcommand> ...", so $3 is the subcommand.
//
// It exists to reach the per-step error branches of a pipeline that runs
// several git commands in a row. Making the second or fourth of them fail
// against a real repository is not something a test can arrange.
func fakeGitFailing(t *testing.T, guard string) {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nif %s; then echo 'stub failure' >&2; exit 1; fi\nexit 0\n", guard)
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// InitLocalRepo runs five git commands in sequence. Each has its own error
// message so a failure names the step it came from rather than reporting a
// generic "could not initialise repository".
func TestInitLocalRepo_StepFailures(t *testing.T) {
	cases := []struct {
		name    string
		guard   string
		wantMsg string
	}{
		{"config user.email", `[ "$3" = "config" ] && [ "$4" = "user.email" ]`, "git config user.email"},
		{"config user.name", `[ "$3" = "config" ] && [ "$4" = "user.name" ]`, "git config user.name"},
		{"add", `[ "$3" = "add" ]`, "git add"},
		{"commit", `[ "$3" = "commit" ]`, "git commit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeGitFailing(t, c.guard)

			err := InitLocalRepo(t.TempDir(), "test@example.com", "Test", "initial")
			if err == nil {
				t.Fatalf("expected an error when %s fails", c.name)
			}
			if !strings.Contains(err.Error(), c.wantMsg) {
				t.Fatalf("error = %v, want it to mention %q", err, c.wantMsg)
			}
		})
	}
}

// A path that is not a repository makes `git status` exit non-zero, which
// HasChanges must surface rather than reporting a clean tree.
func TestHasChanges_NotARepo(t *testing.T) {
	dir := t.TempDir()

	changed, err := HasChanges(context.Background(), dir)
	if err == nil {
		t.Fatal("expected an error for a path that is not a git repository")
	}
	if changed {
		t.Fatal("expected changed=false alongside the error")
	}
}

// git init cannot run against a regular file, so the first step of the
// snapshot pipeline reports rather than proceeding into config and commit.
func TestInitLocalRepo_InitFails(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := InitLocalRepo(file, "test@example.com", "Test", "initial")
	if err == nil {
		t.Fatal("expected an error when git init cannot run")
	}
	if !strings.Contains(err.Error(), "git init") {
		t.Fatalf("error = %v, want it to name the failing step", err)
	}
}

// BranchTipCommit parses a pipe-delimited log line. Each way that parse can
// fail has its own message so an operator can tell a missing branch from
// output git should never have produced.
func TestBranchTipCommit_UnparseableOutput(t *testing.T) {
	cases := []struct {
		name    string
		output  string
		wantMsg string
	}{
		{"no output", "", "not found or has no commits"},
		{"too few fields", "abc123", "unexpected git log output"},
		{"unparseable timestamp", "abc123|not-a-timestamp|subject", "parse commit timestamp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeGit(t, c.output)

			hash, subject, ts, err := BranchTipCommit("/somewhere", "main")
			if err == nil {
				t.Fatalf("expected an error for git output %q", c.output)
			}
			if !strings.Contains(err.Error(), c.wantMsg) {
				t.Fatalf("error = %v, want it to mention %q", err, c.wantMsg)
			}
			if subject != "" || !ts.IsZero() {
				t.Fatalf("expected no partial result, got subject=%q ts=%v", subject, ts)
			}
			if c.output == "" && hash != "" {
				t.Fatalf("expected no hash, got %q", hash)
			}
		})
	}
}

// An add that fails for a reason other than the branch-already-exists race is
// reported verbatim rather than being routed into the reattach recovery. An
// invalid branch name is rejected by git before it touches the filesystem, so
// its output carries none of the strings that trigger the reattach.
func TestCreateWorktree_AddFails(t *testing.T) {
	repo := setupRepo(t)
	target := filepath.Join(t.TempDir(), "wt")

	err := CreateWorktree(repo, target, "bad..name")
	if err == nil {
		t.Fatal("expected an error for an invalid branch name")
	}
	if !strings.Contains(err.Error(), "git worktree add") {
		t.Fatalf("error = %v, want it to name the failing command", err)
	}
	if strings.Contains(err.Error(), "existing branch") {
		t.Fatalf("error = %v, want the plain add failure rather than the reattach path", err)
	}
}

// When the branch already exists, CreateWorktree reattaches it with a forced
// add. That add can fail for its own reasons, and the error says which path
// it came from so the two are distinguishable in logs.
func TestCreateWorktree_ReattachFails(t *testing.T) {
	repo := setupRepo(t)
	gitRun(t, repo, "branch", "feature")
	target := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(target, []byte("in the way"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := CreateWorktree(repo, target, "feature")
	if err == nil {
		t.Fatal("expected an error when reattaching an existing branch fails")
	}
	if !strings.Contains(err.Error(), "existing branch") {
		t.Fatalf("error = %v, want the reattach path to identify itself", err)
	}
}
