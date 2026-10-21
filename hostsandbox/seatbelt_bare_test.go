// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// These checks run a bare repository's folder against the real Seatbelt,
// which lives on macOS alone.

//go:build darwin

package hostsandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A bare repository's folder, a directory whose name ends in .git, holds its
// config and hooks at the top level. Those are denied, so a stage cannot edit
// them in place; the folder itself is pinned too, so a stage cannot remove it,
// rename it away to edit it under another name and move it back, or build one
// elsewhere and move it into place, and so give the folder the operator later
// pushes to hooks of the stage's choosing.

// TestABareRepositoryNodeCannotBeSwapped runs, under the real Seatbelt, each
// route by which a stage might replace a bare repository's folder, and checks
// each is refused, the folder stays where it is with its config unchanged, and
// no folder named *.git is planted.
func TestABareRepositoryNodeCannotBeSwapped(t *testing.T) {
	driver, grant, repo := newRepo(t)
	bare := filepath.Join(grant, "origin.git")
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, bare)
	before := readFile(t, filepath.Join(bare, "config"))

	// Routes a shell drives: remove the folder, rename it away (with and
	// without moving it back), move a prepared folder into a *.git name, and
	// create a *.git name as a symbolic link.
	for name, script := range map[string]string{
		"removed":                        `rm -rf origin.git`,
		"renamed away":                   `mv origin.git origin.away`,
		"renamed away, edited, and back": `mv origin.git away && echo evil >> away/hooks/post-receive && mv away origin.git`,
		"a prepared folder moved in":     `mkdir -p prep/hooks && echo evil > prep/hooks/post-receive && mv prep fresh.git`,
		"created directly":               `mkdir plain.git`,
		"created as a symbolic link":     `ln -s ` + ShellQuote(grant) + ` evil.git`,
	} {
		if output, err := gitShell(t, driver, grant, grant, script); err == nil {
			t.Errorf("%s succeeded: %q", name, output)
		}
	}
	// Routes git drives, with its own home so it reads no operator config: a
	// bare init, clone and mirror each create a *.git folder, so each fails,
	// as git init and git clone already do inside a grant.
	for name, args := range map[string][]string{
		"git init --bare":    {"init", "-q", "--bare", "new.git"},
		"git clone --bare":   {"clone", "-q", "--bare", repo, "cloned.git"},
		"git clone --mirror": {"clone", "-q", "--mirror", repo, "mirror.git"},
	} {
		if output, err := gitIn(t, driver, grant, grant, args...); err == nil {
			t.Errorf("%s succeeded: %q", name, output)
		}
	}

	if _, err := os.Stat(bare); err != nil {
		t.Errorf("the bare repository was moved or removed: %v", err)
	}
	if body := readFile(t, filepath.Join(bare, "config")); body != before {
		t.Errorf("the bare repository's config changed: %q", body)
	}
	for _, name := range []string{"origin.away", "away", "fresh.git", "plain.git", "evil.git", "new.git", "cloned.git", "mirror.git"} {
		if _, err := os.Lstat(filepath.Join(grant, name)); err == nil {
			t.Errorf("%s was created", name)
		}
	}
}

// TestABareRepositoryPathCannotBeRefilled moves, under the real Seatbelt, the
// ordinary folder holding a bare repository, which is allowed and carries the
// repository along still pinned, and checks that nothing named *.git can then
// be created at the path the repository left: not a folder, not a symbolic
// link, not a file pointing git elsewhere, and not a folder made inside git's
// refs, where such a name is allowed, and moved out. It also pins what the
// rule costs: a file whose name ends in .git cannot be created in a grant
// either.
func TestABareRepositoryPathCannotBeRefilled(t *testing.T) {
	driver, grant, repo := newRepo(t)
	if err := os.Mkdir(filepath.Join(grant, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, filepath.Join(grant, "sub", "origin.git"))
	if output, err := gitShell(t, driver, grant, grant, `mv sub held && mkdir sub`); err != nil {
		t.Fatalf("moving the folder that holds a bare repository failed: %q, %v", output, err)
	}
	for name, script := range map[string]string{
		"a folder":           `mkdir sub/origin.git`,
		"a symbolic link":    `ln -s ../held/origin.git sub/origin.git`,
		"a file":             `printf 'gitdir: ../held/origin.git\n' > sub/origin.git`,
		"a renamed folder":   `mkdir prep && mv prep sub/origin.git`,
		"a folder from refs": `mkdir -p repo/.git/refs/heads/x.git/hooks && mv repo/.git/refs/heads/x.git sub/origin.git`,
		"a name from refs":   `mkdir -p repo/.git/refs/heads/y.git && mv repo/.git/refs/heads/y.git fresh.git`,
		"a file named *.git": `touch notes.git`,
	} {
		if output, err := gitShell(t, driver, grant, grant, script); err == nil {
			t.Errorf("%s was created: %q", name, output)
		}
	}
	for _, path := range []string{"sub/origin.git", "notes.git", "fresh.git"} {
		if _, err := os.Lstat(filepath.Join(grant, path)); err == nil {
			t.Errorf("%s was created", path)
		}
	}
	// The folders made in refs exist, so what was refused was the move.
	for _, path := range []string{"repo/.git/refs/heads/x.git/hooks", "repo/.git/refs/heads/y.git"} {
		if _, err := os.Stat(filepath.Join(grant, path)); err != nil {
			t.Errorf("%s, which git's refs allow, was not made: %v", path, err)
		}
	}
	if err := stageWrite(t, driver, grant, filepath.Join(grant, "held", "origin.git", "hooks", "post-receive")); err == nil {
		t.Error("the moved bare repository's hook was written")
	}
}

// TestABareRepositoryPinHoldsInAGrantNamedWithRegexCharacters runs, under the
// real Seatbelt, a grant whose name holds every character a regular
// expression gives meaning that a file name may hold, and checks the pin is
// written so that it still matches there: the bare repository cannot be
// renamed away, nothing named *.git can be made at the path it leaves when its
// folder moves, and a push into it still works.
func TestABareRepositoryPinHoldsInAGrantNamedWithRegexCharacters(t *testing.T) {
	driver, outer, repo := newRepo(t)
	grant := filepath.Join(outer, `a.b+(c)[d]{1}^$|?*\e`)
	requireGit(t, grant)
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, filepath.Join(grant, "sub", "origin.git"))
	gitOut(t, grant, grant, "clone", "-q", filepath.Join(grant, "sub", "origin.git"), "work")

	work := filepath.Join(grant, "work")
	if err := os.WriteFile(filepath.Join(work, "more.txt"), []byte("more\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "more.txt"}, {"commit", "-q", "-m", "more"}, {"push", "-q", "origin", "main"}} {
		if output, err := gitIn(t, driver, grant, work, args...); err != nil {
			t.Fatalf("git %s failed under Seatbelt: %v\n%s", strings.Join(args, " "), err, output)
		}
	}

	// In this order, since the last moves the folder the first two act on.
	for _, route := range []struct{ name, script string }{
		{"renamed away", `mv sub/origin.git away`},
		{"a *.git created here", `mkdir fresh.git`},
		{"its path refilled", `mv sub held && mkdir sub && mkdir sub/origin.git`},
	} {
		if output, err := gitShell(t, driver, grant, grant, route.script); err == nil {
			t.Errorf("%s succeeded: %q", route.name, output)
		}
	}
	if _, err := os.Stat(filepath.Join(grant, "held", "origin.git", "config")); err != nil {
		t.Errorf("moving the folder that holds the bare repository did not carry it along: %v", err)
	}
	for _, path := range []string{"away", "sub/origin.git", "fresh.git"} {
		if _, err := os.Lstat(filepath.Join(grant, path)); err == nil {
			t.Errorf("%s was created", path)
		}
	}
}

// TestARefNamedLikeABareRepositoryStillWorks runs, under the real Seatbelt,
// git work on refs whose names end in .git, which git stores as files of that
// name under refs and logs: a branch made, checked out and deleted, a tag made
// and deleted, a push of such a branch and tag into a bare repository, and a
// fetch of one from it. The pin's allowance for them is scoped to git's own
// writable directories, so it opens no repository or alternates file there.
func TestARefNamedLikeABareRepositoryStillWorks(t *testing.T) {
	driver, grant, repo := newRepo(t)
	bare := filepath.Join(grant, "origin.git")
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, bare)
	gitOut(t, grant, repo, "remote", "add", "origin", bare) // the operator adds the remote; it writes git's config
	gitOut(t, grant, bare, "branch", "upstream.git", "main")
	for _, args := range [][]string{
		{"branch", "topic.git"}, {"checkout", "-q", "-b", "work.git"}, {"checkout", "-q", "main"},
		{"branch", "-D", "topic.git"}, {"tag", "v1.git"}, {"tag", "-d", "v1.git"}, {"tag", "v2.git"},
		{"push", "-q", "origin", "main:refs/heads/feature.git", "v2.git"},
		{"push", "-q", "origin", ":refs/heads/feature.git"},
		{"fetch", "-q", "origin"},
	} {
		if output, err := gitIn(t, driver, grant, repo, args...); err != nil {
			t.Fatalf("git %s failed under Seatbelt: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	if out := gitOut(t, grant, repo, "branch", "-r"); !strings.Contains(out, "origin/upstream.git") {
		t.Errorf("the fetch did not bring the branch upstream.git: %q", out)
	}
	if out := gitOut(t, grant, bare, "tag"); !strings.Contains(out, "v2.git") {
		t.Errorf("the push did not bring the tag v2.git: %q", out)
	}
	// What the allowance must not open: a repository hidden under refs, and
	// an alternates file moved into place.
	for name, script := range map[string]string{
		"a .git under refs":          `mkdir .git/refs/heads/.git`,
		"alternates moved in":        `printf '/elsewhere\n' > alt && mv alt .git/objects/info/alternates`,
		"a bare alternates moved in": `printf '/elsewhere\n' > alt && mv alt ../origin.git/objects/info/alternates`,
	} {
		if output, err := gitShell(t, driver, grant, repo, script); err == nil {
			t.Errorf("%s succeeded: %q", name, output)
		}
	}
}

// TestABareRepositoryStillTakesEverydayGit runs, under the real Seatbelt, the
// everyday work the pin must leave alone: a stage commits and pushes into a
// bare repository that already exists, and fetches into it from a second,
// which writes its objects and refs without touching the folder itself.
func TestABareRepositoryStillTakesEverydayGit(t *testing.T) {
	driver, grant, repo := newRepo(t)
	bare := filepath.Join(grant, "origin.git")
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, bare)

	if err := os.WriteFile(filepath.Join(repo, "more.txt"), []byte("more\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "more.txt"}, {"commit", "-q", "-m", "more"}, {"push", "-q", bare, "main"}} {
		if output, err := gitIn(t, driver, grant, repo, args...); err != nil {
			t.Fatalf("git %s into the bare repository failed under Seatbelt: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	if out := gitOut(t, grant, bare, "log", "--format=%s", "-1", "main"); !strings.Contains(out, "more") {
		t.Fatalf("the push did not reach the bare repository: %q", out)
	}

	// A fetch into the bare repository from a second one the operator made.
	second := filepath.Join(grant, "second.git")
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, second)
	gitOut(t, grant, bare, "remote", "add", "second", second) // the operator writes the bare's config
	if output, err := gitIn(t, driver, grant, bare, "fetch", "-q", "second"); err != nil {
		t.Fatalf("a fetch into the bare repository failed under Seatbelt: %v\n%s", err, output)
	}
}
