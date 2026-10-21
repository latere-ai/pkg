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
// link, not a file pointing git elsewhere. It also checks that a *.git folder
// cannot be made inside git's refs at all, nor by renaming a folder there, so
// none can be staged and moved out; and it pins what the rule costs: a file
// whose name ends in .git cannot be created in a grant either.
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
		"a folder":                         `mkdir sub/origin.git`,
		"a symbolic link":                  `ln -s ../held/origin.git sub/origin.git`,
		"a file":                           `printf 'gitdir: ../held/origin.git\n' > sub/origin.git`,
		"a renamed folder":                 `mkdir prep && mv prep sub/origin.git`,
		"a *.git folder in refs":           `mkdir repo/.git/refs/heads/x.git`,
		"a *.git folder moved out of refs": `mkdir repo/.git/refs/heads/y && mv repo/.git/refs/heads/y repo/.git/refs/heads/z.git && mv repo/.git/refs/heads/z.git fresh.git`,
		"a file named *.git":               `touch notes.git`,
	} {
		if output, err := gitShell(t, driver, grant, grant, script); err == nil {
			t.Errorf("%s was created: %q", name, output)
		}
	}
	for _, path := range []string{"sub/origin.git", "notes.git", "fresh.git", "repo/.git/refs/heads/x.git"} {
		if _, err := os.Lstat(filepath.Join(grant, path)); err == nil {
			t.Errorf("%s was created", path)
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

// TestABareRepositoryHooksStayDeniedUnderAWritableDir runs the route a review
// found, under the real Seatbelt: a bare repository's folder is ordinary to
// move, so a stage moves the folder that holds one into a gitdir's writable
// directory (refs, then objects), where the everyday-git allowance opens
// everything, and tries to write the bare repository's hook and config there.
// Each is refused, and the operator's later push, from their own terminal,
// runs no planted hook. A legal branch whose name ends in .git still works.
func TestABareRepositoryHooksStayDeniedUnderAWritableDir(t *testing.T) {
	driver, grant, repo := newRepo(t)
	if err := os.Mkdir(filepath.Join(grant, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(grant, "sub", "origin.git")
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, bare)
	gitOut(t, grant, repo, "remote", "add", "origin", bare)

	for _, dir := range []string{"refs/heads/held", "logs/refs/held", "objects/held"} {
		marker := filepath.Join(grant, "ran-"+strings.ReplaceAll(dir, "/", "-"))
		moved := "repo/.git/" + dir
		inside := moved + "/origin.git"
		if output, err := gitShell(t, driver, grant, grant, "mv sub "+ShellQuote(moved)); err != nil {
			t.Fatalf("moving the folder into %s was refused: %q, %v", dir, output, err)
		}
		// With the bare repository under a writable directory, writing its hook
		// or config must still be refused, and so must renaming its folder to a
		// name without .git, which would shed the component the denial keys on.
		for name, script := range map[string]string{
			"its hook":            "printf '#!/bin/sh\\ntouch %s\\n' " + ShellQuote(marker) + " > " + ShellQuote(inside+"/hooks/post-receive"),
			"its config":          "echo '[core] hooksPath=/tmp' >> " + ShellQuote(inside+"/config"),
			"its info/attributes": "printf 'x filter=evil\\n' > " + ShellQuote(inside+"/info/attributes"),
			"renamed to shed .git": "mv " + ShellQuote(inside) + " " + ShellQuote(moved+"/plain") +
				" && printf '#!/bin/sh\\ntouch %s\\n' " + ShellQuote(marker) + " > " + ShellQuote(moved+"/plain/hooks/post-receive"),
		} {
			if output, err := gitShell(t, driver, grant, grant, script); err == nil {
				t.Errorf("%s under %s was written: %q", name, dir, output)
			}
		}
		if output, err := gitShell(t, driver, grant, grant, "mv "+ShellQuote(moved)+" sub"); err != nil {
			t.Fatalf("moving the folder back from %s was refused: %q, %v", dir, output, err)
		}
		// The operator pushes to the unchanged path from their own terminal.
		gitOut(t, grant, repo, "commit", "--allow-empty", "-q", "-m", "x")
		gitOut(t, grant, repo, "push", "-q", "origin", "HEAD:refs/heads/pushed-"+filepath.Base(dir))
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("%s: the operator's push ran a hook the stage planted", dir)
		}
		if body, err := os.ReadFile(filepath.Join(bare, "config")); err != nil || strings.Contains(string(body), "hooksPath") {
			t.Errorf("%s: the bare repository's config was changed: %q, %v", dir, body, err)
		}
	}

	// A legal branch whose name ends in .git is not a bare repository and is
	// unaffected: git stores it as a file under refs.
	if output, err := gitIn(t, driver, grant, repo, "branch", "topic.git"); err != nil {
		t.Errorf("a branch named topic.git was refused: %v\n%s", err, output)
	}
}

// TestANewBareRepositoryCannotBeImportedUnderAWritableDir runs the route a
// review found, under the real Seatbelt: a stage builds a bare repository with
// an executable hook under a name without .git, where its hook is writable,
// then tries to rename it into a *.git name in a gitdir's writable directory,
// which would make a *.git folder git later opens, and carry it to the
// operator's path by moving an ordinary ancestor, which renames no *.git node.
// Creating a *.git folder there is refused, so there is nothing to carry, and
// the operator's push runs no planted hook. A *.git file (a gitfile) the
// allowance does permit under refs, carried to the operator's path, is inert:
// git does not open a file named origin.git as a repository there.
func TestANewBareRepositoryCannotBeImportedUnderAWritableDir(t *testing.T) {
	driver, grant, repo := newRepo(t)
	if err := os.Mkdir(filepath.Join(grant, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(grant, "sub", "origin.git")
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, bare)
	gitOut(t, grant, repo, "remote", "add", "origin", bare)

	for _, dir := range []string{"refs/heads/held", "logs/refs/held", "objects/held", "rebase-merge/held"} {
		marker := filepath.Join(grant, "import-"+strings.ReplaceAll(dir, "/", "-"))
		// A bare repository built under a name without .git, its hook made
		// executable there, then renamed into a *.git folder in the writable
		// directory: the rename makes a *.git folder, which is refused.
		script := strings.Join([]string{
			"cp -R sub/origin.git evilbare",
			"printf '#!/bin/sh\\ntouch %s\\n' " + ShellQuote(marker) + " > evilbare/hooks/post-receive",
			"chmod +x evilbare/hooks/post-receive",
			"mkdir -p " + ShellQuote("repo/.git/"+dir),
			"mv evilbare " + ShellQuote("repo/.git/"+dir+"/origin.git"),
		}, " && ")
		if output, err := gitShell(t, driver, grant, grant, script); err == nil {
			t.Errorf("a bare repository was imported into %s: %q", dir, output)
		}
		if _, err := os.Stat(filepath.Join(grant, "repo", ".git", dir, "origin.git")); err == nil {
			t.Errorf("a *.git folder was made in %s", dir)
		}
		// Clean the staged evilbare between rounds.
		_, _ = gitShell(t, driver, grant, grant, "rm -rf evilbare")
	}

	// A *.git gitfile, a regular file, the allowance does permit under refs; a
	// stage carries it to the operator's path by moving its ancestor. The
	// operator's push does not follow it, so no hook runs, and the real bare
	// repository is untouched.
	gitOut(t, grant, repo, "commit", "--allow-empty", "-q", "-m", "x")
	script := strings.Join([]string{
		"printf '#!/bin/sh\\ntouch %s/imported\\n' " + ShellQuote(grant) + " > evil-post-receive",
		"mkdir -p repo/.git/refs/heads/h2",
		"printf 'gitdir: %s/elsewhere\\n' " + ShellQuote(grant) + " > repo/.git/refs/heads/h2/origin.git",
	}, " && ")
	if _, err := gitShell(t, driver, grant, grant, script); err != nil {
		t.Fatalf("staging the gitfile failed: %v", err)
	}
	// The push to the real bare repository still works and runs no planted hook.
	if output, err := gitIn(t, driver, grant, repo, "push", "-q", "origin", "HEAD:refs/heads/pushed"); err != nil {
		t.Fatalf("a push to the real bare repository failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(grant, "imported")); err == nil {
		t.Error("the operator's push followed a stage-planted gitfile")
	}
}

// TestGCWorksInAGrantedRepository runs git gc under the real Seatbelt in a
// granted repository and checks it leaves no error behind: it must pack the
// refs, which writes packed-refs.new, and refresh the server-info files, which
// writes info/refs through a temporary of its own, both of which a review
// found denied. info/attributes, which names a command git may run, stays
// denied.
func TestGCWorksInAGrantedRepository(t *testing.T) {
	driver, grant, repo := newRepo(t)
	for _, n := range []string{"a", "b", "c"} {
		gitOut(t, grant, repo, "branch", n)
	}
	gitOut(t, grant, repo, "commit", "--allow-empty", "-q", "-m", "more")
	for _, args := range [][]string{{"gc", "-q"}, {"update-server-info"}} {
		if output, err := gitIn(t, driver, grant, repo, args...); err != nil || strings.TrimSpace(output) != "" {
			t.Errorf("git %s left an error under Seatbelt: %v\n%q", strings.Join(args, " "), err, output)
		}
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "packed-refs")); err != nil {
		t.Errorf("gc did not pack the refs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "info", "refs")); err != nil {
		t.Errorf("gc did not refresh info/refs: %v", err)
	}
	if output, err := gitShell(t, driver, grant, repo, `printf 'x filter=evil\n' > .git/info/attributes`); err == nil {
		t.Errorf("info/attributes, which names a filter command, was written: %q", output)
	}

	// update-server-info makes the info directory when a repository has none.
	if err := os.RemoveAll(filepath.Join(repo, ".git", "info")); err != nil {
		t.Fatal(err)
	}
	if output, err := gitIn(t, driver, grant, repo, "update-server-info"); err != nil || strings.TrimSpace(output) != "" {
		t.Errorf("update-server-info could not make the info directory: %v\n%q", err, output)
	}
}

// TestANodeNamedLikeABareRepositoryInRefsMustBeARegularFile checks, under the
// real Seatbelt, the one place a *.git name is allowed: a gitdir's refs and
// logs, where a branch or tag of that name is a file. The allowance is held to
// a regular file, so a symbolic link of that name is refused there, made
// directly or by renaming an ordinary link onto the name, while a regular file
// of the same name in the same place is created.
func TestANodeNamedLikeABareRepositoryInRefsMustBeARegularFile(t *testing.T) {
	driver, grant, _ := newRepo(t)
	for name, script := range map[string]string{
		"a symbolic link in refs": `mkdir -p repo/.git/refs/heads/h && ln -s ../../../../elsewhere repo/.git/refs/heads/h/origin.git`,
		"a symbolic link in logs": `mkdir -p repo/.git/logs/refs/heads/h && ln -s ../../../../../elsewhere repo/.git/logs/refs/heads/h/origin.git`,
		"a renamed symbolic link in refs": `mkdir -p repo/.git/refs/heads/h && ln -s x repo/.git/refs/heads/h/link && ` +
			`mv repo/.git/refs/heads/h/link repo/.git/refs/heads/h/origin.git`,
	} {
		if output, err := gitShell(t, driver, grant, grant, script); err == nil {
			t.Errorf("%s was created: %q", name, output)
		}
	}
	for _, path := range []string{"repo/.git/refs/heads/h/origin.git", "repo/.git/logs/refs/heads/h/origin.git"} {
		if _, err := os.Lstat(filepath.Join(grant, path)); err == nil {
			t.Errorf("%s was created", path)
		}
	}
	// A regular file of the same name in the same place is a branch or tag, and
	// is created, so the refusal above is the node type deciding.
	for name, script := range map[string]string{
		"a branch file in refs": `mkdir -p repo/.git/refs/heads/h && touch repo/.git/refs/heads/h/branch.git`,
		"a branch file in logs": `mkdir -p repo/.git/logs/refs/heads/h && touch repo/.git/logs/refs/heads/h/branch.git`,
	} {
		if output, err := gitShell(t, driver, grant, grant, script); err != nil {
			t.Errorf("%s was refused: %q, %v", name, output, err)
		}
	}
}

// TestAMovedBareRepositoryObjectRedirectStaysDenied moves, under the real
// Seatbelt, the folder holding a bare repository into a gitdir's objects
// directory, whose allowance opens everything below it, and checks that the
// repository's files pointing git at another object store, common directory or
// gitdir, its config.worktree and its info/exclude, are each refused there,
// while its own object content stays writable, so the denial is by control
// name and not of the moved tree. After it is moved back, the operator's push
// works and none of those files took hold.
func TestAMovedBareRepositoryObjectRedirectStaysDenied(t *testing.T) {
	driver, grant, repo := newRepo(t)
	if err := os.Mkdir(filepath.Join(grant, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(grant, "sub", "origin.git")
	gitOut(t, grant, grant, "clone", "-q", "--bare", repo, bare)
	gitOut(t, grant, repo, "remote", "add", "origin", bare)

	moved := "repo/.git/objects/held"
	inside := moved + "/origin.git"
	if output, err := gitShell(t, driver, grant, grant, "mv sub "+ShellQuote(moved)); err != nil {
		t.Fatalf("moving the folder into objects was refused: %q, %v", output, err)
	}
	for _, rel := range []string{
		"objects/info/alternates", "objects/info/http-alternates", "commondir", "gitdir", "config.worktree", "info/exclude",
	} {
		target := inside + "/" + rel
		script := "mkdir -p " + ShellQuote(filepath.Dir(target)) + " && printf x >> " + ShellQuote(target)
		if output, err := gitShell(t, driver, grant, grant, script); err == nil {
			t.Errorf("%s under a moved bare repository was written: %q", rel, output)
		}
	}
	control := inside + "/objects/zz/stage-data"
	if output, err := gitShell(t, driver, grant, grant, "mkdir -p "+ShellQuote(filepath.Dir(control))+" && printf x > "+ShellQuote(control)+" && rm -f "+ShellQuote(control)); err != nil {
		t.Errorf("the moved repository's own object content was refused: %q, %v", output, err)
	}
	if output, err := gitShell(t, driver, grant, grant, "mv "+ShellQuote(moved)+" sub"); err != nil {
		t.Fatalf("moving the folder back was refused: %q, %v", output, err)
	}
	gitOut(t, grant, repo, "commit", "--allow-empty", "-q", "-m", "x")
	gitOut(t, grant, repo, "push", "-q", "origin", "HEAD:refs/heads/pushed")
	// info/exclude exists in every repository, so only the names a bare
	// repository has none of by default are checked for here.
	for _, rel := range []string{"commondir", "gitdir", "config.worktree", "objects/info/alternates", "objects/info/http-alternates"} {
		if _, err := os.Lstat(filepath.Join(bare, rel)); err == nil {
			t.Errorf("%s took hold in the bare repository", rel)
		}
	}
}
