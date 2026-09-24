# Contributing

This file is for people changing `pkg`. People importing it start at the
[README](README.md) and [pkg.go.dev](https://pkg.go.dev/latere.ai/x/pkg).

## What belongs here

A generic package with a plausible second consumer is written here first, at
this module's bar, and consumed from here; a product's `internal/` holds only
what is specific to that product. Extraction happens when the second consumer
appears, not later: the third copy is the one that drifts.

What "generic" means in practice: an S3 client, a metrics registry, an error
envelope, a probe surface, a retry loop, a host allow-list, a cancellable
sleep. What stays in a product: its error codes, its contract header, its
store interface, its configuration. A package here names no product and holds
no server-side logic that belongs to one service.

The module is public. Internal planning documents live elsewhere, and
`make no-tracked-specs` refuses a tracked `specs/` directory.

## Getting set up

You need Go at the version in [`go.mod`](go.mod) and `git`. Every check is
[`latere.ai/x/ci-gate`](https://github.com/latere-ai/ci-gate), pinned as a
tool in `go.mod`, so nothing else is installed and each check runs the same
on your machine as on a runner.

Install the hooks once per clone:

```bash
make hooks
```

The pre-commit hook checks that staged Go files are formatted and hold no
code the standard library already covers. The pre-push hook refuses a
release tag without a changelog section and runs the linter over the
packages the push changes.

## The bar

Every package meets these on its own:

- **Tests.** Every package has unit tests, and they pass under the race
  detector. A function that accepts a string or bytes from outside carries a
  fuzz target (`FuzzXxx`). Tests isolate themselves with `t.Setenv` and
  `t.Cleanup`, so no global state leaks between them.
- **Coverage of 90% or more per package**, not as a module average. An
  average lets a well-tested package carry an untested one: the module once
  passed at 95% overall while `pgxmigrate` sat at 82.1%. Exemptions would
  live in `.lateregate.yaml`, keyed by package with the reason as the value;
  there are none.
- **Few dependencies.** The standard library first. No test-only
  dependencies: `net/http/httptest` and the rest of the standard library
  cover what a test needs. A new direct dependency is justified in the pull
  request. `llmdialect` takes no module dependency at all, and nothing in the
  module uses cgo.
- **Hermetic tests.** The suite needs no database, no credentials, and no
  outbound network: HTTP tests run against `httptest` servers on loopback.
  Three packages drive real binaries on purpose (`cmdexec`, `gitutil`, and
  `hostsandbox`), and `.lateregate.yaml` names the two system directories
  they may reach.
- **A bug fix carries a test** that fails without the fix.

A few tests skip by design: platform limits (Windows file modes and
symlinks, running as root), the `hostsandbox` contract test where no `srt`
is installed, three `gitutil` cases that skip when the local git does not
reproduce the scenario they test, and the `typesafeai` test against the live API, which runs only when
`TYPESAFE_API_KEY` is set because it spends a request.

## Running the checks

```bash
make check          # every gate CI runs: go tool lateregate
make test           # go vet and go test
make race           # the suite under the race detector
make test-hermetic  # the suite with only the toolchain and the allowed directories on PATH
make cover          # the per-package coverage floor
make cover-html     # the coverage report in a browser
make fuzz           # every fuzz target, 30s each (FUZZTIME to change)
make validate       # no-tracked-specs, deps, cgo-free, vuln, and fuzz
make vuln           # govulncheck over what the module imports and calls
```

`go tool lateregate list` names the gates `make check` runs, and
`go tool lateregate <gate>` runs one.

CI runs the same gates on every push to `main` and every pull request,
through the shared workflow in
[`latere-ai/ci`](https://github.com/latere-ai/ci). Two checks of
`make validate` are not gates and run only locally: `fuzz` and
`no-tracked-specs`. Run `make validate` before a change to a fuzzed parser
or to the module layout.

## Writing

Every sentence is written for one reader, and the register follows the
reader: a user of the product, a contributor changing it, or a developer
debugging a running system. An error has one code, one fixed user sentence
in `message`, and one developer detail in a separate field. The rule and the
review checklist are in
[docs/writing/registers.md](docs/writing/registers.md), the canonical
statement for every Latere repository. Package documentation is read on
pkg.go.dev by people outside the organization, so it explains in its own
terms rather than citing internal documents.

## Sending a change

Open a pull request against `main`. Keep one logical change per commit and
write the subject as `scope: what changed`, in lowercase. Add a line under
`## Unreleased` in [CHANGELOG.md](CHANGELOG.md) in the same commit as the
change, in the consumer's words: what they gain, what breaks, and what to do
about it.

## Releasing

A tag is a release, and a release has notes. `CHANGELOG.md` keeps one
section per tag, and that section is the body of the GitHub release.

```bash
make release VERSION=vX.Y.Z
```

This moves the `Unreleased` notes under the version, commits, tags, and
pushes. The release workflow refuses a tag with no section, and so does the
pre-push hook. Both targets are names for `go tool lateregate release` and
`go tool lateregate release-notes`, the rule every Latere repository shares.
