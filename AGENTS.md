# pkg

Platform-wide Go packages for Latere AI.

## Gold Standards

Every package in this repo must meet these requirements:

### Testing

- All packages must have `_test.go` files with unit tests.
- Run tests with the race detector: `go test -race ./...`
- Include fuzz tests (`FuzzXxx`) for functions that accept string or byte inputs.
- Use `t.Setenv` and `t.Cleanup` for test isolation — no global state leaks between tests.

### Coverage

- **Every package** must be at **>= 90%**. The floor is per package, not a
  module average: an average lets one package sit under the line while the
  others carry it.
- CI enforces it per package. Exemptions live in `.lateregate.yaml`, keyed by
  package with the reason as the value, so an entry cannot exist without one.
- Use package-level function variables for external constructors to make error paths testable without adding dependencies.

### Dependencies

- Minimize external dependencies. Prefer the standard library.
- Do not add test-only dependencies — use `net/http/httptest`, `errors`, etc. from stdlib.
- When adding a new direct dependency, justify it.

## Before writing a package

Check this module first. A generic package with a plausible second
consumer is written here first, at this module's bar, and consumed from
here; a product's `internal/` holds only what is specific to that
product. Extraction happens when the second consumer appears, not later:
the third copy is the one that drifts. What "generic" means in practice:
an S3 client, a metrics registry, an error envelope, a probe surface, a
retry loop, a host allow-list, a cancellable sleep. What stays in a
product: its error codes, its contract header, its store interface, its
configuration.

## Writing

Every sentence is written for one reader, and the register follows the
reader: user, contributor, or developer. An error has one code, one fixed
user sentence in `message`, and one developer detail in a separate field.
The rule and the review checklist are in
[docs/writing/registers.md](docs/writing/registers.md); it is the canonical
statement for every Latere repository.

## Commands

```
make test           # go vet + go test
make test-race      # run tests with race detector
make test-hermetic  # run tests with only the toolchain on PATH
make fuzz           # run fuzz tests (30s)
make cover          # enforce a 90% floor per package
make cover-html     # open coverage report in browser
make validate       # no-tracked-specs, deps, cgo-free, vuln, fuzz
make release VERSION=vX.Y.Z   # move Unreleased notes under the version, commit, tag, push
```

## Releases

A tag is a release, and a release has notes. `CHANGELOG.md` keeps one
section per tag; the release workflow and the pre-push hook both refuse a
tag without one. Add notes under `## Unreleased` in the same commit as the
change they describe, in the audience's words: what a consumer gains, what
breaks, what to do about it.
