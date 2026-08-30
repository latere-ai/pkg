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

- **Every package** must be at **>= 90%**, which is stricter than a module
  average even though the number is lower: an average lets one package sit
  under the line while the others carry it, which is how `pgxmigrate` ran at
  82.1% behind a passing 95%.
- CI enforces it per package; exemptions live in `.lateregate.yaml` and the
  value in the map is the reason, so an entry cannot exist without one.
- Use package-level function variables for external constructors to make error paths testable without adding dependencies.

### Dependencies

- Minimize external dependencies. Prefer the standard library.
- Do not add test-only dependencies — use `net/http/httptest`, `errors`, etc. from stdlib.
- When adding a new direct dependency, justify it.

## Commands

```
make test           # go vet + go test
make test-race      # run tests with race detector
make test-hermetic  # run tests with only the toolchain on PATH
make fuzz           # run fuzz tests (30s)
make cover          # enforce a 90% floor per package
make cover-html     # open coverage report in browser
make validate       # no-tracked-specs, deps, cgo-free, vuln, fuzz
```
