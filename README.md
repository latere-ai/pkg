# pkg

Go building blocks shared across [Latere AI](https://latere.ai) services:
authentication, LLM wire-dialect translation, telemetry, audit events,
transactional email, Postgres migrations, git and subprocess execution, and a
set of small concurrency and text utilities. Every package is importable on its
own, keeps its dependency surface small, and carries its own tests.

[![CI](https://github.com/latere-ai/pkg/actions/workflows/ci.yml/badge.svg)](https://github.com/latere-ai/pkg/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/latere.ai/x/pkg.svg)](https://pkg.go.dev/latere.ai/x/pkg)
[![Go version](https://img.shields.io/github/go-mod/go-version/latere-ai/pkg)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Install

The module path is `latere.ai/x/pkg`. The source lives at
`github.com/latere-ai/pkg`.

```bash
go get latere.ai/x/pkg
```

Import the package you need, not the module root:

```go
import "latere.ai/x/pkg/md"
```

## Quick start

Parse frontmatter and render Markdown:

```go
package main

import (
	"fmt"
	"log"

	"latere.ai/x/pkg/md"
)

func main() {
	src := []byte("---\ntitle: Notes\n---\n\n# Hello\n\nSome *text*.\n")

	var meta struct{ Title string }
	body, err := md.ParseInto(src, &meta)
	if err != nil {
		log.Fatal(err)
	}

	html, err := md.Render(body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(meta.Title)
	fmt.Println(string(html))
}
```

Call the Lux gateway with a typed request:

```go
c := luxsdk.New("https://lux.latere.ai", luxsdk.WithAPIKey(key))
res, err := c.Generate(ctx, &luxsdk.Request{
	Model:    "claude-sonnet-5",
	Messages: []luxsdk.Message{luxsdk.UserText("hello")},
})
```

## Packages

### Infrastructure

| Package | What it gives you |
|---|---|
| [`audit`](audit/) | A canonical audit-event envelope plus emitters (stdout, OTLP) to serialize it through, so storage adapters stay a per-product concern |
| [`authkit`](authkit/) | The auth tree. The root holds the one `Identity` type, the `Authenticator` interface, and the middleware every service shares; `authkit/jwt` verifies RS256 tokens against a cached JWKS and authenticates bearer JWTs; `authkit/oidc` is the OIDC relying party with a `Provider` for any standard issuer (Latere auth, Keycloak, Google, Cognito) and the Latere `Client` with encrypted cookie sessions, token refresh, org switching, and a shared `/me` assembly; `authkit/cli` holds the token store and device-code login for command-line clients |
| [`batch`](batch/) | A generic non-blocking batching pump: producers add without blocking, one goroutine flushes by size or interval and drains on shutdown |
| [`email`](email/) | Transactional mail transport (Mailgun, SMTP, or a log-only fallback) that refuses header injection; subjects and bodies stay with the calling service |
| [`llmdialect`](llmdialect/) | Translation between LLM inference wire dialects (Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, lux-native) through a neutral intermediate representation, with an explicit loss report instead of silent drops. Carries provider-executed tools (web search, web fetch) alongside the caller-implemented kind |
| [`llmjson`](llmjson/) | Repairs the JSON a model meant to send: strips a markdown fence and escapes the raw newlines and tabs left inside string values, so a correct answer in the wrong encoding still decodes |
| [`luxsdk`](luxsdk/) | First-party Go client for the Lux gateway's native dialect: typed generate, streaming, and token counting |
| [`md`](md/) | YAML frontmatter parsing and GFM-to-HTML rendering |
| [`otel`](otel/) | One-call OpenTelemetry bootstrap for traces, metrics, and structured logs, plus HTTP server and client instrumentation |
| [`pgxmigrate`](pgxmigrate/) | Applies embedded golang-migrate migrations and reliably closes migrate's own connection pool afterward |
| [`scopes`](scopes/) | Typed registry of the OAuth/RBAC scopes the Latere auth service issues, for call-site gating and OIDC discovery |

### Utilities

Smaller pieces with no product knowledge in them. Most were extracted once a
second service needed the same thing.

| Package | What it gives you |
|---|---|
| [`atomicfile`](atomicfile/) | Write-then-rename file replacement, so a reader never observes a half-written file |
| [`bearer`](bearer/) | Token extraction from `Authorization: Bearer` with the RFC 7235 case-insensitive scheme, and constant-time comparison |
| [`cache`](cache/) | Generic TTL cache with a bounded LRU cap over every entry and an injectable clock |
| [`circuitbreaker`](circuitbreaker/) | Trip-on-failure gate that stops hammering a dependency that is already down |
| [`cmdexec`](cmdexec/) | Fluent subprocess builder and a transactional sequencer that rolls back completed steps when a later one fails |
| [`dag`](dag/) | Topological ordering with cycle detection |
| [`dircp`](dircp/) | Recursive directory copy |
| [`envutil`](envutil/) | Typed environment reads with defaults: integers, bounded integers, durations, and the conventional boolean spellings |
| [`gitutil`](gitutil/) | The git CLI behind structured results and typed errors: worktrees, rebase with conflict recovery, stashes, branch discovery |
| [`httpjson`](httpjson/) | Strict JSON request decoding (unknown fields and trailing content rejected) and response writing |
| [`metrics`](metrics/) | Prometheus text-exposition registry with labeled counters, histograms, and scrape-time gauges, with no client-library dependency |
| [`ndjson`](ndjson/) | NDJSON file reading and appending, plus the terminal-result scan agent output parsers need |
| [`pagination`](pagination/) | Cursor pagination helpers |
| [`pubsub`](pubsub/) | In-process topic fanout with per-subscriber buffering |
| [`registry`](registry/) | Generic slug-keyed registry |
| [`relpath`](relpath/) | Traversal-safe relative paths: validate, join under a base, and symlink-aware containment |
| [`retry`](retry/) | Bounded exponential backoff with jitter and a driver that runs a function under it |
| [`routine`](routine/) | Periodic fire-and-forget callbacks keyed by UUID, one timer each, with an injectable clock |
| [`sanitize`](sanitize/) | Rune-safe display truncation, byte-budget truncation that never splits a rune, slug generation, and slug validation |
| [`statemachine`](statemachine/) | Declarative transition table with guarded moves |
| [`syncmap`](syncmap/) | Type-safe `sync.Map`, with `LoadOrStore` for the per-key mutex idiom |
| [`trackedwg`](trackedwg/) | Wait group that reports what is still outstanding |
| [`tree`](tree/) | Generic tree construction and rendering |
| [`uniq`](uniq/) | Order-preserving deduplication, with a trim-and-drop-empties form for string lists |
| [`wait`](wait/) | Cancellable sleep, ticker loop, and poll; `wait/waittest` polls a condition in a test until it holds |
| [`watcher`](watcher/) | Filesystem change notification with debouncing |

Package-level documentation, including the streaming grammar and per-provider
notes, is on [pkg.go.dev](https://pkg.go.dev/latere.ai/x/pkg).

## Status

The module is at `v0.x`. The API is not frozen: a minor version bump may
contain a breaking change, so pin an exact version and read the release notes
before upgrading. Package layout and the module path are stable.

## Releasing

Every tag has a section in [CHANGELOG.md](CHANGELOG.md), and that section is
the body of the GitHub release. Write notes under `Unreleased` as changes
land, then:

```bash
make release VERSION=v0.50.0
```

This moves the `Unreleased` notes under the version, commits, tags, and
pushes. The release workflow refuses a tag with no section, and the
pre-push hook installed by `make hooks` refuses to push one.

## Testing

The suite is hermetic. It needs no database, no credentials, and no outbound
network access (HTTP tests run against `httptest` servers on loopback), and
nothing is skipped for missing configuration:

```bash
go test ./...
```

The only conditional skips are two filesystem cases in `authkit` that cannot
run where the OS resolves a user config directory without consulting env vars,
or where changing a temporary directory's mode has no effect. Everything else
runs everywhere.

```bash
make test           # go vet + go test
make test-race      # run tests with the race detector
make test-hermetic  # run tests with only the toolchain on PATH
make cover          # enforce a 90% floor per package
make cover-html     # open the coverage report in a browser
make fuzz           # run every fuzz target for 30s (FUZZTIME to change)
make validate       # the checks specific to what this module promises
make vuln           # fail on vulnerabilities in imported or called code
```

**`make cover` gates each package, not the module.** An average lets a
well-tested package carry an untested one: this module passed at 95% overall
while `pgxmigrate` sat at 82.1%, invisible behind it. All 48 packages clear
90% on their own.

**`make test-hermetic` runs the suite with `PATH` stripped** to the Go
toolchain and the directories `.lateregate.yaml` names. A test that depends on
what happens to be installed passes on a laptop and fails on a runner, which
is the worst order to find out. Two packages here legitimately drive real
binaries — `cmdexec` and `gitutil` — and the config says so.

**`make validate`** is `no-tracked-specs`, `deps`, `cgo-free`, `vuln` and
`fuzz`: no internal specs in this public module, `llmdialect` staying
stdlib-only, no cgo anywhere, and the two scans.

CI runs all of it on pushes to `main` and on every pull request, through the
shared pipeline in
[`latere-ai/ci`](https://github.com/latere-ai/ci). The checks themselves are
[`latere.ai/x/ci-gate`](https://github.com/latere-ai/ci-gate), pinned as a tool
dependency in `go.mod`, so every gate runs the same here as on a runner — a
gate you can only run in CI tells you too late. `make vuln` needs `jq` and
installs `govulncheck` if it is not already present.

## Contributing

Issues and pull requests are welcome. A change is easiest to accept when it
keeps the dependency surface small (standard library first), comes with tests,
and holds the coverage floor that CI checks.

Install the formatting hook once per clone:

```bash
make hooks
```

## License

[MIT](LICENSE)
