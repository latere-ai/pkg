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
| [`authkit`](authkit/) | Product-agnostic authentication glue: one shared `Identity` type and `Authenticator` interface, so services share an implementation instead of maintaining drifting copies |
| [`batch`](batch/) | A generic non-blocking batching pump: producers add without blocking, one goroutine flushes by size or interval and drains on shutdown |
| [`email`](email/) | Transactional mail transport (Mailgun, SMTP, or a log-only fallback) that refuses header injection; subjects and bodies stay with the calling service |
| [`jwtauth`](jwtauth/) | JWKS-based RS256 JWT validation with key caching, so a service verifies tokens locally instead of round-tripping to the issuer |
| [`llmdialect`](llmdialect/) | Translation between LLM inference wire dialects (Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, lux-native) through a neutral intermediate representation, with an explicit loss report instead of silent drops |
| [`luxsdk`](luxsdk/) | First-party Go client for the Lux gateway's native dialect: typed generate, streaming, and token counting |
| [`md`](md/) | YAML frontmatter parsing and GFM-to-HTML rendering |
| [`oidc`](oidc/) | Relying Party client for the Latere auth service: PKCE, encrypted cookie sessions, token refresh, org switching, and a shared `/me` assembly |
| [`oidclogin`](oidclogin/) | Standard OIDC only, no vendor extensions: discovers an issuer, drives a browser PKCE login, and maps ID-token claims through a per-provider mapper. Point it at Keycloak, Google, Cognito, or Latere auth by configuration |
| [`otel`](otel/) | One-call OpenTelemetry bootstrap for traces, metrics, and structured logs, plus HTTP server and client instrumentation |
| [`pgxmigrate`](pgxmigrate/) | Applies embedded golang-migrate migrations and reliably closes migrate's own connection pool afterward |
| [`scopes`](scopes/) | Typed registry of the OAuth/RBAC scopes the Latere auth service issues, for call-site gating and OIDC discovery |

### Utilities

Smaller pieces with no product knowledge in them. Most were extracted once a
second service needed the same thing.

| Package | What it gives you |
|---|---|
| [`atomicfile`](atomicfile/) | Write-then-rename file replacement, so a reader never observes a half-written file |
| [`cache`](cache/) | Generic TTL cache with optional LRU bounding and an injectable clock |
| [`circuitbreaker`](circuitbreaker/) | Trip-on-failure gate that stops hammering a dependency that is already down |
| [`cmdexec`](cmdexec/) | Fluent subprocess builder and a transactional sequencer that rolls back completed steps when a later one fails |
| [`dag`](dag/) | Topological ordering with cycle detection |
| [`dircp`](dircp/) | Recursive directory copy |
| [`envutil`](envutil/) | Typed environment reads with defaults: integers, bounded integers, durations, and the conventional boolean spellings |
| [`gitutil`](gitutil/) | The git CLI behind structured results and typed errors: worktrees, rebase with conflict recovery, stashes, branch discovery |
| [`httpjson`](httpjson/) | Strict JSON request decoding (unknown fields and trailing content rejected) and response writing |
| [`keyedmu`](keyedmu/) | Per-key mutex, so unrelated keys do not serialize against each other |
| [`lazyval`](lazyval/) | Once-computed value with error memoization |
| [`metrics`](metrics/) | Prometheus text-exposition registry with labeled counters, histograms, and scrape-time gauges, with no client-library dependency |
| [`ndjson`](ndjson/) | NDJSON file reading and appending, plus the terminal-result scan agent output parsers need |
| [`pagination`](pagination/) | Cursor pagination helpers |
| [`pubsub`](pubsub/) | In-process topic fanout with per-subscriber buffering |
| [`registry`](registry/) | Generic slug-keyed registry |
| [`routine`](routine/) | Periodic fire-and-forget callbacks keyed by UUID, one timer each, with an injectable clock |
| [`sanitize`](sanitize/) | Rune-safe display truncation and container-safe slug generation |
| [`set`](set/) | Generic set |
| [`slugutil`](slugutil/) | Kebab-case identifier validation |
| [`sortedkeys`](sortedkeys/) | Deterministic map iteration |
| [`statemachine`](statemachine/) | Declarative transition table with guarded moves |
| [`syncmap`](syncmap/) | Type-safe `sync.Map` |
| [`tail`](tail/) | Last-n elements of a slice, without copying |
| [`trackedwg`](trackedwg/) | Wait group that reports what is still outstanding |
| [`tree`](tree/) | Generic tree construction and rendering |
| [`uuidutil`](uuidutil/) | UUID parsing helpers |
| [`watcher`](watcher/) | Filesystem change notification with debouncing |

Package-level documentation, including the streaming grammar and per-provider
notes, is on [pkg.go.dev](https://pkg.go.dev/latere.ai/x/pkg).

## Status

The module is at `v0.x`. The API is not frozen: a minor version bump may
contain a breaking change, so pin an exact version and read the release notes
before upgrading. Package layout and the module path are stable.

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
make test       # run tests
make race       # run tests with the race detector
make fuzz       # run every fuzz target for 30s (FUZZTIME to change)
make cover      # run tests and enforce the 95% statement-coverage floor
make cover-html # open the coverage report in a browser
make vuln       # fail on vulnerabilities in imported or called code
```

CI runs the race detector, the coverage floor, the toolchain modernizers, the
fuzz targets, and a vulnerability scan on pushes to `main` and on every
pull request. `make
cover` needs `bc`; `make vuln` needs `jq` and installs `govulncheck` if it is
not already present.

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
