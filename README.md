# pkg

Go packages shared across [Latere AI](https://latere.ai) services:
authentication and authorization, egress credential substitution, LLM
wire-dialect translation, telemetry, audit events, object storage,
transactional email, Postgres migrations, git and subprocess execution, and
a set of small concurrency and text utilities. Every package is importable on
its own, keeps its dependency surface small, and carries its own tests.

[![CI](https://github.com/latere-ai/pkg/actions/workflows/ci.yml/badge.svg)](https://github.com/latere-ai/pkg/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/latere.ai/x/pkg.svg)](https://pkg.go.dev/latere.ai/x/pkg)
[![Go version](https://img.shields.io/github/go-mod/go-version/latere-ai/pkg)](go.mod)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Install

The module path is `latere.ai/x/pkg`; the source lives at
`github.com/latere-ai/pkg`.

```bash
go get latere.ai/x/pkg
```

Import the package you need, not the module root:

```go
import "latere.ai/x/pkg/md"
```

The whole module is pure Go with no cgo, so it cross-compiles anywhere the Go
toolchain does.

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
c := luxsdk.New("https://api.latere.ai/v1/models", luxsdk.WithAPIKey(key))
res, err := c.Generate(ctx, &luxsdk.Request{
	Model:    "claude-sonnet-5",
	Messages: []luxsdk.Message{luxsdk.UserText("hello")},
})
```

## Packages

Each row links to the package directory. The full API, with examples, is on
[pkg.go.dev](https://pkg.go.dev/latere.ai/x/pkg).

### Services and protocols

| Package | What it gives you |
|---|---|
| [`agentweb`](agentweb/) | A site's public pages for crawlers and AI agents: robots.txt with Content Signals usage preferences, a sitemap with hreflang alternates, llms.txt and a streamed llms-full.txt, and middleware that answers `Accept: text/markdown` with the page's Markdown twin, all rendered from one page index. Standard library only. See [`agentweb/README.md`](agentweb/README.md) |
| [`audit`](audit/) | The canonical audit-event envelope, the `Emitter` interface products compose behind `MultiEmitter`, a stdout emitter, and redaction helpers. Storage adapters stay in each product |
| [`authkit`](authkit/) | Authentication. The root holds the shared `Identity` type, the `Authenticator` interface, the grants a personal access token carries, and the middleware services share. `authkit/jwt` verifies RS256 and ES256 tokens offline against a cached JWKS; `authkit/oidc` is the OIDC relying party with cookie sessions, token refresh, and the login handlers; `authkit/cli` is the token store and device-code login for command-line clients; `authkit/issuertest` is a stub issuer for tests; `authkit/conformance` is the verification suite a service runs against its own authenticator |
| [`authz`](authz/) | The authorizer contract the open cores share: the request and decision envelope, a client with caching and fail-closed rules, the owner policy a self-hosted core falls back to, and a core's action table as data. A decision is narrowed by the grants the caller's credential carries. `authz/server` is the scaffold an authorization endpoint is written on, `authz/stub` a stub endpoint for test tiers, and `authz/conformance` the suite every endpoint passes |
| [`drive`](drive/) | Client for the Drive workspace HTTP contract: attach, materialize, write back, lease renewal, and paginated lists, with a bearer resolved per request and typed errors |
| [`egress`](egress/) | Credential substitution at an egress boundary: a workload holds an opaque placeholder, and the gateway swaps it for the real secret only toward the hosts the credential is scoped to. The substitution engine, static and minted secrets, an ingest API and client, JWT proxy authentication, and a TLS-terminating CONNECT gateway. `egress/placeholder` mints and recognizes placeholders with the standard library alone |
| [`email`](email/) | Transactional mail over Mailgun or SMTP, with a log-only fallback; refuses header injection. Subjects and bodies stay with the calling service |
| [`health`](health/) | The probe surface a service serves on its internal listener: `/livez`, `/readyz` with named checks, `/version`, and `/metrics`. Why two probes and how to move a service is in [`docs/health.md`](docs/health.md) |
| [`hostsandbox`](hostsandbox/) | Runs a process on the operator's own machine inside an `srt` sandbox (Seatbelt on macOS, bubblewrap on Linux), detached, with output written where the process cannot reach it, and a handle that survives a restart. `hostsandbox/hostsandboxtest` is the contract every driver is held to |
| [`llmdialect`](llmdialect/) | Translation between LLM wire dialects (Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, and the Lux-native dialect) through a neutral intermediate representation, with an explicit loss report instead of silent drops. Standard library only. `llmdialect/bridge` translates requests, responses, and streams with no server in between; `llmdialect/tokencount` estimates input tokens without a tokenizer |
| [`llmjson`](llmjson/) | Repairs the JSON a model meant to send: strips a Markdown fence and escapes raw newlines and tabs inside strings, so a correct answer in the wrong encoding still decodes |
| [`luxsdk`](luxsdk/) | Go client for the Lux gateway's native dialect: typed generate, streaming, and token counting, or the same calls straight to a provider. See [`luxsdk/README.md`](luxsdk/README.md) |
| [`md`](md/) | YAML frontmatter parsing and GitHub Flavored Markdown to HTML. See [`md/README.md`](md/README.md) |
| [`otel`](otel/) | One-call OpenTelemetry setup for traces, metrics, and structured logs, HTTP server and client instrumentation, child spans, and a same-origin relay for browser telemetry. See [`otel/README.md`](otel/README.md) |
| [`pgxmigrate`](pgxmigrate/) | Applies embedded golang-migrate migrations and closes migrate's own connection pool afterward |
| [`provenance`](provenance/) | Carries the person a call is for across service hops as W3C Baggage (`initiator.sub`, `initiator.iss`, `entry`) and puts it on spans, log lines, and audit records. Metadata only: it grants nothing |
| [`s3`](s3/) | S3 REST client in the standard library: put, create-if-absent, conditional get, head, delete, prefixed listing, and presigned GET and PUT, signed with Signature Version 4 and retried under `retry`. `s3/s3test` is an in-process endpoint for tests that checks signatures and digests the way a provider does |
| [`typesafeai`](typesafeai/) | Unofficial client for the TypeSafe API: one state evaluated against typed questions (a yes/no probability, a choice from a set, or a score against a rubric). The package name is `typesafe` |

### Utilities

Smaller pieces with no product knowledge in them.

| Package | What it gives you |
|---|---|
| [`atomicfile`](atomicfile/) | Write-then-rename file replacement, so a reader never observes a half-written file |
| [`batch`](batch/) | A non-blocking batching pump: producers add without blocking, and one goroutine flushes by size or interval and drains on shutdown |
| [`bearer`](bearer/) | Reads the token from `Authorization: Bearer` with a case-insensitive scheme, and compares tokens in constant time |
| [`cache`](cache/) | Generic TTL cache with an optional LRU cap over every entry and an injectable clock |
| [`circuitbreaker`](circuitbreaker/) | Two breakers: a lock-free closed, open, and half-open breaker for hot paths, and a mutex-based breaker with exponential backoff |
| [`cmdexec`](cmdexec/) | Fluent subprocess builder, and a sequencer that rolls back completed steps when a later one fails |
| [`dag`](dag/) | Graph operations over adjacency lists: deterministic topological sort, cycle detection, reachability, longest path, edge reversal |
| [`dircp`](dircp/) | Recursive directory copy |
| [`envutil`](envutil/) | Typed environment reads with defaults: integers, bounded integers, durations, and the conventional boolean spellings |
| [`errwriter`](errwriter/) | A writer that remembers the first error, so a run of writes is checked once |
| [`gitutil`](gitutil/) | The git command line behind structured results and typed errors: worktrees, rebase with conflict recovery, stashes, branch discovery |
| [`hostmatch`](hostmatch/) | One host allow-list rule: exact names and `*.` wildcards that match any subdomain depth but never the apex |
| [`httpjson`](httpjson/) | Strict JSON request decoding (unknown fields and trailing content rejected), response writing, and the `{"error": {code, message, details}}` envelope |
| [`metrics`](metrics/) | Prometheus text-exposition registry with labeled counters, histograms, and scrape-time gauges, and no client-library dependency |
| [`ndjson`](ndjson/) | Reading and appending newline-delimited JSON files, and the terminal-result scan agent output parsers need |
| [`pagination`](pagination/) | Cursor pagination over a pre-sorted slice |
| [`pubsub`](pubsub/) | Generic in-process fan-out hub with a bounded replay buffer, so a subscriber that reconnects picks up where it left off |
| [`ratelimit`](ratelimit/) | Keyed token buckets with refill, burst, per-key rates, retry delay, and idle eviction that cannot reset a quota |
| [`relpath`](relpath/) | Traversal-safe relative paths: validate, join under a base, and symlink-aware containment |
| [`retry`](retry/) | Bounded exponential backoff with jitter, and optional per-attempt deadlines under the caller's total budget |
| [`routine`](routine/) | Periodic fire-and-forget callbacks keyed by UUID, one timer each, with an injectable clock |
| [`sanitize`](sanitize/) | Rune-safe display truncation, byte-budget truncation that never splits a rune, slug generation, and slug validation |
| [`semaphore`](semaphore/) | Cancellable admission for concurrent work, with a wait deadline and an idempotent release |
| [`statemachine`](statemachine/) | Generic finite state machine that validates each transition against a table |
| [`syncmap`](syncmap/) | Type-safe `sync.Map`, with `LoadOrStore` for the per-key mutex idiom |
| [`trackedwg`](trackedwg/) | Wait group that reports which labeled goroutines are still outstanding |
| [`tree`](tree/) | Generic rooted tree with parent-child links, a key index, and a walk |
| [`uniq`](uniq/) | Order-preserving deduplication, a trim-and-drop-empties form for string lists, and a catalog merge that rejects a repeated key |
| [`wait`](wait/) | Cancellable sleep, ticker loop, and poll. `wait/waittest` polls a condition in a test until it holds |
| [`watcher`](watcher/) | Event loop for a background goroutine woken by a signal, a ticker, or both, with an optional settle delay before it acts |

## Stability

The module is at `v0.x`, and the API is not frozen: a minor version may carry
a breaking change. Pin an exact version and read its section of
[CHANGELOG.md](CHANGELOG.md) before upgrading; every tag has one, and a
breaking change says what to do about it. The module path and the package
layout are stable.

## Documentation

- [pkg.go.dev](https://pkg.go.dev/latere.ai/x/pkg): the API of every package.
- [`agentweb`](agentweb/README.md), [`luxsdk`](luxsdk/README.md),
  [`md`](md/README.md), and [`otel`](otel/README.md) carry a usage guide
  beside the code.
- [`docs/health.md`](docs/health.md): the probe paths and how to adopt them.
- [`docs/writing/registers.md`](docs/writing/registers.md): the writing rule
  for everything a Latere product emits, and the canonical statement that
  every Latere repository points to.

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) says
what belongs in this module, the bar a package meets, how to run the checks
locally, and how a release is cut.

## License

[Apache 2.0](LICENSE)
