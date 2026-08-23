# pkg

Go building blocks shared across [Latere AI](https://latere.ai) services: OIDC
and JWT authentication, LLM wire-dialect translation, OpenTelemetry setup,
audit events, transactional email, and Postgres migrations. Every package is
importable on its own, standard-library-first, and carries its own tests.

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
| [`oidc`](oidc/) | OIDC Relying Party client with PKCE, encrypted cookie sessions, token refresh, and a shared `/me` assembly |
| [`oidclogin`](oidclogin/) | Portable, IDP-agnostic Relying Party for the browser Authorization Code + PKCE flow; point it at any RS256 issuer by configuration |
| [`otel`](otel/) | One-call OpenTelemetry bootstrap for traces, metrics, and structured logs, plus HTTP server and client instrumentation |
| [`pgxmigrate`](pgxmigrate/) | Applies embedded golang-migrate migrations and reliably closes migrate's own connection pool afterward |
| [`scopes`](scopes/) | Typed registry of the OAuth/RBAC scopes the Latere auth service issues, for call-site gating and OIDC discovery |

Package-level documentation, including the streaming grammar and per-provider
notes, is on [pkg.go.dev](https://pkg.go.dev/latere.ai/x/pkg).

## Status

The module is at `v0.x`. The API is not frozen: a minor version bump may
contain a breaking change, so pin an exact version and read the release notes
before upgrading. Package layout and the module path are stable.

## Testing

The suite is hermetic. No database, no network access, and no credentials are
required, and nothing is skipped for missing configuration:

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
