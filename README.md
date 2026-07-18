# pkg

Platform-wide Go packages for [Latere AI](https://latere.ai).

## Packages

| Package | Description |
|---|---|
| [`audit`](audit/) | Canonical audit-event envelope and the shared emitters (stdout, OTLP) products serialize it through |
| [`authkit`](authkit/) | Product-agnostic authentication glue: the shared Identity type and Authenticator interface every service builds on |
| [`batch`](batch/) | Generic non-blocking batching pump: producers add without blocking, one goroutine flushes by size or interval |
| [`jwtauth`](jwtauth/) | JWKS-based RS256 JWT validation for services accepting auth-issued tokens |
| [`llmdialect`](llmdialect/) | Translation between LLM inference wire dialects (Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, lux-native) through a neutral intermediate representation |
| [`luxsdk`](luxsdk/) | First-party Go client for the Lux gateway's native dialect: typed generate, streaming, and token counting |
| [`md`](md/) | YAML frontmatter parsing and GFM-to-HTML rendering |
| [`oidc`](oidc/) | OIDC Relying Party client for the auth service with PKCE, encrypted cookie sessions, and token refresh |
| [`oidclogin`](oidclogin/) | Portable, IDP-agnostic OAuth 2.0 / OIDC Relying Party for the browser Authorization Code + PKCE flow |
| [`otel`](otel/) | OpenTelemetry tracing, metrics, and HTTP instrumentation |
| [`pgxmigrate`](pgxmigrate/) | Runs embedded golang-migrate migrations and reliably closes migrate's own connection pool afterward |
| [`scopes`](scopes/) | Source of truth for every OAuth/RBAC scope the auth service can issue |

## Development

```bash
make test       # run tests
make race       # run tests with race detector
make fuzz       # run fuzz tests (30s)
make cover      # run tests with coverage (95% minimum enforced)
make cover-html # open coverage report in browser
```

## License

[MIT](LICENSE)
