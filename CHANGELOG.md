# Changelog

Every tag has a section here, and the section is the body of the GitHub
release. A tag without one fails the release workflow, and `make release`
refuses to create it. Write under `Unreleased` as work lands; `make release
VERSION=vX.Y.Z` turns that into the tag's section.

The module is at `v0.x`: a minor bump may contain a breaking change, listed
under **Removed** or **Changed** with what to do about it.

## Unreleased

The three auth packages are now one tree under `authkit`, with one
principal type. Update imports, then the handful of renamed symbols below.
Every browser session logs in again once after the relying party deploys.

### Changed

- `jwtauth` is now `authkit/jwt` and `oidc` is now `authkit/oidc`. Replace
  the import paths and the `jwtauth.` qualifier with `jwt.`; no symbol
  changed its name in the move. A local variable named `jwt` shadows the
  package for the rest of its function, so rename it.
- `authkit.Identity` is the one principal. `jwt.Claims` embeds it and adds
  the token envelope (`Iss`, `Aud`, `Exp`); `oidc.User` embeds it and adds
  the profile (`Name`, `Picture`, `DisplayName`, `Raw`). Field reads such
  as `claims.Sub` and `user.OrgID` are unchanged. A composite literal that
  sets those fields compiles as before on Go 1.27.
- `Identity.PrincipalType` is the named type `authkit.PrincipalType`, with
  `PrincipalUser`, `PrincipalService`, `PrincipalAgent`, and `PrincipalDev`.
  `jwt.PrincipalType`, `jwt.PrincipalUser`, and `jwt.PrincipalService` are
  aliases. Comparisons against string literals still compile.
- `Identity` carries JSON tags (`sub`, `org_id`, `roles`, ...). `TokenID`
  and `AuthMethod` are never serialised.
- `oidc.User.OrgRoles` is the embedded `Roles`; `oidc.User.AvatarURL` is
  gone, read `Picture`. The `avatar_url` access-token claim still feeds
  `Picture` when `picture` is absent.
- `oidc.ClaimsMapper.Map` and `Provider.VerifyIDToken` return `oidc.User`;
  `oidc.Identity` is deleted and its `Subject` is `Sub`. A verified ID token
  that maps to no subject is rejected.
- `oidc.SessionCookieName` is `__Host-latere-session-v2`. A session written
  under the previous shape stored roles under another key, so it is not
  read; users sign in once more after deploy.
- `jwt.Validator.Middleware` also stores the principal through
  `authkit.WithIdentity`, so `authkit.IdentityFromContext` works behind it.
- `authkit` imports no other auth package. The two authenticators that
  needed one moved to where they are produced: `authkit.NewJWT` is
  `jwt.NewAuthenticator` (type `jwt.Authenticator`), and
  `authkit.NewSessionAuthenticator` is `oidc.NewSessionAuthenticator`.
  `authkit.TokenInfo`, `TokenInfoClient`, `CachedTokenInfo`,
  `TokenInfoLookup`, and `ErrRevoked` moved to `jwt` unchanged.
- `authkit.FileTokenStore`, `TokenStore`, `DefaultFileTokenStorePath`,
  `DeviceCodeClient`, and `NewDeviceCodeClient` moved to `authkit/cli`, the
  only package in the tree that opens a browser or touches the home
  directory.
- `jwtauth.WriteUnauthorized` is `authkit.WriteUnauthorized`;
  `oidc.SplitScopes` is `authkit.SplitScopes`.
- Error strings from the JWT package start with `authkit/jwt:`; sentinel
  errors are unchanged.

## v0.52.0 - 2026-09-06

### Changed

- `llmdialect/anthropic`: the backend encodes structured output as
  `output_config.format`; the top-level `output_format` member is retired
  API-wide and no longer emitted. The frontend decodes both spellings, and
  `output_config` is a known request key rather than a loss.

### Added

- `llmdialect/anthropic.BackendOptions.DropSampling`: omit `temperature`,
  `top_p`, and `top_k` from the body and record each one the caller set in
  the loss report. Set it for models that reject sampling parameters with a
  400 (Claude Opus 4.7 and later, Claude Sonnet 5, Claude Fable 5); the
  codec carries no model table, the gateway decides per model.
- `llmdialect/ir.LossTopP`, the loss field for a dropped `top_p`.
- `luxsdk.Effort`, the reasoning effort type, alongside the effort constants
  it already re-exported.

## v0.51.0 - 2026-09-05

### Changed

- Every outbound HTTP client the module builds carries the otel transport:
  `authkit.NewTokenInfoClient`, `jwtauth`'s JWKS fetch, `luxsdk`'s default
  client, the `oidc` token exchange, discovery and userinfo calls, and the
  `otel` telemetry relay. A downstream span now joins the caller's trace
  instead of opening a new one. Nothing changes for a caller that supplied
  its own client.
- `oidc` and `authkit` log through the `*Context` slog variants on the
  request path, so the otelslog bridge stamps trace and span ids on the
  records.

### Fixed

- `llmdialect/anthropic`: the backend now carries
  `usage.output_tokens_details.thinking_tokens` into `ir.Usage.ReasoningTokens`.
  A Responses-dialect caller (codex) driving an Anthropic model through the
  compat surface saw `reasoning_tokens: 0` on every call even when the model
  thought, and could not tell an ignored effort from an applied one. Streaming
  and non-streaming responses both pick it up; `output_tokens` is unchanged
  (thinking was always included in it).
- `relpath.Contains`: resolve symlinks before parent traversal (`link/..`),
  preventing paths from being accepted under a different directory than the
  one the filesystem actually accesses.

- `pubsub`: concurrent publishers preserve sequence order in replay and live
  delivery, so reconnecting consumers do not skip events. `LatestSeq` no
  longer advances before the event is available.

- `circuitbreaker`: a half-open probe stays exclusive until it reports a
  result, even when the cooldown elapses while the probe is still running.

- `dircp.CopyFile`: copying onto the source, a hard link, or a symlink to it
  returns an error without destroying the source contents.

- `dircp`: the Go fallback creates the destination directory, including for
  empty sources, and reports invalid source or destination roots as errors.

- `relpath`: containment checks accept children of `.` and filesystem roots,
  and reject unresolved symlinks instead of treating them as missing paths.

- `cache`: a `SetPermanent` insert no longer lets an expired TTL entry take a
  `MaxSize` slot and evict a live key.

## v0.50.0 - 2026-09-01

### Changed

- `oidc` is the one OIDC relying party. `oidclogin` moved in as
  `Provider`, `ProviderConfig`, `NewProvider`, `Identity`, `ClaimsMapper`,
  and the `LatereMapper`, `KeycloakMapper`, `GoogleMapper`, and
  `CognitoMapper` mappers. `ProviderConfig.Provider` is now `Kind`.
  `Provider.AuthCodeURL` takes extra `oauth2.AuthCodeOption`s after the
  verifier. The Latere `Client` is built on a `Provider`, and
  `HandleCallback` now verifies the ID token the exchange returns against
  the auth service's JWKS and rejects a nonce that does not match the
  login. Replace `oidclogin.New` with `oidc.NewProvider`.

### Removed

- `oidclogin`. Import `oidc`.

## v0.49.0 - 2026-09-01

The first release note since v0.7.4. That tag held three packages: `md`,
`oidc`, and `otel`. This one holds 39. Forty-one tags in between were cut
without notes, so this section covers the whole range.

### Added

Authentication and identity:

- `authkit`: one `Identity` and one `Authenticator` interface for every
  service, with JWT, session-cookie, static-token, dev-bypass, and
  device-code authenticators, CSRF issue and validate, a `TokenStore`
  with a file implementation, and a cached token-info client.
- `jwtauth`: JWKS-backed RS256 validation with a key cache that serves
  stale keys on fetch failure, refreshes on an unknown `kid`, checks
  `nbf`, and never holds its lock across the network. `ParseUnverified`
  and `DecodePayload` for claims that arrived over a trusted channel.
- `bearer`: `Authorization: Bearer` extraction with the case-insensitive
  scheme RFC 7235 requires, and a constant-time `Equal`.
- `scopes`: the typed registry of every OAuth/RBAC scope the auth service
  issues.
- `oidclogin`: a provider-agnostic OIDC relying party with claim mappers
  for Latere, Keycloak, Google, and Cognito.

LLM plumbing:

- `llmdialect`: translation between Anthropic Messages, OpenAI Chat
  Completions, OpenAI Responses, and the Lux native dialect through a
  neutral intermediate representation, with an explicit loss report, SSE
  framing, a stream pump, logprobs across the boundary, provider-executed
  tools and web search, gateway-reported cost, and a token estimator.
  Stdlib only, and gated to stay that way.
- `luxsdk`: the first-party Go client for the Lux gateway: generate,
  stream, count tokens, cost tags, provider-direct mode, and
  `LUX_BASE_URL` / `LUX_API_KEY` resolution.
- `llmjson`: repairs the two encoding mistakes a model makes when asked
  for JSON, a markdown fence and raw control characters in strings.

Service building blocks:

- `audit`: the cross-product audit envelope with stdout and OTLP emitters
  and credential redaction over text and JSON.
- `email`: transactional mail over Mailgun, SMTP, or a log-only fallback,
  refusing header injection.
- `pgxmigrate`: embedded golang-migrate `Up` that closes its pool and
  retries a transient database open so a rolling deploy cannot crash boot.
- `httpjson`: strict request decoding and a response writer that marshals
  before it commits the status line.
- `metrics`: a Prometheus text-exposition registry with no client
  dependency.
- `batch`: a non-blocking batching pump with drain on shutdown.
- `pubsub`: in-process fanout with a bounded replay log.
- `routine`: periodic callbacks keyed by UUID with an injectable clock.
- `watcher`: a wake-or-tick event loop with a settle delay.
- `cache`: a TTL cache with an LRU cap over every entry and an
  injectable clock.
- `circuitbreaker`: a lock-free three-state breaker and a backoff breaker.
- `retry`: bounded exponential backoff with jitter, `Do`, `Stop`, and an
  exported attempt budget.
- `wait`: cancellable `Sleep`, `Every`, and `Until`; `wait/waittest`
  polls a condition in a test.
- `envutil`: typed environment reads with defaults.
- `statemachine`, `dag`, `tree`, `pagination`, `registry`: the transition
  guard, topological sort, tree rendering, cursor pagination, and
  slug-keyed catalog merge extracted from wallfacer.
- `trackedwg`, `syncmap`: a wait group that names what is outstanding,
  and a typed `sync.Map` with `LoadOrStore`.

Files, text, and processes:

- `atomicfile`: write-then-rename, with `WriteSync` fsyncing the file and
  its directory.
- `relpath`: traversal-safe relative paths and symlink-aware containment.
- `sanitize`: rune-budget and byte-budget truncation that never splits a
  rune, slug generation, and slug validation.
- `uniq`: order-preserving deduplication.
- `ndjson`: NDJSON read and append.
- `cmdexec`, `gitutil`: a subprocess builder with transactional rollback,
  and the git CLI behind typed results.
- `dircp`: recursive directory copy with a native fast path.
- `errwriter`: a console writer that remembers its first error.

### Changed

- `oidc`: public secret-less clients, the RFC 8628 device-code flow,
  configurable scopes and audience, `SessionFromRequest` with proactive
  refresh, a shared `/me` assembly (`BuildMe`, `Initials`,
  `SwitchOrgRedirect`), org listing and switching, `HandleLogoutNotify`,
  `GetSessionByName` for cookie cutovers, scopes read from the `scp`
  claim, `LoadConfigWithPrefix` for env-var migrations, and
  `AUTH_INSECURE_COOKIES` for local development against a remote issuer.
  Cookie helpers fail closed without a configured key.
- `otel`: one-call `Bootstrap` with `RunServer`, an instrumented client,
  a configurable sampler, stderr plus OTLP log tee with trace context
  stamped on local logs, `http.route` from the ServeMux pattern, handler
  panics recorded on the server span, the committed HTTP status, the
  OTel resource environment contract, `OTEL_SDK_DISABLED`, and a browser
  telemetry relay bounded by a per-process byte budget. OTel train
  v1.44.0.
- `md`: frontmatter fences are line-anchored, so an interior `---` no
  longer truncates the document, and indented frontmatter is preserved.
- `circuitbreaker.BackoffBreaker` takes its schedule from `retry.Policy`.
- `cache.WithMaxSize` bounds TTL entries as well as permanent ones.
- Go 1.27.

### Removed

- `set`, `tail`, `uuidutil`, `keyedmu`, `slugutil`, `sortedkeys`,
  `lazyval`, `cache.Lazy`, `registry.ContainsSlug`. Each was a line or
  two over the standard library or had one importer. Replacements:
  `map[T]struct{}`, a slice expression, `uuid.Validate`,
  `syncmap.Map.LoadOrStore`, `sanitize.IsSlug`,
  `slices.Sorted(maps.Keys(m))`, `sync.OnceValue`,
  `slices.ContainsFunc`.
- `authkit.LoadConfigWithPrefix` moved to `oidc.LoadConfigWithPrefix`.
- `authkit.CSRFIssue` and `oidc.GenerateState` no longer return an error;
  `crypto/rand` cannot fail since Go 1.24.
- `authkit`'s agent exchange client and the delegation claim vocabulary
  and strict tier in `jwtauth`.
- `scopes`: the Lux `llm.*` entries and the sandbox vocabulary; each
  product now owns its own.
- `oidc.Config.LegacyCookieNames`; use `GetSessionByName` during a
  cutover.
- The internal spec tree; this module is public and carries code only.

### Fixed

- `circuitbreaker`: the backoff delay wrapped below `MaxDelay` after
  enough failures.
- `httpjson.Write` answered 200 with an empty body when encoding failed.
- `sanitize.Truncate` panicked on a negative budget.
- `oidc`: open-redirect bypass through a backslash in `return_to`;
  `SwitchOrgRedirect` query escaping; user name and picture lost across
  token refresh.
- `otel`: OTLP log endpoint base paths and https endpoints were
  mishandled; oversized relay payloads are rejected; the log exporter is
  shut down when resource construction fails.
- `audit.RedactJSON`: large integers survive a round trip; quoted,
  plural-key, and authorization-header credentials are redacted.
- `jwtauth`: a non-2xx JWKS response is a fetch failure, not an empty key
  set.
- `bearer` parsing in `authkit` and `jwtauth` was case-sensitive.
