# Changelog

Every tag has a section here, and the section is the body of the GitHub
release. A tag without one fails the release workflow, and `make release`
refuses to create it. Write under `Unreleased` as work lands; `make release
VERSION=vX.Y.Z` turns that into the tag's section.

The module is at `v0.x`: a minor bump may contain a breaking change, listed
under **Removed** or **Changed** with what to do about it.

## Unreleased

### Added

- `llmdialect/bridge`, the translation layer between LLM provider API
  dialects as an import (latere-ai/specs
  `infrastructure/pkg/pkg-08-llmdialect-bridge.md`; Lux spec 021): what
  a proxy writes around a `llmdialect` codec pair, taken out of the Lux
  gateway so a program translates requests, responses, and streams with
  no gateway running. `Open(from, to, Options)` pairs the codecs of two
  dialects and is `Unsupported` for a dialect with none; `Request`
  decodes, writes the upstream's model name, encodes, and returns the
  loss report with the caller's entries in it, nil when nothing was
  lost; `Response` writes the caller's name back and returns the usage
  normalised so input never counts cache reads; `Stream` relays event by
  event with `FirstByte`, `Flush`, and `Fail` hooks, the name on
  `message_start`, and the last value of each usage member; and
  `StreamResponse` re-emits one JSON body as the caller's events. Around
  the pair, in each of four wires (`WireOpenAI`, `WireAnthropic`,
  `WireGoogle`, `WireLux`): `Envelope` and `ParseEnvelope` for the error
  shape, `ErrorFrame` for the frame that ends a stream which failed past
  its first byte, `GoogleStatus`, `ModelList` and `ModelEntry` over
  `Model`, whose zero fields are what each API writes for a model
  without that datum (the display name is the name, the owner `owner`,
  the creation time the epoch), `CountTokens` and `CountBody` for a count
  the upstream cannot answer, with `CountTokensFor` naming the body's
  dialect where a wire carries more than one request shape, and `UsageOf` and `NewUsageScanner` for the
  usage members of a body or of a stream as it is relayed, SSE or JSON
  array. The byte edits `Probe`, `SetModel`, `SetModelInFrame`,
  `SetIncludeUsage`, and `RemoveMember` change one member of a body and
  no other byte, and `RemoveMember` now reads a key with an escaped
  quote correctly where the gateway's copy did not. Every failure is an
  `*Error` with one of seven codes, one sentence each, the codec's words
  in `Detail`, the codec's error under `Unwrap`, and, for
  `DecodeRequest`, the refusal scope that `Scope` reports. Two of the
  spec's open questions are taken at their written defaults: `Response`
  keeps its loss slot, nil with today's codecs, so a codec that reports
  response-leg loss does not change the signature; and
  `CountBody(WireGoogle, n)` renders Google's own `{"totalTokens":n}`,
  written because the wire is otherwise complete and to be removed if no
  second consumer appears. The goldens under `testdata/` are the
  gateway's own bytes: every envelope, frame, list, entry, and count
  body, and every dialect pair's request, response, stream, and
  re-emitted-events leg, so the swap Lux spec 021 carries is a diff and
  not a judgement.
- `llmdialect/ir.Request.CacheKey`, the caller's prefix-cache key:
  requests that share it share a cacheable prefix, so whoever sits in
  front of the engine can keep them on the replica whose cache holds it.
  It is routing information for that layer, not a member for the
  engine, and no backend emits it: the IR cannot tell a caller's own key
  from one this layer derived, and a derived key that changes every
  turn would steer an upstream's own cache routing worse than no key.
  The frontends fill it from the signal each wire has. Responses:
  `prompt_cache_key`. `ir.PrefixCacheKeys` is that hash, documented byte
  for byte (role, type and the block's content fields, each as a
  netstring) and fixed, and returns one key per breakpoint in order so
  a router can fall back to a shorter prefix.

## v0.67.0 - 2026-09-14

- `authkit/jwt.Scopes(raw)` decodes the `scp` claim of a product-local token in one place, so a service that mints tokens for its own seams (rule R4) reads their scopes through the shared helper instead of re-declaring `{scp []string}` at each call site. The family identity still carries no scope (rule R9); this centralises the decode, not the meaning.

## v0.66.0 - 2026-09-14

### Added

- `authkit/jwt` verifies ES256 beside RS256 (latere-ai/specs
  `infrastructure/open-cores.md`, C5; Lux spec 006): a token whose header
  names `alg: ES256` is checked against the key set's `kty: EC`, `crv:
  P-256` keys, an RS256 one against its RSA keys, and never the other way
  round, so a signature is not tried against a key of the other family.
  Any other `alg` is still `ErrUnsupportedAlg`, and a key of another type
  or curve is skipped as a non-RSA key was. `issuertest.WithES256` is the
  stub that mints such tokens.
- `authkit/issuertest` serves `GET /requests`, the list `Requests()`
  returns as a JSON array, and `DELETE /requests`, which is
  `ResetRequests`, mirroring `authz/stub`, so a test in another process
  can prove a service dialled the issuer zero times during its data-plane
  requests (Lux spec 001's third invariant, spec 015). The two reads are
  not themselves recorded, and an empty record is `[]`, never `null`.
- `authz/stub` has the second kind of outage beside a status: `FailBody`
  makes every answer a 200 whose body is no answer, `BodyMalformed` (not
  JSON) or `BodyNoAllow` (parses, no `allow` field), and `PUT /fail` takes
  `{"body": "malformed"}` or `{"body": "no-allow"}` beside `{"status":
  <int>}`; `{"status": 0}` and `Resume` clear either. `authz.Client`
  treats both as `*Unavailable`, which the stub's test proves (Lux spec
  006's forms of unavailability).
- `authz/conformance`, the test every authorizer passes, which
  `infrastructure/open-cores.md` and Lux spec 006 said the package carries
  and it did not: `conformance.Run(t, url, token)` proves the probe id is
  denied for every subject, the anonymous one included, and every action;
  a wrong bearer and no bearer are refused; a well-formed request answers
  a 200 with `allow` a boolean; `ttl` when present is a positive integer,
  `limits` an object, `filter` owners (`[]string`) and labels
  (`map[string]string`) and nothing else; and a deny carries a reason. A
  core names its vocabulary with `WithActions` and its subjects with
  `WithSubjects`. `authz/stub` passes it, and the package's own test
  shows an endpoint that allows the probe, or bends any one field, fails
  it with a message naming the request.
- `ratelimit.Buckets.AllowN(key, n)`, a charge of n tokens at once or none,
  `Retry` the wait until all n are available, and
  `ratelimit.Buckets.Adjust(key, delta)`, which settles a reservation: a
  positive delta refunds up to the burst and a negative one debits past
  zero into a deficit the refill covers before the next `Allow`. Lux spec
  007's rate windows reserve an estimate, settle to the measured count,
  and refund whole on a later refusal; until now `Allow` took exactly one
  token and nothing gave any back.

### Changed

- `ratelimit.Config.PerMinute` of zero is no longer a disabled limiter: it
  is the mode with no default bucket, where a key is unlimited until
  `SetRate` gives it a rate and limited to that rate after (Lux spec 007,
  whose rates arrive per Key). A negative `PerMinute` and a nil `*Buckets`
  still disable everything, and every positive `PerMinute` behaves as
  before. A caller that passed zero to turn the limiter off and never
  called `SetRate` sees no change; one that did call `SetRate` now limits
  that key, and passes a negative value to keep the old behaviour.
  `Allowance.Remaining` reads zero, not a negative figure, in a deficit.

### Fixed

- `authz.Policy` allows the `Create` action on an object that does not
  exist whether or not the request names an id. The row required an id,
  while `authz.Resource` and `infrastructure/open-cores.md`'s envelope say
  a create carries none; an id, when present, names the object the caller
  chose. A name that resolves to another subject's object is still
  `not_owner` under the create action, and the anonymous subject still
  creates nothing.
- `authkit/issuertest`: the doc comments of `WithDefaultAudience` and
  `WithServiceClient` were attached to the wrong function.
- `llmdialect/lux`: a request carrying `server_tools` or `web_search`
  reported both as loss although the decoder reads them, so a caller saw a
  spurious loss header on an answer that lost nothing. Both are named
  among the request keys, and the test holds every field `Request`
  declares to a named key so the two cannot drift again.

## v0.65.0 - 2026-09-13

### Added

- `authz`, the one authorizer contract the open cores share
  (latere-ai/specs `decisions/2026-09-13-one-platform-open-cores.md`, C3
  and C4; Origo spec 028): the envelope `Request{subject, issuer, sub,
  claims, action, resource, request}` and `Decision{allow, reason, ttl,
  limits, filter}`; `Client`, which caches an allow for its `ttl` (default
  60 s, cap 600 s) and a deny for 5 s, never caches an unavailable
  answer, retries once when the connection failed before a response line
  and on nothing else, times out at 5 s, and fails closed on every other
  outcome; `Ask` for an action whose answer shape is the core's own;
  `ProbeID` and `Check`, the reserved id every authorizer denies;
  `Subject` and `SplitSubject`, the `<iss>|<sub>` rendering; and `Policy`,
  the owner policy's frame a core applies when no authorizer is
  configured. `authz/stub` is the stub authorizer the cores' test tiers
  run, speaking this contract alone, with a rule table, a request record,
  and the two outage modes over HTTP and by method.

## v0.64.0 - 2026-09-13

### Removed

- `authkit.Identity.IsSuperadmin` and `authkit.Identity.Scopes`, and
  `authkit.HasScope` with them (identity id-09, rule R9). Access is by
  role: the platform administrator is the `platform_admin` name in
  `roles`, on every token of that principal, and a service decides with
  its own table over `Identity.Has`. `scp` is OAuth's ceiling on what a
  client may request and no service decides from it; a product whose own
  tokens carry scopes decodes them into its own type with
  `jwt.DecodePayload` after `Validate`, which is what `egress.TokenAuth`
  now does for the workload scope. `authkit/jwt` and `authkit/oidc` no
  longer read `is_superadmin` or `scp`: a token carrying the flag and no
  role yields an Identity on which `Has("platform_admin")` is false.
- `DevConfig.Scopes` and `AUTH_DEV_SCOPES`. `DevConfig.IsSuperadmin` is
  `DevConfig.PlatformAdmin`, and `AUTH_DEV_SUPERADMIN` grants the
  `platform_admin` role rather than setting a flag. `NewBearerToken`'s
  dev identity carries the role the same way.

### Added

- `authkit.Identity.Has(role string) bool`, and the five names as
  constants: `RolePlatformAdmin`, `RoleOwner`, `RoleAdmin`, `RoleMember`
  (the personal-tenant member is a token with no `org_id` and no roles).
- `conformance.RefusesTheFlag`, the sixth row of the id-04 suite: a token
  carrying `is_superadmin: true` and no `platform_admin` role opens no
  admin route, and one carrying the role in `roles` is reported by `Has`.
  `Run` includes it.
- `authkit/issuertest` serves `POST /token`, the `client_credentials`
  grant: a client registered with `WithServiceClient` presents HTTP Basic
  credentials and receives a token addressed to the issuer for the account
  it stands for, `principal_type: service`. `/actor-tokens` then narrows a
  registered client's bearer only to the audiences its row names and
  refuses the rest with `invalid_target`, which is the issuer's registry
  gate (identity rule R3); a person's bearer names no client and is not
  gated by the stub. A stub with no registered client refuses every grant.
  Until now a repository testing an unattended run had to hand-roll the
  endpoint (agents `cmd/toposd/unattended_e2e_test.go` did).

## v0.63.1 - 2026-09-13

### Changed

- `issuertest`: `POST /mint` mints any field its body carries that `Claims`
  does not name as an extra claim, so a consumer's verification table can
  ask for a token with a retired claim and prove its verifier refuses it.

## v0.63.0 - 2026-09-13

### Added

- `oidc.ClientCredentials` and `oidc.ServiceTokenSource`: a service's own
  credential, minted with the client_credentials grant for one audience
  and reused until 30 s before it expires. A service that acts as itself,
  not for a person, holds one source per audience and asks it per call.
- `issuertest.WithRS256`, the explicit form of the default, so a wrapper
  that defaults to ES256 can be asked for RS256.

## v0.62.0 - 2026-09-13

### Added

- `authkit/issuertest`: the family's stub issuer for tests, moved from
  Origo's `test/stubs/issuer`. Discovery, JWKS, `POST /mint` for a token
  with any one claim wrong, `POST /actor-tokens` as the one hop, rotate,
  hang and resume, and a request recorder. RS256 by default, ES256 by
  option.
- `authkit/conformance`: rule R2 as a test a service runs with the
  authenticator it installs in production: its own audience is admitted
  and yields sub, org_id, roles and principal_type; the issuer's audience,
  another service's audience and a token with no subject are refused; and
  nothing but the key set is called while authenticating.

### Removed

- `jwt.TokenInfoClient`, `jwt.CachedTokenInfo` and `jwt.TokenInfoLookup`:
  the clients of the issuer's `GET /tokeninfo`, which the issuer no longer
  serves. Team membership travels in the token as `teams`; read
  `Identity.Teams` and ask the issuer nothing at request time.

## v0.61.0 - 2026-09-13

### Added

- `oidc.MintActorToken` and `(*oidc.Client).ActorToken`: the one way a
  service acts for a person at another service. `ActorToken` posts the
  session token to the issuer's `/actor-tokens` for one audience, asks the
  full lifetime, and reuses the result per session and audience until 30 s
  before it expires. The issuer mints only for an audience the client is
  registered to act at; a refusal reaches the caller with the issuer's
  reason.

### Changed

- `oidc.Config.Audience` no longer defaults to the issuer and `/authorize`
  carries no `audience` parameter unless one is configured. A login token
  is addressed to the issuer alone; a client that set `AUTH_AUDIENCE` to a
  product removes it and reaches that product with `ActorToken`.
- `jwt.NewAuthenticator` takes the validator alone; the second argument
  never had a second value. Callers drop it.

### Removed

- `scopes`: the billing vocabulary, which no service checked.

## v0.60.1 - 2026-09-12

### Fixed

- `hostsandbox`'s own test suite no longer assumes the macOS dependency set,
  so it passes on Linux, where srt also needs bubblewrap and socat. Nothing a
  consumer imports changed.

## v0.60.0 - 2026-09-12

- `drive` shares the workspace HTTP client across mount consumers: attach, materialize, writeback, lease renewal, create/get, and complete paginated lists. Tokens are resolved per request; typed errors preserve writer-holder details.

### Added

- `hostsandbox`, the srt host sandbox extracted from replichai: `StageSpec`,
  `StageHandle`, `StageStatus`, `Capabilities` and the `Sandbox` interface
  any isolation driver satisfies; `New(Config)` for the srt `Driver`, which
  launches a stage detached under `setsid`, records its exit status beside
  the log, and answers `Observe` from that file and from the pid and start
  time in the `pid:<pid>@<start>:<log>` handle, so a reused pid is never
  mistaken for the stage; `Render`, `Profile`, `Settings` and
  `AlwaysDenyRead` for srt's settings file, with the home directory denied,
  the named paths allowed back, TLS termination declared whenever a domain
  is allowed, and no open mode because srt refuses a wildcard;
  `AllowedEnvironment` and `Environment` for what a stage inherits;
  `ShellQuote` and `ShellJoin`; `Preflight`, `Remedies`, `DefaultRemedies`
  and `NotReadyError`, whose remediation names the install commands for the
  platform and whose `Alternative` is the consumer's own text.
  `hostsandbox/hostsandboxtest.Run` is the contract suite every driver of
  the seam is held to.

- `circuitbreaker.Admits` inspects readiness without consuming the half-open probe, and `RetryAfter` reports the remaining cooldown. Pollers and retry headers can use the shared breaker without maintaining duplicate state; protocol-specific rounding remains with the consumer.

- `ratelimit.New` provides per-key token buckets with configurable refill, burst, idle eviction, clock injection, and rate overrides. Admission reports remaining tokens and retry delay. Idle cleanup retains depleted buckets until replenished, preventing expiry from resetting quota; it runs on activity or explicit `Sweep` without a background goroutine.

- `semaphore.New` bounds concurrent work with `Acquire(ctx, wait)`, which returns an idempotent, concurrency-safe release function. Nonpositive waits try once; nonpositive capacity is uncapped. Canceled callers are refused, and `Size`/`Held` expose capacity and occupancy.

- `retry.Policy.Timeout` bounds each attempt independently while the parent context bounds the entire retry loop. Callbacks must honor cancellation; zero preserves the unbounded-attempt default. `s3.WithRetry` applies the bound to request headers and response processing, including listing and error bodies. Successful `GetObject` downloads retain parent cancellation but stop the attempt timer at headers, so large objects remain readable; close the returned reader to release resources. Permanent HTTP refusals remain non-retryable even if reading their error body times out.

- `otel.Start` and `otel.StartScoped` open child spans on the configured provider and return an end function that records an optional error. `otel.SetAttributes` adds attributes to the current span. `StartScoped` preserves a consumer-specific instrumentation scope; attributes use the OpenTelemetry API types, with no SDK setup needed in callers.

- `hostmatch.ValidPattern` accepts `hostmatch.WithSingleLabel()` to opt into exact hosts such as `localhost` and bare service names. Default validation and wildcard rules remain unchanged.

- `metrics.Histogram.Init(labels)` exposes zero-valued series before the first observation, so dashboards can discover a fixed label vocabulary at startup. Repeated initialization preserves counts and sums.

- `circuitbreaker.WithClock` lets callers advance cooldowns without sleeping in tests. Existing constructors keep the wall clock; a nil clock option leaves that default intact.

## v0.59.0 - 2026-09-06

### Added

- `s3.Body.ContentType` is sent as `Content-Type` on `PutObject` and
  `CreateObject` and signed with the request; `s3.Object.ContentType` is
  what `GetObject` and `HeadObject` read back. An empty field sends no
  header, as before, and the store answers its own default. `s3test`
  keeps the type a PUT carried, answers it on GET and HEAD, stores
  `s3test.DefaultContentType` (`application/octet-stream`, as MinIO does)
  for a PUT without one, and adds `ContentType(key)` and
  `PutWithContentType` for a consumer's assertions and seeds.
- `s3.WithContentType` on `PresignPut` binds `Content-Type` into the
  signature the way `Content-Length` is, so a presigned upload is refused
  unless it carries that type. `PresignPut` takes the option variadically;
  every existing call is unchanged.

## v0.58.0 - 2026-09-06

### Added

- `metrics.Counter.Value` and `metrics.Histogram.Count` read a series
  back by label set, so a test asserts on a counter without parsing the
  exposition.
- `health`, the probe surface every service serves on its internal
  listener: `/livez`, `/readyz`, `/version`, and `/metrics` where the
  service has some. `Handler(Options{Ready, Timeout, Metrics, Version,
  Commit, BuildTime, LegacyHealthz})`; `Checks` folds named readiness
  checks and `/readyz` names each failing one in its body, while `/livez`
  and `/version` never carry an error text. `LegacyHealthz` serves
  `/healthz` as an alias of `/livez` for the release in which a manifest
  moves. The decision, and why one `healthz` is wrong under Kubernetes,
  is `docs/health.md`.
- `httpjson.Error`, `httpjson.ErrorEnvelope`, and `httpjson.WriteError`:
  the error envelope every Latere API answers with, rendered as
  `{"error": {"code", "message", "details"}}` through `Write`. `message`
  is the user sentence fixed per code and `details` the developer detail,
  per `docs/writing/registers.md`. Every existing function is unchanged;
  a service that carried its own envelope type decodes into
  `ErrorEnvelope` instead.
- `s3`, a client for the S3 REST API in the standard library, signed with
  Signature Version 4 and checked against the signing documentation's
  published vectors. It carries the primitives Latere services use and
  nothing more: `PutObject` with Content-MD5, `CreateObject` (PUT with
  `If-None-Match: *`, answering `ErrPreconditionFailed` when the key
  exists), `GetObject` with `If-None-Match` answering `ErrNotModified`,
  `HeadObject` answering `ErrNotFound`, `DeleteObject`, `ListObjects` with
  prefix, delimiter, and start-after pagination, and `PresignGet` and
  `PresignPut` with the Content-Length bound into the PUT's signature.
  There is no `If-Match` on PUT: the providers the family runs on do not
  agree on it, and the package documentation says which. A 5xx, a 429, or
  a transport failure is retried under a `retry.Policy`; a 4xx is not.
  `s3/s3test` is an in-process endpoint for a consumer's tests: it
  verifies every signature, digest, and presigned expiry the way a
  provider does, answers 412 to every `If-Match` the way the least
  capable provider does, and injects failures for the retry path. A
  service that carried a cloud SDK for these calls switches to this
  package and drops the SDK.
- `docs/writing/registers.md`, the platform-wide writing rule: every
  sentence is written for one of three readers (user, contributor,
  developer), and an error has one code, one fixed user sentence, and one
  developer detail in a separate field. Every Latere repository's
  `CONTRIBUTING.md` points here.

## v0.57.0 - 2026-09-06

The egress ingest wire format carries the v0.56.0 features, so a control
plane that pushes maps over HTTP can use dynamic credentials and body
substitution. Every existing body decodes exactly as before.

### Added

- `egress.IngestEntry` gains `kind` (`static`, the default when absent, or
  `oauth_client_credentials`), `substitute_body`, and for the oauth kind an
  `oauth` object `{token_url, client_id, client_secret, scope, audience}`
  (`IngestOAuth`). `DecodeIngestBody` and `IngestHandler` turn an oauth
  entry into an `Entry` with its own `OAuthClientCredentials` resolver, so
  the token cache lives with the map and is dropped with it. An unknown
  kind, or an oauth entry missing `token_url`, `client_id`, or
  `client_secret`, rejects the body with a 400 that names the entry and the
  field. `IngestKindStatic` and `IngestKindOAuthClientCredentials` name the
  kinds; `IngestOAuthEntryFor` builds an oauth entry for `Client.PushMap`.

## v0.56.0 - 2026-09-06

### Changed

The module is licensed under Apache-2.0. The root `LICENSE` said MIT while
every source file already carried the `Apache-2.0` SPDX notice that the
gate enforces; the root file now matches the notices.

The changelog rule this file describes now lives in `lateregate`, shared by
every latere.ai repository: `make release` and `make release-notes` call
`go tool lateregate release` and `release-notes`, the pre-push hook refuses
a release tag without a section through `lateregate prepush`, and the
release workflow publishes through `notes-release.yml` in latere-ai/ci.
The two shell scripts under `.github/scripts` are gone.

`egress` gains dynamic credentials, opt-in body substitution, and a stricter
header rule. Every change is additive: a consumer on v0.55.0 upgrades without
edits.

### Added

- `egress.Entry.Resolve`: a secret produced at substitution time instead of
  held in `Secret`. `Map.SubstituteValueContext` runs resolvers and returns
  their error with the value unchanged; the context-free `SubstituteValue`
  skips such entries and leaves their placeholders as they are.
- `egress.OAuthClientCredentials`: the built-in resolver, the RFC 6749
  client_credentials grant from a token URL, client id and secret, and an
  optional scope and audience. It caches the token per entry, refreshes
  `Skew` (default 30 s) ahead of expiry, shares one in-flight mint between
  concurrent callers, serves a still-valid token when a refresh fails, and
  returns `ErrNoValidToken` when nothing valid is cached. `HTTPClient`,
  `Now`, and `MintTimeout` are injectable. The resolved value is the bare
  token: the request already carries the "Bearer " around the placeholder.
- `egress.NewMapStrict`: `NewMap` that also returns the entries it dropped as
  `DroppedEntry` values wrapping `ErrEmptyPlaceholder`, `ErrNoAllowedHosts`,
  or `ErrSecretLineBreak`.
- `egress.SubstituteHTTPRequestContext`: `SubstituteHTTPRequest` for maps
  with resolver entries. Every resolver runs at most once per request, and
  on an error the request is returned exactly as given.
- `egress.Entry.SubstituteBody`: opt-in body substitution by
  `SubstituteHTTPRequestContext`. A body with a known Content-Length of at
  most `DefaultMaxBodyBytes` (64 KiB, or the `WithMaxBodyBytes` limit) and a
  JSON, form, or text Content-Type is rewritten for entries that opted in,
  with Content-Length following. A streaming, chunked, larger, or binary
  body is never read, so SSE and uploads are never buffered.

### Changed

- `egress.NewMap` drops a static secret containing CR or LF, and a resolved
  secret with a line break fails the substitution with `ErrSecretLineBreak`:
  a line break in a header value is a header injection.
- `egress.SubstituteHTTPRequest` and `SubstituteHTTPRequestContext` never
  rewrite Content-Length, Transfer-Encoding, TE, Trailer, Connection,
  Keep-Alive, Upgrade, Proxy-Connection, Proxy-Authorization, or any
  X-Forwarded-* header.
- `egress.Gateway` substitutes through `SubstituteHTTPRequestContext`, so a
  resolver that cannot produce a secret answers 502 instead of forwarding
  the placeholder.

## v0.55.0 - 2026-09-06

`dag` gains the two operations its one consumer was hand-rolling beside it,
and the one-function `registry` package folds into `uniq`.

### Added

- `dag.TopoSort` and `dag.TopoSortFunc`: Kahn topological sort with a
  deterministic tie-break, so the order depends on the input alone. On a
  cycle the result holds the nodes that could still be ordered and the
  error is `dag.ErrCycle`.
- `dag.LongestPath`: the number of nodes on the longest path from a start
  node, memoised, for critical-path scoring.
- `uniq.Merge`: base followed by extra with every key unique, or an error
  wrapping `uniq.ErrDuplicate` that names the repeated key.

### Removed

- `registry`. Replace `registry.MergeUnique(kind, builtins, user, slugOf, mark)`
  with `uniq.Merge(builtins, user, slugOf)`. Apply `mark` to a clone of
  `builtins` before the call and wrap the error with `kind` at the call site.

## v0.54.0 - 2026-09-06

The egress credential-substitution engine is now a shared package, so a
second front door can be built on the same core, and the host allow-list rule
it scopes secrets by is its own package.

### Added

- `egress`: credential substitution at an egress boundary. A workload holds
  an opaque placeholder (`MintPlaceholder`, `IsPlaceholder`); the engine
  (`Map`, `NewMap`, `Map.SubstituteValue`, `Map.HostHasSecret`,
  `SubstituteHTTPRequest`) swaps it for the real secret only toward the hosts
  the credential is scoped to. `Registry` holds one map per principal;
  `IngestHandler` and `DecodeIngestBody` fill it over the control-plane API,
  and `Client` is the matching caller with per-replica fan-out
  (`PushMapAllReplicas`, `PurgeMapAllReplicas`). `RePusher` keeps every
  replica warm from a `PrincipalLister`, `PlaceholderReader`,
  `SecretResolver`, and `MapPusher`. `TokenAuth` verifies the proxy JWT
  against a JWKS with `TokenAuthOptions`: the required `Audience`, an optional
  `Scope` and `Kind`, and `SubjectClaim`, the claim that names the principal
  (default `sub`). `Gateway` is the TLS-terminating CONNECT proxy on top,
  with `Realm` for its 407 challenge, and `CA` mints the per-SNI leaves
  (`GenerateCA(commonName)`, `LoadCA`, `CA.CertPEM`). Every piece below
  `Gateway` works without it.
- `hostmatch`: the one host allow-list rule every egress surface shares.
  `New(patterns, normalize)` compiles exact FQDNs and `*.`-prefixed wildcards
  into a `Matcher`; `ValidPattern` is the grammar.

## v0.53.0 - 2026-09-06

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
