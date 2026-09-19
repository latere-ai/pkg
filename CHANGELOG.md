# Changelog

Every tag has a section here, and the section is the body of the GitHub
release. A tag without one fails the release workflow, and `make release`
refuses to create it. Write under `Unreleased` as work lands; `make release
VERSION=vX.Y.Z` turns that into the tag's section.

The module is at `v0.x`: a minor bump may contain a breaking change, listed
under **Removed** or **Changed** with what to do about it.

## Unreleased

## v0.78.0 - 2026-09-19

### Added

- `oidc.Me.Roles` exposes role hints from the current access token. Consoles
  can update navigation after token refresh without reading stale roles from
  the login cookie or making another identity request. API authorization
  still verifies the access token.

## v0.77.1 - 2026-09-19

### Fixed

- `authz.Client` no longer reuses a cached decision after claims, workload,
  resource policy, issuer, subject parts, caller IP, or user-agent change.
  Cache identity covers the exact serialized request except its correlation
  ID; unencodable requests fail closed even when an older allow is cached.

## v0.77.0 - 2026-09-19

### Removed

- `scopes`, the registry of OAuth scopes the auth service issues. Auth
  issues only the four standard OIDC scopes and advertises them itself;
  every product scope is owned by the product that checks it, so a shared
  registry had nothing left to hold. Callers that named the OIDC constants
  use the literal `openid`, `email`, `profile` and `offline_access`.

## v0.76.0 - 2026-09-18

### Fixed

- The egress gateway no longer refuses a sandbox whose token was minted more
  than a day ago. Since v0.71.0 `egress.TokenAuth` applied the family's
  24-hour age bound to the tokens it verifies, so a sandbox running longer
  than a day was answered `407 Proxy Authentication Required` on every
  request it proxied, until the next re-mint replaced its token. The token
  was valid: it was days from its expiry, and nothing but its issue time was
  wrong with it.

  A token the gateway verifies is a workload credential, and the plane that
  issued it re-mints it on that plane's own schedule, so its `exp` is its
  bound and its age is not. The gateway now reads `exp` alone.
  `egress.TokenAuthOptions.MaxTokenAge` puts an age bound back for a
  deployment that wants one; zero, the default, is no bound.

## v0.75.0 - 2026-09-17

### Added

- A personal access token can now be narrower than the person who holds
  it. The key's holder chooses what it may do when they create it, the
  grants ride on every token it mints as RFC 9396's
  `authorization_details`, and a service that takes this version enforces
  them.

  What a service gets:

  - `jwt.Config.ReadsGrants` turns the reading on. A verified token then
    hands back `Identity.TokenUse` and `Identity.Grants`, beside the
    subject and the roles it always carried.
  - `authz.Restrict(core, decision, request, grants)` narrows one
    decision by them: an allow becomes a deny with reason `grant` when no
    grant covers the request, and a deny is never turned into an allow. A
    grant is a restriction and never authority, so a grant on a resource
    the person cannot reach still reaches nothing.
  - An endpoint written on `authz/server` applies it already. Bump the
    package and the narrowing is there, with no option to switch it off.
  - `authz/conformance` runs one more case under `WithVocabulary`: a
    token granted one action on one resource is refused every other
    action on it and that action anywhere else.

  **A scoped token is refused until the service sets `ReadsGrants`.** The
  flag is off by default, and a token carrying grants is answered with a
  401 whose reason is `grants_unread`. That is deliberate: the claim says
  what the credential may *not* do, so a service that reads the token and
  applies nothing grants more than its holder asked for, and silently. A
  refusal is visible; an ignored restriction is not. Set the flag once
  the conformance run passes.

  A token that is not a personal access token is unaffected, whatever the
  claim says, and a service that never sets the flag keeps verifying
  every token it verified before.

- `jwt.Validator.Warm(ctx) error` reads every configured issuer's key set
  once, for a process that would rather pay for the fetch at start-up
  than have the first request pay for it. Call it from a start-up hook or
  a readiness probe; calling it is optional, and a validator that was
  never warmed fetches on the first token exactly as before.

  It is idempotent: warming again inside `CacheTTL` reads the cache and
  reaches no network, so a probe on a schedule costs one fetch per TTL.
  The return is a report and not a verdict — an issuer that did not
  answer is named, every other issuer is still warm, and the validator
  verifies either way.

- `authz.Vocabulary.WithLabels(map[string]string)` and
  `Vocabulary.Label(kind)` give a resource kind the name a person reads,
  so a picker can group by function without anybody hard-coding the
  headings. `SandboxSet` is a type name; `Sandbox sets` is a heading. A
  vocabulary that declares no label renders as its kind, and
  `NewVocabulary`'s signature does not change.

### Changed

- `authz/conformance` drives one more case under `WithVocabulary`, so a
  suite that passed on the previous version can go red on this one. The
  case sends a personal access token granted one action on one resource
  and requires a deny for every other action on it and for that action
  anywhere else. An authorizer that answers `allow: true` to those fails.

  What to do about it depends on how the authorizer is written. An
  endpoint on `authz/server` needs nothing: bump the package and the
  narrowing is applied for you. An authorizer written by hand calls
  `authz.Restrict(vocabulary.Core, decision, request, grants)` on its own
  answer, with the grants from `authz.ParseGrants(request.Claims)`. A
  core that decides locally with `authz.Policy` does the same, and must
  fill `Request.Claims` from its verified token: a request built with
  empty claims restricts nothing.

  The case is silent without `WithVocabulary`, because the grants name an
  action qualified by its core and there is no core to qualify with.

- `authz/stub`, told a vocabulary, now narrows an allow by the grants the
  request carries, the way a conforming endpoint does. A stub told no
  vocabulary answers its rule table alone, unchanged.

### Removed

- `authkit.Identity.AgentID`, and its `agent_id` JSON tag. The auth
  service stopped issuing a delegated-agent claim when the identity work
  settled what an agent is: an agent is a service account, and the acting
  agent is a column a product keeps beside the bearer, not something a
  verifier hands out. The field had no reader anywhere in the family,
  checked by grep across every repository, so nothing to do: a service
  that never read it is unaffected, and one that set it deletes the
  assignment.

  A test now reads every non-test Go file of this module and fails on a
  word the identity work retired: `agent_id`, `grantor_id`, `"act"`,
  `actor: true`, `/tokeninfo`, `/userinfo/permissions` and
  `/v1/tokens/exchange`. Test files are exempt, because a test that mints
  a token carrying a retired claim is how a package proves it refuses
  one.

## v0.74.0 - 2026-09-17

### Added

- `jwt.Config.Now func() time.Time` is this node's clock. Nil is
  `time.Now`, which is what a service wants and what every existing caller
  gets; a caller supplies one to run the validator on a clock it moves.

  It is the one clock the validator reads: the `exp`, `nbf` and `iat`
  windows, the key set's cache TTL, and the back-off that bounds how often
  a `kid` miss may force a refresh. A validator handed a clock therefore
  reaches no real time at all, so a test can mint a token, verify it, move
  the clock past its `exp` and see it refused, and move the clock past
  `CacheTTL` and see the refetch a node would make.

- `jwt.ErrIssuerUnavailable`, reason `jwt.ReasonIssuerUnavailable`
  (`issuer_unavailable`), is an issuer whose key set could not be read: its
  discovery document or its JWKS endpoint did not answer, and no cached set
  was held to answer in their place. The fetch failure was unclassified
  before, so `jwt.ReasonOf` read the empty string and a caller could not
  tell an unreachable issuer from anything else; it now carries the
  family's word for the row.

  The stale-on-error fallback is unchanged: a cached set is an answer,
  however stale, and is still served, so this refusal is the one a node
  holding nothing gives. A discovery document refused under OIDC 4.3 keeps
  its own row rather than reading as the issuer being out of reach: the
  issuer answered, and what it said was refused.

- `jwt.ParseHeader(token) (jwt.Header, error)` reads a compact JWT's JOSE
  header: `Alg`, `KID` and `Typ`. It verifies nothing and reaches no
  network, and it is the header `jwt.Validator.Validate` reads for itself,
  so a caller holding its own key sets can select a key by the `kid` the
  token names rather than trying every key it holds. A token that is not
  three segments, or whose header is not base64url JSON, is
  `jwt.ErrMalformedToken`.

### Fixed

- Security: a discovery document must name the issuer it was fetched from.
  `Config.Issuers` discovers each issuer's key set at
  `<issuer>/.well-known/openid-configuration` and followed the document's
  `jwks_uri` whatever issuer the document named. A document served under a
  trusted issuer's URL could therefore name another party and hand this
  node that party's key set, and that set then verified tokens minted in
  the trusted issuer's name: key substitution, with the trusted URL as the
  only thing an operator had checked.

  The document's `issuer` is now compared to the configured issuer,
  trailing slashes aside, before anything else in the document is read
  (OpenID Connect Discovery 4.3). A mismatch, and a document that names no
  issuer at all, is `jwt.ErrBadDiscovery`, reason `issuer`, and no key of
  that document's `jwks_uri` is ever fetched.

  This reaches the `Config.Issuers` path alone, which is the only path that
  discovers: `Config.Issuer` is configured with its `Config.JWKSURL`
  directly and never read a discovery document. An issuer whose document
  names itself, which is what the family's issuers publish, is unchanged.

## v0.73.0 - 2026-09-17

### Changed

- One rule decides which key verifies a token, on every path, and one
  reason says when no key does. The `kid` names the key: the key declaring
  it, or a key declaring no kid at all, since a key published without a name
  can be reached no other way. A token carrying no `kid` leaves the choice
  to the set, which only a set holding exactly one key can make. Anything
  else, a kid the set does not hold or a choice between keys, is
  `jwt.ErrUnknownKey`, reason `unknown_key`.

  On the JWKS path this removes a fallback. A kid that matched nothing was
  tried against every key of the set in turn, so a token could name one key
  and be admitted by another: a claim about the issuer's set that the issuer
  never made. A kid miss still forces one refresh of the set first, so a key
  just rotated in at the issuer is picked up rather than refused. A
  single-key set, which is what the family's issuers serve, is otherwise
  unchanged.

  On the local path this changes a reason. A token of `Config.LocalIssuer`
  naming a kid the local set does not hold was `ErrInvalidSignature`, which
  said a signature had failed when no key had been asked.

  Once the key is chosen, only its own verdict counts: a signature that does
  not check out against it is `ErrInvalidSignature` and not the other
  refusal, so the key a rotation replaced does not get to verify in the
  newer key's place. A caller that relied on the fallback sees `unknown_key`
  where it saw `invalid signature`. Both are refusals, so nothing that was
  admitted before is refused now except a token naming a key nobody
  published, and nothing that was refused is admitted.

## v0.72.0 - 2026-09-17

### Added

- `jwt.Config.Issuers []string` is a list of issuer URLs to trust beside
  `Config.Issuer`, for a node whose deployment reads its trusted issuers as
  a list. A token's `iss` must name one of them, trailing slashes aside.
  Each issuer's key set is discovered from the issuer itself, at
  `<issuer>/.well-known/openid-configuration`, so no JWKS URL is configured
  per issuer, and each set is fetched and cached per issuer. Each issuer
  answers for its own tokens alone: trusting two issuers does not pool
  their keys, and a token naming one issuer and signed by another's key is
  refused. `Config.Issuer` keeps its own `JWKSURL` and is trusted beside
  the list; with the list empty nothing changes at all.

  One order differs in this form, and only in it: an `iss` that names no
  trusted issuer is refused as the issuer before the signature is weighed,
  because the issuer is what selects the key set. The single-issuer form
  still checks the signature first.
- `jwt.Config.LocalKeys []jwt.LocalKey`, each a `{KeyID, Key}`, holds more
  than one key for `Config.LocalIssuer`. That is what a rotation needs: the
  newer key signs while the older still verifies, so tokens minted before
  the rotation are read until they expire rather than refused the moment
  the key changes. A token's `kid` selects the key that must verify it, so
  a kid the set does not hold is refused rather than tried against every
  key the node holds; a key that declares no `KeyID` answers whatever kid a
  token names, as the one-key form does. `Config.LocalKey` and
  `Config.LocalKeyID` are that one-key form, unchanged, and the two may be
  given together.

## v0.71.0 - 2026-09-16

### Added

- `jwt.Config.ClockSkew` is the tolerance on `exp` and `nbf` for the
  difference between the issuer's clock and this node's: a token is read
  until the skew past its `exp`, and from the skew before its `nbf`. Two
  clocks that disagree by seconds were refusing each other's tokens at the
  edges with nothing a caller could set. It is zero by default, so nothing
  a caller verified before verifies differently. It widens those two
  claims and nothing else: not `MaxTokenAge`, which is how long a token
  stays a credential on this clock alone, and not a token of
  `Config.LocalIssuer`, which was stamped on this clock and has no second
  clock to reconcile.

### Changed

- An issuer's `iss` is compared with trailing slashes trimmed on both
  sides, so an issuer that publishes `https://x` and stamps `https://x/`
  is one issuer rather than two. A deployment could not reconcile that
  from outside: the claim is the issuer's to stamp and the configuration
  is the operator's to write. `Config.Issuer` and `Config.LocalIssuer` are
  both matched this way, nothing else about the URL is normalised, and a
  path is still a path, so `https://x/realm` is a different issuer.
  `Claims.Iss` is unchanged: it is handed back exactly as the token
  carried it.

### Added

- `authkit/jwt` carries a reason table. Every refusal is a `*jwt.Error`
  holding a `jwt.Reason`, and `jwt.ReasonOf(err)` reads it through any
  number of wraps, so a service writes the family's word for a refusal
  instead of inventing one: `malformed`, `signature`, `issuer`,
  `audience`, `expired`, `nbf`, `size`, `iat`. The sentinels keep their
  identity and their text, so `errors.Is` and every message are what they
  were. `ErrUnsupportedAlg` reads as `signature`, because an algorithm no
  key of the set can answer is what a caller learns as a signature that
  did not check out, and `ErrNoToken` carries no reason, because nothing
  arrived to refuse.
- `jwt.Config.MaxTokenBytes` is the size above which a token is
  `jwt.ErrTokenTooLarge`, checked before the split so nothing large is
  decoded. A bearer token is a credential, not a document. The default is
  `jwt.DefaultMaxTokenBytes`, 8 KiB, past every token the family's
  issuers mint; a negative value is no bound, for a caller whose tokens
  are larger.
- `jwt.Config.MaxTokenAge` is how old `iat` may be before a token is
  `jwt.ErrTokenTooOld`, whatever `exp` it carries, so an issuer that
  mints a long-lived token does not thereby mint a credential that
  outlives the day it was issued in. The default is
  `jwt.DefaultMaxTokenAge`, a day; a negative value is no bound.
  `jwt.Config.RequireIssuedAt` refuses a token that stamps no `iat` at
  all, for a caller whose issuers always stamp one; without it a token
  with no `iat` has no age and verifies as it always did. An `iat` of 0 is
  not an absent one: it names the epoch, so it is ancient.
- `jwt.Config.LocalIssuer`, `LocalKey` and `LocalKeyID` verify one
  issuer's tokens against a configured key with no JWKS fetch: the tokens
  a process mints for itself, and a stub issuer a test stands up with no
  server. A token naming the local issuer is checked against that key
  alone, under the kid `LocalKeyID` names, and is not checked against
  `Config.Issuer`; every other token takes the JWKS path unchanged. `New`
  panics on a local issuer configured without a usable key, because such
  a verifier would refuse its own tokens as bad signatures, which is a
  wiring mistake and not a verdict.

These are the family's C5 (`latere-ai/specs`,
`decisions/2026-09-13-one-platform-open-cores.md`): the options Origo's
verifier has and this one lacked, so that one verifier serves every core.
ES256 beside RS256, the fourth of them, shipped in v0.66.0.

### Changed

- The two new bounds are refusals a caller that configures neither did not
  have: a token above 8 KiB, and one whose `iat` is more than a day old
  under an `exp` that is still in the future. Set `MaxTokenBytes: -1` or
  `MaxTokenAge: -1` to keep the old behaviour exactly.
- `Validator.Validate` decodes the payload before it chooses the keys,
  because the `iss` it carries is what selects them. A token that is both
  malformed in the payload and wrong in the signature now reads as
  `ErrMalformedToken` where it read as `ErrInvalidSignature`, and it no
  longer reaches the key set. Every other order is unchanged.

## v0.70.1 - 2026-09-16

### Fixed

- `authz/server` routed every action whose name ends in `.list` to
  `Options.Lister` and answered 400 where none was configured, so a core
  whose list actions answer decisions could not use the scaffold without
  a Lister that decides and renders. That rule was Origo's `repo.list` —
  a directory page of repositories and a cursor — generalised from the
  one core that has one. The contract's own rule is the opposite: a list
  action answers a decision whose `Filter` narrows the core's list, which
  is what Cella's five list actions and Lux's four do. The verb no longer
  routes anything. Every action of the vocabulary reaches `Decider`, a
  list included, and its decision is written as a decision, `filter` and
  all; a page is what a core declares by name.
- `server.Options.PageActions []string` is that declaration: the actions
  whose answer is a page of the core's own shape. Each is routed to
  `Options.Lister`, which is now required only when `PageActions` names
  one. Origo keeps its directory with `PageActions: []string{"repo.list"}`;
  a core whose lists are decisions sets neither field and drops the
  Lister it only had to satisfy the routing. `New` panics on a
  `PageActions` with no `Lister`, and on an entry the `Vocabulary` does
  not name, beside the two wiring panics it already had.
- `conformance.WithPageActions(actions ...string)` tells a run which
  actions answer pages: those are checked for the 200 and a JSON object,
  because the contract fixes no field of a body whose shape is the core's
  own, and every other action is checked for a decision. A run that does
  not call it accepts either shape for an action whose verb is list, so
  an authorizer of either kind passes. `WithPageActions()` with no action
  is a declaration too: every action, a list included, answers a
  decision.

### Changed

- `authz.IsList` is a vocabulary helper and no longer a routing rule. It
  still reports whether an action's verb is list, which the cores and the
  conformance suite read; what an action answers is
  `server.Options.PageActions`.
- The `latere.authz.decisions` counter records `result=list` for an
  action of `PageActions` alone. A list action that is decided is counted
  `allow` or `deny` with its reason, like every other decision.
- `stub.WithAction` is the stub's half of `PageActions`, and its
  behaviour is unchanged: an action registered there answers a page, and
  an action left unregistered answers from the rule table whatever its
  verb, `Rule.Filter` included.

## v0.70.0 - 2026-09-16

### Added

- `authz.Vocabulary`, a core's action table as data, read by the client,
  the endpoint and the conformance suite instead of copied into each
  (latere-ai/specs
  `infrastructure/identity/id-11-one-authorizer-library.md`, design (c)).
  A core declares `authz.NewVocabulary("origo", authz.Action{Name:
  "repo.read", Kind: "Repository"}, ...)` once, in a package it publishes
  at its module root, and gets `Known`, `Kind` and `Kinds` over it;
  `NewVocabulary` refuses a table that is no map from action to kind, so
  a duplicate name or a row with no kind is an error where the table is
  written and never at run time. `authz.IsList` names the one action
  whose answer is a page rather than a verdict. Set it as
  `authz.Options.Vocabulary` and `Client.Authorize` refuses an action
  outside it before the wire, as `*authz.UnknownAction` and never as an
  `*Unavailable`: a typo in a core is caught by that core's own tests, it
  is not retried, and no core fails closed on it. A client that sets none
  behaves exactly as before.
- `conformance.WithVocabulary(v)`, which drives a case per row of a
  declared table rather than the rows somebody wrote out by hand, and
  adds the one check a hand-written list cannot support: an action
  outside the table answers 400 and never a deny. `WithActions` stays for
  an endpoint that is not a core's, and a run that uses it is unchanged.
  A list action's answer is a page of the core's own shape, so the check
  there is the 200 alone.
- `stub.WithVocabulary(v)`, so the stub authorizer a test tier runs
  refuses an unknown action with the 400 the endpoint will, rather than
  answering it from the rule table.
- `authz/server`, the endpoint half of the contract, so an authorizer is
  written once (same leaf, design (b)). `server.New(server.Options{...})`
  is an `http.Handler` that owns the bearer — the current token or its
  successor, compared in constant time, so a rotation is two deploys and
  no outage — one body bound (`DefaultMaxBody`, 64 KiB, overridable), the
  decode into `authz.Request`, the validation of the action and the
  resource kind against the vocabulary, the probe rule, the failure
  mapping and the `{result, reason}` counter. What you write is
  `Decider.Decide(ctx, req) (authz.Decision, error)`, and
  `server.ErrUnavailable` — or `server.Unavailable(reason)`, which names
  the reason the 503 is counted with — for the answers your state cannot
  give: no snapshot, a snapshot too stale for this action. The handler
  renders it as the 503 a core reads as authorizer_unavailable and never
  as an allow. `server.Lister` answers an action whose reply is a page of
  your own shape; the handler writes what it returns and names nothing
  about it. Two rules it owns rather than trusting a decider with: an
  action outside the vocabulary is a 400, not a deny, and the reserved
  probe id is denied before the routing, a list action included.
  `conformance.Run` against a `server.New` over a four-line decider
  passes every rule of the contract.

### Changed

- `conformance.Action` is an alias of `authz.Action` rather than a type
  of its own, so a vocabulary declared once is passed to `WithActions`
  unchanged. `go vet` now reports an unkeyed literal of it, because the
  type is another package's: write `conformance.Action{Name: "repo.read",
  Kind: "Repository"}` where you wrote `conformance.Action{"repo.read",
  "Repository"}`. The fields, their order and the wire are unchanged.
- The stub authorizer denies the reserved probe id before it builds an
  answer registered with `stub.WithAction`. Such an answer is a page and
  carries no verdict, and the rule that the probe is denied for every
  subject and action binds every action. A test that asserted a page for
  the probe id on a registered action now reads a deny; every other
  request is answered as before.
- `pkg/provenance`, the family's answer to "on whose behalf did this service
  act, and by what path did the call arrive" (latere-ai/specs
  `infrastructure/provenance.md`). The verified edge — the first service that
  validated the person's token — calls `provenance.Stamp` once, which puts
  three members in the W3C Baggage header that already rides every hop:
  `initiator.sub` (the issuer-qualified subject `<iss>|<sub>`, rendered by
  `authz.Subject`), `initiator.iss` and `entry` (the front door's host).
  Every service after it calls `provenance.From`, and never sets. The carrier
  needed no work: `otel.Bootstrap` has installed a composite
  `TraceContext`+`Baggage` propagator all along, so what was missing was a
  producer.

  `provenance.Attrs(ctx)` and `provenance.SpanAttrs(ctx)` emit the same three
  keys on a log line and on a span, so a reader who learns the vocabulary in
  one place finds it in the other. `provenance.Audit` and
  `provenance.AuditAttrs` write the durable record: one `slog` record at info
  with a fixed `audit=true` attribute, plus `action`, `resource` and
  `outcome`. `at`, `service`, `trace_id` and `span_id` are already on every
  record from `otel.SetupLogs`, so the helper adds nothing that exists.

  `provenance.Assert(ctx, id, issuer)` is for a hop that verifies a person's
  token behind an edge that already stamped: it returns a `*MismatchError`
  wrapping `ErrInitiatorMismatch` when the two subjects disagree, which the
  caller answers with `400 invalid_request` and one security event naming both
  values. It never overwrites and never silently accepts. A service, agent or
  dev principal asserts nothing: unattended work has no initiator, and the
  absence of the members is the correct record of it.

  Nothing here is authority. Baggage is unauthenticated, it grants nothing,
  and forging it buys a misleading log line and no access. So nothing here
  fails a call either: `Stamp` returns `ctx` unchanged and logs at warn when a
  value cannot be encoded or the edge passed no issuer — `authz.Subject`
  renders an empty issuer as `|<sub>`, and half an initiator is not an
  initiator — and `From` reports `ok` false rather than an error.

  Two notes for readers of the spec:

  - `Stamp` and `Assert` take the `issuer` as an argument, which the spec's
    sketch does not show. `authkit.Identity` carries no issuer — the claim is
    verified by `jwt.Validator` and stops there, since
    `Claims.authenticated()` copies only the embedded `Identity`. The spec's
    own member table names two sources for `initiator.sub`, the identity's
    `Sub` *and* the issuer, so the edge supplies the issuer it verified
    against. `Assert` needs it for the same reason: comparing bare subs alone
    would accept a same-sub, different-issuer contradiction, which is the one
    thing the rule exists to catch.
  - The fields are `initiator.*`, not `pkg/audit`'s `Actor{Type, PrincipalID,
    OwnerSub}`. `pkg/audit` is untouched and unimported: the spec calls the
    two layers rather than two standards, and leaves re-expressing `Actor` to
    whoever next touches that package. `actor` stays the family's name for
    the one-hop token kind, so `initiator` is the word for metadata that
    grants nothing.

## v0.69.0 - 2026-09-16

### Added

- `authkit.Identity.PreferredUsername`, `.OrgSlug` and `.OrgName`, the
  issuer's display labels for the person and for the active organisation
  (latere-ai/specs `infrastructure/identity/id-06-code-control-plane.md`,
  "The origo-web repoint: the token carries the labels"). Once the auth
  service stamps `preferred_username`, `org_slug` and `org_name` on an
  actor token, `jwt.Validator.Validate` and `jwt.ParseUnverified` both
  surface all three, so a service names the owner of a resource from the
  token it has already verified instead of asking the issuer for a handle
  or an organisation name. Each claim is optional and its field is empty
  without it: `PreferredUsername` until the person claims a handle,
  `OrgSlug` and `OrgName` whenever `OrgID` is empty. They are display only
  and confer nothing — the membership a service decides from stays `OrgID`
  and `Roles`. A claim carrying a non-string value is `ErrMalformedToken`,
  the refusal `org_id` and `email` have always had; none of the three
  decodes a number or a list to an empty field.

## v0.68.0 - 2026-09-15

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
  `prompt_cache_key`. Chat: `prompt_cache_key`, else vLLM's `cache_salt`
  extension; both are known request keys now rather than unknown-field
  loss, and `cache_salt` is still recorded as `ir.LossCacheSalt` because
  the partition it puts on the engine's cache has no IR member and does
  not reach the upstream. Messages, which has no key member: the
  breakpoints its `cache_control` blocks mark, as the lowercase hex
  SHA-256 of the system and message content up to and including the
  last one, so two requests that share that prefix share the key
  whatever follows. `ir.PrefixCacheKeys` is that hash, documented byte
  for byte (role, type and the block's content fields, each as a
  netstring) and fixed, and returns one key per breakpoint in order so
  a router can fall back to a shorter prefix. The lux dialect carries
  the field as `cache_key`, verbatim and never derived, since a lux
  caller names its own.

### Changed

- `llmdialect/ir.Usage.CacheReadInputTokens` and `CacheWriteInputTokens`
  are `*int64`: nil when the backend reported no such figure, a pointer
  to the count, zero included, when it did. They were plain integers,
  so an engine without per-request cache accounting (an
  OpenAI-compatible server that writes no `prompt_tokens_details`)
  decoded to zero, and the Anthropic frontend then wrote
  `cache_read_input_tokens: 0` and `cache_creation_input_tokens: 0`,
  which a Messages-API client reads as a measurement that found nothing
  cached, the opposite of "not measured". Now the `openaichat` and
  `openairesp` backends set the read count only when
  `prompt_tokens_details.cached_tokens` (Chat) or
  `input_tokens_details.cached_tokens` (Responses) is present, and never
  a write count, since neither wire has one; the `anthropic` backend
  sets each from its own member when present, on `message_delta` as
  well as `message_start`, where a later zero never erases a count
  already reported; the `anthropic` frontend omits each key whose count
  is nil and writes it, zero included, when it is not, on the response
  body, `message_start`, and `message_delta` alike; the OpenAI-shaped
  frontends keep writing `cached_tokens` as 0 for nil, since those wires
  always carry the member and their readers take 0 as "no cache read".
  `lux.Usage` (and so `luxsdk.Usage`) carries the two as `*int64` with
  `omitempty`, as it already carries `cost_usd_micro`: nil is no key, an
  explicit zero travels as `0`. `bridge.Usage` is unchanged, a floored
  total for a meter. What to do about it: a consumer that read the two
  fields dereferences them after a nil check, nil meaning unknown; one
  that built an `ir.Usage` or `lux.Usage` literal takes the address of
  the count; and a `==` between two `ir.Usage` values now compares
  pointers, so compare members or use `reflect.DeepEqual`.

### Fixed

- `llmdialect/openaichat`: the backend reads a model's thinking under
  `reasoning` as well as `reasoning_content`, on `choices[].message` and
  on stream deltas alike. vLLM's OpenAI-compatible server names the
  member `reasoning` in some versions, and the codec read only the
  original spelling, so a caller behind such a server saw the answer
  with no thinking block and no thinking deltas, indistinguishable from
  a model that did not think. `reasoning_content` wins when a body
  carries both, and a `reasoning` member that is not a string is ignored
  rather than failing the decode. The frontend still writes
  `reasoning_content` only.

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
