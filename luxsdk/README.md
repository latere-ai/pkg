# luxsdk

The first-party Go client for the Lux gateway's native dialect
(`POST /lux/v1/generate`): one typed request/response/stream shape for
every model Lux routes. Wire types are re-exports of
`latere.ai/x/pkg/llmdialect/lux`, so the SDK cannot drift from the
gateway codec.

```go
import "latere.ai/x/pkg/luxsdk"
```

## Callers

Both caller kinds expose the same `Caller` surface (`Generate` for one
JSON response and `Stream` for SSE), so call sites are agnostic to how
the model is reached. The gateway `Client` additionally offers
`CountTokens`. TypeScript and Python clients with the same surface
live in their own public repos: [lux-typescript-sdk](https://github.com/latere-ai/lux-typescript-sdk)
and [lux-python-sdk](https://github.com/latere-ai/lux-python-sdk).

```go
// Through a Lux deployment: key custody, gates, metering, routing.
c := luxsdk.New("https://api.latere.ai/v1/models", luxsdk.WithAPIKey(key))

// Provider-direct: BYO endpoint + key; the dialect translation runs
// client-side through the same llmdialect backends the gateway uses.
d, err := luxsdk.NewDirect(luxsdk.ProviderAnthropic, key, "")
```

Both connection values fall back to `LUX_BASE_URL` and `LUX_API_KEY`
when omitted, so a process configured by `eval "$(latere lux env
--compat lux)"` can construct with neither:

```go
c := luxsdk.New("")
```

Explicit arguments always win: the environment only fills what the
caller left unset, so exporting `LUX_BASE_URL` can never redirect a
client that passed its own. The Go, TypeScript, and Python clients
apply the same precedence, so one environment configures all three
identically.

`Provider` is a closed enum: `ProviderAnthropic`, `ProviderOpenAI`
(reasoning models are routed to `/v1/responses` automatically),
`ProviderGemini` (openai-compat prefix), `ProviderOpenRouter`,
`ProviderOllama` (unauthenticated when no key is set),
`ProviderMoonshot`, `ProviderXai`, and `ProviderZhipu` (whose chat
endpoint lives under `/api/paas/v4`, not `/v1`).

Auth options: `WithAPIKey` (static bearer; provider key in direct
mode), `WithTokenSource` (a per-call bearer for a credential that
rotates; the gateway still takes only a Key value, never a Latere
Auth token a platform did not register as one),
`WithOAuthToken` (direct Anthropic only: bearer + OAuth beta header),
`WithHTTPClient`.

## Cost attribution

```go
c := luxsdk.New("https://api.latere.ai/v1/models", luxsdk.WithAPIKey(key),
    luxsdk.WithCostTags(map[string]string{"tenant": "acme", "project": "web"}))
```

`WithCostTags` labels every call, sent as the `Lux-Labels` header
(sorted `key=value` pairs, e.g. `project=web,tenant=acme`) on
`Generate`, `Stream`, and `CountTokens`. Gateway `Client` only; a nil
or empty map sends no header.

Lux records the pairs as the request's own labels, apart from the
Key's labels, and shows them in its request history (`GET
/v1/requests`). They are for reporting only: never an aggregate
dimension of usage, never a split of a budget or a bill, and never a
change to who is billed or what the key can reach. Lux never forwards
the header to the provider.

The gateway keeps at most 8 pairs, each key 1 to 64 characters of
`[A-Za-z0-9._-]` and each value 1 to 128 characters of
`[A-Za-z0-9._:/-]`. A pair that breaks the rule, and every valid pair
past the eighth in sorted key order, is dropped and the request still
runs: a bad label costs the label, never the call. A key or value
holding `,` or `=` breaks the wire form: the gateway reads it as other
pairs or drops it.

## Requests

```go
maxTokens := int64(4096)
res, err := c.Generate(ctx, &luxsdk.Request{
    Model:     "claude-sonnet-5",
    MaxTokens: &maxTokens,
    System:    []luxsdk.Block{{Type: luxsdk.BlockText, Text: "Be brief.", CacheHint: true}},
    Messages:  []luxsdk.Message{luxsdk.UserText("hello")},
    Tools:     []luxsdk.Tool{{Name: "bash", Description: "run", InputSchema: schema}},
    Reasoning: &luxsdk.Reasoning{Effort: luxsdk.EffortHigh}, // or BudgetTokens
})
```

Messages are two-role (`RoleUser` / `RoleAssistant`); tool results are
`BlockToolResult` blocks inside a user turn. Block types:
`text`, `image`, `tool_use`, `tool_result`, `thinking`,
`redacted_thinking`. `Generate` forces `stream: false`; `Stream`
forces it on. The flag on the request is never trusted.

## Streaming

The stream grammar is the gateway IR's, verbatim:

```
message_start (block_start (text_delta|args_delta|thinking_delta|signature_delta)* block_stop)* message_delta message_stop
```

```go
st, err := c.Stream(ctx, req)
defer st.Close()
for {
    ev, err := st.Next() // io.EOF after message_stop
    ...
}
```

Assemble a streamed tool call from `block_start` (id, name) +
`args_delta` fragments, closed by `block_stop`. `Usage` appears on
`message_start` (input side) and `message_delta` (output side);
accumulate both. A mid-stream gateway failure surfaces from `Next` as
`*StreamError`.

## Usage and cost

`res.Usage` carries the call's token counts and, when the gateway
reports one, its cost:

```go
if c := res.Usage.CostUSDMicro; c != nil {
    fmt.Println(*c) // millionths of a USD, as reported by the gateway
}
```

`CostUSDMicro` is nil when the gateway reported no cost. Nil means
unknown, not free: a reported zero cost arrives as a pointer to zero,
so the two cases stay distinguishable for a caller that must refuse to
spend against an unknown price.

## Token counting

```go
tc, err := c.CountTokens(ctx, req) // POST /lux/v1/count_tokens; no spend gates
// tc.InputTokens; tc.Estimated marks a heuristic count (no native tokenizer)
```

## Errors and loss

A non-2xx gateway answer decodes into `*Error` from the lux error
envelope:

```json
{"error":{"code":"model_not_found","message":"There is no model of that name.",
  "details":{"detail":"no Model named \"x\"","request_id":"req_..."}}}
```

`Code` is `error.code` from the gateway's code table
(`unauthenticated`, `model_not_found`, `rate_limited`,
`spend_exceeded`, `upstream_timeout`, ...), the field to switch on.
`Message` is the code's one fixed sentence for a person, `Detail` is
the developer's account of this failure, and `RequestID` is the id to
quote about it. A body that is not the envelope arrives whole as
`Message` with an empty `Code`. In direct mode, `Code` and `Message`
are the provider's own `error.type` and `error.message`.

Fields the target dialect cannot represent are never silently dropped:
they arrive as `Result.Loss` / `Stream.Loss()` (from the `Lux-Loss`
header in gateway mode, computed locally in direct mode).
`TokenCount.Estimated` comes from the `Lux-Estimated` header.
