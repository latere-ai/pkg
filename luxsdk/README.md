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

Both caller kinds expose the same `Caller` surface — `Generate` (one
JSON response) and `Stream` (SSE) — so call sites are agnostic to how
the model is reached. The gateway `Client` additionally offers
`CountTokens`. TypeScript and Python clients with the same surface
live in the lux repo (`sdk/typescript`, `sdk/python`).

```go
// Through a Lux deployment: key custody, gates, metering, routing.
c := luxsdk.New("https://lux.latere.ai", luxsdk.WithAPIKey(key))

// Provider-direct: BYO endpoint + key; the dialect translation runs
// client-side through the same llmdialect backends the gateway uses.
d, err := luxsdk.NewDirect(luxsdk.ProviderAnthropic, key, "")
```

`Provider` is a closed enum: `ProviderAnthropic`, `ProviderOpenAI`
(reasoning models are routed to `/v1/responses` automatically),
`ProviderGemini` (openai-compat prefix), `ProviderOpenRouter`,
`ProviderOllama` (unauthenticated when no key is set).

Auth options: `WithAPIKey` (static bearer; provider key in direct
mode), `WithTokenSource` (per-call token, e.g. a rotating JWT),
`WithOAuthToken` (direct Anthropic only: bearer + OAuth beta header),
`WithHTTPClient`.

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
forces it on — the flag on the request is never trusted.

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

## Token counting

```go
tc, err := c.CountTokens(ctx, req) // POST /lux/v1/count_tokens; no spend gates
// tc.InputTokens; tc.Estimated marks a heuristic count (no native tokenizer)
```

## Errors and loss

Non-2xx responses decode into `*Error{Status, Code, Message,
RequestID}` with the retryable type vocabulary (`rate_limit_error`,
`overloaded_error`, ...). Fields the target dialect cannot represent
are never silently dropped: they arrive as `Result.Loss` /
`Stream.Loss()` (from the `X-Lux-Compat-Loss` header in gateway mode,
computed locally in direct mode).
