# otel

OpenTelemetry traces, metrics, and structured logs for Go services. Disabled by default (zero overhead). Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable OTLP/HTTP export.

## Getting started

`Bootstrap` wires logging, traces, and metrics in one call and sets the slog default. That is all most services need.

### HTTP service

```go
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger, shutdown, err := otel.Bootstrap(ctx, otel.Config{ServiceName: "my-service"})
	if err != nil {
		logger.Warn("otel log bridge degraded", "err", err)
	}
	defer shutdown(context.Background())

	srv := &http.Server{
		Addr:    ":8080",
		Handler: otel.Handler(mux, "my-service"),
	}
	if err := otel.RunServer(ctx, srv, 5*time.Second, nil); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
```

### Worker or CLI (no HTTP server)

```go
logger, shutdown, err := otel.Bootstrap(ctx, otel.Config{ServiceName: "my-worker"})
if err != nil {
	logger.Warn("otel log bridge degraded", "err", err)
}
defer shutdown(context.Background())
// ... run the worker loop; logs/traces/metrics flow automatically.
```

### Calling another service

The instrumented client propagates the trace context, so a downstream service's spans join the caller's trace. A plain `http.Client` leaves both sides with spans that are never linked.

```go
client := otel.HTTPClient()              // or otel.Transport(base) to wrap a custom RoundTripper
resp, err := client.Do(req.WithContext(ctx))
```

### Deploy

Export starts when the deployment sets the OTLP endpoint. In Kubernetes that is an env var pointing at the collector service:

```yaml
env:
  - name: OTEL_EXPORTER_OTLP_ENDPOINT
    value: http://otel-collector.<namespace>.svc:4318
```

Without it the instrumentation is a noop: spans are created and discarded, and nothing reaches a backend. Importing the package and setting the variable are both required for a service to be observable.

## Functions

- `Bootstrap(ctx, Config)` — one-call logs + traces + metrics; sets slog default; returns a combined shutdown. Noop export when the endpoint is unset.
- `RunServer(ctx, srv, timeout, preShutdown)` — runs an `http.Server` and shuts it down gracefully when ctx is cancelled. Caller owns signals and handler wrapping.
- `Version(override)` — resolves a version string from the override, then build info (module version or short VCS revision), then `"dev"`.
- `Replica()` — resolves a replica label from `POD_NAME`, `HOSTNAME`, or the OS hostname.
- `Transport(base)` / `HTTPClient()` — instrument an outbound `http.Client` and propagate the trace context.
- `Setup(ctx, name, version)` — lower-level traces + metrics only (used by `Bootstrap`).
- `SetupLogs(ctx, LogsConfig)` — lower-level logging only (used by `Bootstrap`).
- `Handler(h, operation, opts...)` — wraps an `http.Handler` with tracing/metrics and sets the `X-Trace-Id` response header.
- `TraceIDs(ctx)` / `LogAttrs(ctx)` — extract trace/span IDs for log correlation.

## Logging

Records emitted inside a span carry `trace_id` and `span_id` on both streams:
the OTLP bridge attaches span context structurally, and the local handler gets
the same two fields as attributes. Copy a `trace_id` out of `kubectl logs` and
it resolves in the backend.

Both depend on the call carrying the request context. What that means in
practice:

- Request-path logs (handlers, middleware, anything whose context derives from
  `r.Context()`) use the `*Context` variants: `slog.InfoContext(ctx, ...)`,
  `logger.ErrorContext(ctx, ...)`.
- Startup, shutdown, and background-loop logs stay plain. They have no request
  trace, and converting them adds noise.
- Work that outlives the request (queues, async pipelines) keeps correlation
  with `context.WithoutCancel(reqCtx)`.
- Where threading a context is disproportionate, append `LogAttrs(ctx)...` to
  a plain call instead. Prefer the `*Context` variants: they reach the OTLP
  bridge too, which `LogAttrs` cannot do.

Outbound HTTP follows the same rule: wrap `Transport` and build requests with
`http.NewRequestWithContext`, otherwise the trace ends at the hop.

## Environment Variables

| Variable | Description |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint URL (required to enable export) |
| `OTEL_EXPORTER_OTLP_HEADERS` | Optional headers (e.g. `Authorization=Basic <base64>`) |
| `OTEL_TRACES_SAMPLER_ARG` | Head-sampling ratio for root spans, `0`–`1` (default `0.2`). `ParentBased`, so a sampled trace stays whole across services. Set `1.0` to sample everything. |
| `LATERE_ENV` | Deployment environment (`deployment.environment.name` resource attribute; defaults to `production`) |
| `POD_NAME` | Replica label (set from `metadata.name` in k8s) |
| `OTEL_SDK_DISABLED` | `true` turns every signal off even when an endpoint is set. Local logging keeps working. |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes, `k=v,k=v`. Cannot override `service.name` or `service.version`, which come from `Config`. |
