# otel

OpenTelemetry tracing and metrics setup. Disabled by default (zero overhead). Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable OTLP/HTTP export.

## Usage

```go
import "latere.ai/x/pkg/otel"

shutdown := otel.Setup(ctx, "my-service", "1.0.0")
defer shutdown()

srv := &http.Server{
    Handler: otel.Handler(mux, "my-service"),
}

// Log correlation
traceID, spanID := otel.TraceIDs(ctx)
```

### Functions

- `Setup(ctx, name, version)` — initializes tracing and metrics; noop when endpoint is unset
- `Handler(h, operation)` — wraps `http.Handler` with tracing/metrics and sets `X-Trace-Id` response header
- `TraceIDs(ctx)` — extracts trace ID and span ID from context

## Environment Variables

| Variable | Description |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint URL (required to enable) |
| `OTEL_EXPORTER_OTLP_HEADERS` | Optional headers (e.g. `Authorization=Basic <base64>`) |
| `LATERE_ENV` | Deployment environment (sets `deployment.environment` resource attribute; defaults to `production`) |
