# pkg

Shared Go packages for [Latere AI](https://latere.ai).

## Packages

### `otel`

OpenTelemetry tracing and metrics setup. Disabled by default (zero overhead). Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable OTLP/HTTP export.

```go
import "latere.ai/x/pkg/otel"

shutdown := otel.Setup(ctx, "my-service", "1.0.0")
defer shutdown()

srv := &http.Server{
    Handler: otel.Handler(mux, "my-service"),
}
```

Environment variables:

| Variable | Description |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint URL (required to enable) |
| `OTEL_EXPORTER_OTLP_HEADERS` | Optional headers (e.g. `Authorization=Basic <base64>`) |

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
