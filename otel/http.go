package otel

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Handler wraps an http.Handler with OpenTelemetry tracing and metrics.
func Handler(h http.Handler, operation string) http.Handler {
	return otelhttp.NewHandler(h, operation)
}
