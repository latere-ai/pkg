package otel

import (
	"context"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// Handler wraps an http.Handler with OpenTelemetry tracing and metrics.
func Handler(h http.Handler, operation string) http.Handler {
	return otelhttp.NewHandler(h, operation)
}

// TraceIDs extracts the trace ID and span ID from the context.
// Returns empty strings if no active span exists.
func TraceIDs(ctx context.Context) (traceID, spanID string) {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		traceID = span.SpanContext().TraceID().String()
		spanID = span.SpanContext().SpanID().String()
	}
	return
}
