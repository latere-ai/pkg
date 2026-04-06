package otel

import (
	"context"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// TraceHeaderName is the HTTP response header containing the trace ID.
const TraceHeaderName = "X-Trace-Id"

// Handler wraps an http.Handler with OpenTelemetry tracing and metrics.
// It injects the trace ID as a response header for client-side correlation.
func Handler(h http.Handler, operation string) http.Handler {
	// Wrap the inner handler to set the trace header before writing the response.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID, _ := TraceIDs(r.Context())
		if traceID != "" {
			w.Header().Set(TraceHeaderName, traceID)
		}
		h.ServeHTTP(w, r)
	})
	return otelhttp.NewHandler(inner, operation)
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
