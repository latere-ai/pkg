package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestHandler(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := Handler(inner, "test-op")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
}

func TestHandlerWithActiveSpan(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := Handler(inner, "test-op")

	// Create a span context with a valid trace ID.
	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	spanID := trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	wrapped.ServeHTTP(rec, req)

	got := rec.Header().Get(TraceHeaderName)
	if got == "" {
		t.Error("expected X-Trace-Id header to be set")
	}
}

func TestTraceIDsWithSpan(t *testing.T) {
	tid := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid := trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	traceID, spanID := TraceIDs(ctx)
	if traceID != tid.String() {
		t.Errorf("traceID = %q, want %q", traceID, tid.String())
	}
	if spanID != sid.String() {
		t.Errorf("spanID = %q, want %q", spanID, sid.String())
	}
}

func TestTraceIDsNoSpan(t *testing.T) {
	traceID, spanID := TraceIDs(context.Background())
	if traceID != "" || spanID != "" {
		t.Errorf("expected empty strings, got traceID=%q spanID=%q", traceID, spanID)
	}
}
