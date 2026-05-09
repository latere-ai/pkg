package otel

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	otelglobal "go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
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

	if got := rec.Header().Get(TraceHeaderName); got == "" {
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

func TestLogAttrs(t *testing.T) {
	if got := LogAttrs(context.Background()); got != nil {
		t.Errorf("no span: got %v, want nil", got)
	}
	tid := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid := trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)
	got := LogAttrs(ctx)
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	if got[0] != "trace_id" || got[1] != tid.String() {
		t.Errorf("trace_id slot wrong: %v %v", got[0], got[1])
	}
	if got[2] != "span_id" || got[3] != sid.String() {
		t.Errorf("span_id slot wrong: %v %v", got[2], got[3])
	}
}

// installRecorder swaps in a recording tracer provider for the duration of the
// test. otelhttp pulls from the global, so this gives us real spans to inspect.
func installRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(rec),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prev := otelglobal.GetTracerProvider()
	otelglobal.SetTracerProvider(tp)
	t.Cleanup(func() {
		otelglobal.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	return rec
}

func TestHandlerWithRouteAndSurface(t *testing.T) {
	rec := installRecorder(t)
	wrapped := Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}),
		"edge",
		WithRouteTemplate(func(r *http.Request) string { return "/v1/items/:id" }),
		WithSurfaceAttr(func(r *http.Request) string { return "public-api" }),
	)
	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/items/abc", nil))

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	span := spans[0]
	if !strings.HasPrefix(span.Name(), "GET /v1/items/:id") {
		t.Errorf("span name = %q, want prefix GET /v1/items/:id", span.Name())
	}
	attrs := map[string]string{}
	for _, kv := range span.Attributes() {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}
	if attrs["http.route"] != "/v1/items/:id" {
		t.Errorf("http.route = %q", attrs["http.route"])
	}
	if attrs["cella.surface"] != "public-api" {
		t.Errorf("cella.surface = %q", attrs["cella.surface"])
	}
}

func TestHandlerWithSurfaceAttrEmptyOmitsAttribute(t *testing.T) {
	rec := installRecorder(t)
	wrapped := Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		"op",
		WithRouteTemplate(func(r *http.Request) string { return "/x" }),
		WithSurfaceAttr(func(r *http.Request) string { return "" }),
	)
	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	for _, kv := range rec.Ended()[0].Attributes() {
		if string(kv.Key) == "cella.surface" {
			t.Fatalf("cella.surface should not be set when surface fn returns empty")
		}
	}
}

func TestHandlerWithSkipShortCircuits(t *testing.T) {
	rec := installRecorder(t)

	var hookCalls atomic.Int32
	wrapped := Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		"op",
		WithSkip(func(r *http.Request) bool { return r.URL.Path == "/healthz" }),
		WithMetricsHook(func(ctx context.Context, route, method, class string, dur time.Duration) {
			hookCalls.Add(1)
		}),
	)

	rrec := httptest.NewRecorder()
	wrapped.ServeHTTP(rrec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rrec.Code != http.StatusOK {
		t.Errorf("skipped path should still serve, got %d", rrec.Code)
	}
	if rrec.Header().Get(TraceHeaderName) != "" {
		t.Errorf("X-Trace-Id should not be set on skipped requests")
	}
	if hookCalls.Load() != 0 {
		t.Errorf("metrics hook fired on skipped request")
	}
	if got := len(rec.Ended()); got != 0 {
		t.Errorf("span recorded for skipped request: %d", got)
	}

	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/x", nil))
	if hookCalls.Load() != 1 {
		t.Errorf("metrics hook should fire on non-skipped request, got %d", hookCalls.Load())
	}
	if got := len(rec.Ended()); got != 1 {
		t.Errorf("span should be recorded for non-skipped request, got %d", got)
	}
}

func TestHandlerWithMetricsHookCarriesMethodAndClass(t *testing.T) {
	installRecorder(t)

	type call struct {
		route, method, class string
		dur                  time.Duration
	}
	var got call
	var fired atomic.Int32

	wrapped := Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}),
		"op",
		WithRouteTemplate(func(r *http.Request) string { return "/api/:id" }),
		WithMetricsHook(func(ctx context.Context, route, method, class string, dur time.Duration) {
			got = call{route: route, method: method, class: class, dur: dur}
			fired.Add(1)
		}),
	)

	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/abc", nil))
	if fired.Load() != 1 {
		t.Fatalf("hook fired %d times", fired.Load())
	}
	if got.route != "/api/:id" || got.method != http.MethodPost || got.class != "4xx" {
		t.Errorf("hook got %+v", got)
	}
	if got.dur < 0 {
		t.Errorf("duration negative: %v", got.dur)
	}
}

func TestStatusClass(t *testing.T) {
	cases := map[int]string{
		200: "2xx", 204: "2xx",
		301: "3xx", 308: "3xx",
		400: "4xx", 418: "4xx",
		500: "5xx", 599: "5xx",
		100: "2xx",
	}
	for code, want := range cases {
		if got := statusClass(code); got != want {
			t.Errorf("statusClass(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestStatusWriter(t *testing.T) {
	rr := &flushingHijackingRecorder{ResponseRecorder: httptest.NewRecorder()}
	sw := &statusWriter{ResponseWriter: rr, code: http.StatusOK}
	sw.WriteHeader(http.StatusTeapot)
	if sw.code != http.StatusTeapot {
		t.Errorf("code = %d", sw.code)
	}
	if sw.Unwrap() != rr {
		t.Errorf("Unwrap returned wrong writer")
	}
	sw.Flush()
	if !rr.flushed {
		t.Errorf("Flush did not delegate")
	}
	if _, _, err := sw.Hijack(); err != nil {
		t.Errorf("Hijack delegated err = %v", err)
	}

	// Hijack on a non-hijackable writer returns an error.
	sw2 := &statusWriter{ResponseWriter: &nonHijackWriter{}, code: 200}
	if _, _, err := sw2.Hijack(); err == nil {
		t.Errorf("Hijack should fail on non-hijackable writer")
	}

	// Flush is a noop when the underlying writer doesn't implement Flusher.
	sw3 := &statusWriter{ResponseWriter: &nonHijackWriter{}, code: 200}
	sw3.Flush() // must not panic
}

type flushingHijackingRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (r *flushingHijackingRecorder) Flush() { r.flushed = true }
func (r *flushingHijackingRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c1, c2 := net.Pipe()
	go func() { _ = c2.Close() }()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

type nonHijackWriter struct{}

func (nonHijackWriter) Header() http.Header       { return http.Header{} }
func (nonHijackWriter) Write([]byte) (int, error) { return 0, nil }
func (nonHijackWriter) WriteHeader(int)           {}
