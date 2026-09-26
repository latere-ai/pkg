// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	otelglobal "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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

func TestRouteFromPattern(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"GET /v1/parse/{id}":        "/v1/parse/{id}",
		"/static/":                  "/static/",
		"POST /x":                   "/x",
		"GET example.com/v1/x/{id}": "/v1/x/{id}",
		"unknown":                   "",
	}
	for in, want := range cases {
		if got := routeFromPattern(in); got != want {
			t.Errorf("routeFromPattern(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHandlerRouteFromServeMuxPattern verifies that without an explicit
// WithRouteTemplate, http.route is derived from the Go 1.22 ServeMux pattern the
// mux sets on the request after matching — bound IDs collapse to {id}.
func TestHandlerRouteFromServeMuxPattern(t *testing.T) {
	rec := installRecorder(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/parse/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := Handler(mux, "testsvc")

	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/parse/prs_abc123", nil))

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	var route string
	for _, kv := range spans[0].Attributes() {
		if string(kv.Key) == "http.route" {
			route = kv.Value.AsString()
		}
	}
	if route != "/v1/parse/{id}" {
		t.Errorf("http.route = %q, want /v1/parse/{id}", route)
	}
}

// installMeterReader swaps in a meter provider backed by a manual reader for
// the duration of the test. otelhttp resolves its meter from the global
// provider when the handler is built, so call this before Handler.
func installMeterReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otelglobal.GetMeterProvider()
	otelglobal.SetMeterProvider(mp)
	t.Cleanup(func() {
		otelglobal.SetMeterProvider(prev)
		if err := mp.Shutdown(context.Background()); err != nil {
			t.Errorf("meter provider shutdown: %v", err)
		}
	})
	return reader
}

// requestRoutes collects http.server.request.duration and returns the number
// of recorded requests per http.route value. Data points without http.route
// count under "". An empty map means no request was recorded.
func requestRoutes(t *testing.T, reader *sdkmetric.ManualReader) map[string]uint64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	routes := map[string]uint64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			hist, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("%s is %T, want Histogram[float64]", m.Name, m.Data)
			}
			for _, dp := range hist.DataPoints {
				v, _ := dp.Attributes.Value(attribute.Key("http.route"))
				routes[v.AsString()] += dp.Count
			}
		}
	}
	return routes
}

func assertRoutes(t *testing.T, got, want map[string]uint64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("request metrics by http.route = %v, want %v", got, want)
	}
	for route, n := range want {
		if got[route] != n {
			t.Fatalf("request metrics by http.route = %v, want %v", got, want)
		}
	}
}

// TestHandlerRouteTemplateLabelsRequestMetrics covers the request metrics
// otelhttp records for a hand-written router. The request has no ServeMux
// pattern, so http.route on the metrics comes only from the template. Traces
// are never sampled here: the metrics are recorded for every request, and the
// route must reach them whether or not the span is kept.
func TestHandlerRouteTemplateLabelsRequestMetrics(t *testing.T) {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample()))
	prevTP := otelglobal.GetTracerProvider()
	otelglobal.SetTracerProvider(tp)
	t.Cleanup(func() {
		otelglobal.SetTracerProvider(prevTP)
		if err := tp.Shutdown(context.Background()); err != nil {
			t.Errorf("tracer provider shutdown: %v", err)
		}
	})

	t.Run("template", func(t *testing.T) {
		reader := installMeterReader(t)
		wrapped := Handler(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
			"op",
			WithRouteTemplate(func(r *http.Request) string { return "/v1/items/:id" }),
		)
		wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/items/a", nil))
		wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/items/b", nil))
		assertRoutes(t, requestRoutes(t, reader), map[string]uint64{"/v1/items/:id": 2})
	})

	t.Run("empty template omits route", func(t *testing.T) {
		reader := installMeterReader(t)
		wrapped := Handler(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			"op",
			WithRouteTemplate(func(r *http.Request) string { return "" }),
		)
		wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
		assertRoutes(t, requestRoutes(t, reader), map[string]uint64{"": 1})
	})
}

// TestHandlerServeMuxPatternLabelsRequestMetrics pins the ServeMux case.
// Without a template the matched pattern is the route. With one, the template
// decides for matched and unmatched requests alike: a service that names its
// routes is not overridden by whatever pattern a mux inside it matched.
func TestHandlerServeMuxPatternLabelsRequestMetrics(t *testing.T) {
	newMux := func() *http.ServeMux {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /v1/parse/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		return mux
	}

	t.Run("pattern", func(t *testing.T) {
		reader := installMeterReader(t)
		wrapped := Handler(newMux(), "testsvc")
		wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/parse/prs_abc123", nil))
		assertRoutes(t, requestRoutes(t, reader), map[string]uint64{"/v1/parse/{id}": 1})
	})

	t.Run("pattern and template", func(t *testing.T) {
		reader := installMeterReader(t)
		wrapped := Handler(newMux(), "testsvc",
			WithRouteTemplate(func(r *http.Request) string { return "/v1/parse/:id" }),
		)
		wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/parse/prs_abc123", nil))
		wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/unknown", nil))
		assertRoutes(t, requestRoutes(t, reader), map[string]uint64{"/v1/parse/:id": 2})
	})
}

// spanRoutes returns each ended span's name and http.route, in order.
func spanRoutes(rec *tracetest.SpanRecorder) [][2]string {
	var out [][2]string
	for _, s := range rec.Ended() {
		route := ""
		for _, kv := range s.Attributes() {
			if kv.Key == "http.route" {
				route = kv.Value.AsString()
			}
		}
		out = append(out, [2]string{s.Name(), route})
	}
	return out
}

func serve(h http.Handler, method, target string) {
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, target, nil))
}

// A service with a route table mounted under a catch-all: the mux matches "/"
// for every request, and before the template decided the route, that pattern
// replaced the template on the request metrics.
func TestTemplateDecidesOverAMatchedMount(t *testing.T) {
	rec := installRecorder(t)
	reader := installMeterReader(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
	wrapped := Handler(mux, "svc", WithRouteTemplate(func(r *http.Request) string {
		if strings.HasPrefix(r.URL.Path, "/v1/items/") {
			return "/v1/items/{id}"
		}
		return ""
	}))

	serve(wrapped, http.MethodGet, "/v1/items/a")
	serve(wrapped, http.MethodGet, "/nowhere")

	assertRoutes(t, requestRoutes(t, reader), map[string]uint64{"/v1/items/{id}": 1, "": 1})
	want := [][2]string{{"GET /v1/items/{id}", "/v1/items/{id}"}, {"GET", ""}}
	if got := spanRoutes(rec); !slices.Equal(got, want) {
		t.Errorf("spans = %q, want %q", got, want)
	}
}

type copyKey struct{}

// A router behind middleware that copies the request sets its pattern on the
// copy, which Handler never sees, so without SetRoute the request had no route.
func TestSetRouteBehindARequestCopy(t *testing.T) {
	for _, record := range []bool{false, true} {
		t.Run(fmt.Sprintf("SetRoute=%v", record), func(t *testing.T) {
			rec := installRecorder(t)
			reader := installMeterReader(t)
			mux := http.NewServeMux()
			mux.HandleFunc("GET /v1/sandboxes/{id}", func(w http.ResponseWriter, r *http.Request) {
				if record {
					SetRoute(r.Context(), r.Pattern)
				}
			})
			copying := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), copyKey{}, 1)))
			})
			serve(Handler(copying, "svc"), http.MethodGet, "/v1/sandboxes/sb_1")

			route, name := "", "GET"
			if record {
				route, name = "/v1/sandboxes/{id}", "GET /v1/sandboxes/{id}"
			}
			assertRoutes(t, requestRoutes(t, reader), map[string]uint64{route: 1})
			if got := spanRoutes(rec); !slices.Equal(got, [][2]string{{name, route}}) {
				t.Errorf("spans = %q, want name %q route %q", got, name, route)
			}
		})
	}
}

// Nested routers that each record the pattern they matched: the innermost is
// the last to run, so its route stands. A route recorded with SetRoute also
// takes precedence over the template.
func TestSetRouteInnermostWins(t *testing.T) {
	reader := installMeterReader(t)
	inner := http.NewServeMux()
	inner.HandleFunc("GET /v1/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		SetRoute(r.Context(), r.Pattern)
	})
	outer := http.NewServeMux()
	outer.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		SetRoute(r.Context(), r.Pattern)
		inner.ServeHTTP(w, r.WithContext(r.Context()))
	})
	wrapped := Handler(outer, "svc", WithRouteTemplate(func(*http.Request) string { return "/v1/*" }))

	serve(wrapped, http.MethodGet, "/v1/items/a")
	serve(wrapped, http.MethodGet, "/v1/other")

	assertRoutes(t, requestRoutes(t, reader), map[string]uint64{"/v1/items/{id}": 1, "/v1/": 1})
}

// Handler mounted under a subtree of a mux in front of it: the outer pattern
// is on the request before otelhttp sees it, and used to label every request
// under the mount. The inner route replaces it, and a request the inner mux
// does not serve carries no route rather than the mount's.
func TestRouteOfAMuxInFrontOfHandler(t *testing.T) {
	reader := installMeterReader(t)
	inner := http.NewServeMux()
	inner.HandleFunc("POST /internal/lux/authorize", func(w http.ResponseWriter, r *http.Request) {})
	outer := http.NewServeMux()
	outer.Handle("/internal/", Handler(inner, "internal"))
	outer.Handle("POST /internal/events", Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), "events"))

	serve(outer, http.MethodPost, "/internal/lux/authorize")
	serve(outer, http.MethodPost, "/internal/nope")
	serve(outer, http.MethodPost, "/internal/events")

	assertRoutes(t, requestRoutes(t, reader), map[string]uint64{
		"/internal/lux/authorize": 1,
		"":                        1,
		"/internal/events":        1,
	})
}

func TestSetRouteOutsideHandlerDoesNothing(t *testing.T) {
	SetRoute(context.Background(), "/x")
}

func TestMetricsHookReceivesTheDecidedRoute(t *testing.T) {
	var got []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/items/{id}", func(w http.ResponseWriter, r *http.Request) {})
	wrapped := Handler(mux, "svc", WithMetricsHook(func(_ context.Context, route, _, _ string, _ time.Duration) {
		got = append(got, route)
	}))
	serve(wrapped, http.MethodGet, "/v1/items/a")
	serve(wrapped, http.MethodGet, "/nowhere")
	if want := []string{"/v1/items/{id}", ""}; !slices.Equal(got, want) {
		t.Errorf("hook routes = %q, want %q", got, want)
	}
}

// TestHandlerWithSkipRecordsNoRequestMetrics checks that a skipped request
// reaches neither the span nor the request metrics, and that the next
// observed request is labeled with its template.
func TestHandlerWithSkipRecordsNoRequestMetrics(t *testing.T) {
	reader := installMeterReader(t)
	wrapped := Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		"op",
		WithSkip(func(r *http.Request) bool { return r.URL.Path == "/healthz" }),
		WithRouteTemplate(func(r *http.Request) string { return r.URL.Path }),
	)

	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assertRoutes(t, requestRoutes(t, reader), map[string]uint64{})

	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/x", nil))
	assertRoutes(t, requestRoutes(t, reader), map[string]uint64{"/v1/x": 1})
}

func FuzzRouteFromPattern(f *testing.F) {
	f.Add("")
	f.Add("GET /v1/parse/{id}")
	f.Add("/static/")
	f.Add("POST /x {$}")
	f.Fuzz(func(t *testing.T, pattern string) {
		got := routeFromPattern(pattern)
		// A suffix of the input that is empty or starts at its first slash.
		if !strings.HasSuffix(pattern, got) || (got != "" && (got[0] != '/' || strings.IndexByte(pattern, '/') != len(pattern)-len(got))) {
			t.Errorf("routeFromPattern(%q) = %q, want the input from its first slash", pattern, got)
		}
	})
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

func TestStatusWriter_RecordsCommittedFinalStatus(t *testing.T) {
	rw := &recordingWriter{}
	sw := &statusWriter{ResponseWriter: rw, code: http.StatusOK}
	sw.WriteHeader(http.StatusEarlyHints)
	sw.WriteHeader(http.StatusNoContent)
	sw.WriteHeader(http.StatusInternalServerError)
	if sw.code != http.StatusNoContent {
		t.Fatalf("recorded code = %d, want first final status 204", sw.code)
	}
	if got := rw.codes; len(got) != 2 || got[0] != http.StatusEarlyHints || got[1] != http.StatusNoContent {
		t.Fatalf("written status codes = %v, want [103 204]", got)
	}
}

func TestStatusWriter_WriteCommitsImplicitOK(t *testing.T) {
	rw := &recordingWriter{}
	sw := &statusWriter{ResponseWriter: rw, code: http.StatusOK}
	if _, err := sw.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	sw.WriteHeader(http.StatusInternalServerError)
	if sw.code != http.StatusOK {
		t.Fatalf("recorded code = %d, want implicit 200", sw.code)
	}
	if got := rw.codes; len(got) != 1 || got[0] != http.StatusOK {
		t.Fatalf("written status codes = %v, want [200]", got)
	}
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

type recordingWriter struct {
	header http.Header
	codes  []int
}

func (w *recordingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *recordingWriter) WriteHeader(code int) {
	w.codes = append(w.codes, code)
}
