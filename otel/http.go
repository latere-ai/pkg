package otel

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// TraceHeaderName is the HTTP response header containing the trace ID.
const TraceHeaderName = "X-Trace-Id"

// HandlerOption configures Handler.
type HandlerOption func(*handlerConfig)

type handlerConfig struct {
	routeTemplate func(*http.Request) string
	surfaceAttr   func(*http.Request) string
	skip          func(*http.Request) bool
	metricsHook   func(ctx context.Context, route, method, statusClass string, dur time.Duration)
}

// WithRouteTemplate sets a function that returns the route template for the
// request (e.g. "/v1/sandboxes/:id"). The result is set as the http.route span
// attribute and passed to the metrics hook so labels stay bounded.
func WithRouteTemplate(fn func(*http.Request) string) HandlerOption {
	return func(c *handlerConfig) { c.routeTemplate = fn }
}

// WithSurfaceAttr sets a function returning a coarse-grained surface label
// (e.g. "public-api", "auth", "static"). The result is set as the cella.surface
// span attribute. Optional.
func WithSurfaceAttr(fn func(*http.Request) string) HandlerOption {
	return func(c *handlerConfig) { c.surfaceAttr = fn }
}

// WithSkip filters requests that should not be observed at all: no span, no
// metrics hook, no X-Trace-Id header. The wrapped handler still runs. Use for
// liveness / readiness probes that would otherwise dominate trace volume.
func WithSkip(fn func(*http.Request) bool) HandlerOption {
	return func(c *handlerConfig) { c.skip = fn }
}

// WithMetricsHook registers a callback invoked once per non-skipped request
// after the inner handler returns. Status class is the canonical "2xx"/"4xx"/etc.
// bucket. The callback is responsible for its own cardinality discipline.
func WithMetricsHook(fn func(ctx context.Context, route, method, statusClass string, dur time.Duration)) HandlerOption {
	return func(c *handlerConfig) { c.metricsHook = fn }
}

// Handler wraps an http.Handler with OpenTelemetry tracing and metrics.
// It injects the trace ID as a response header for client-side correlation.
//
// Without options it preserves the prior simple shape: otelhttp.NewHandler
// plus an X-Trace-Id response header. With options it adds route templating,
// surface attribution, probe skipping, and a metrics callback so products can
// share the boilerplate without giving up their own metrics registry shape.
func Handler(h http.Handler, operation string, opts ...HandlerOption) http.Handler {
	cfg := handlerConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.skip != nil && cfg.skip(r) {
			h.ServeHTTP(w, r)
			return
		}

		traceID, _ := TraceIDs(r.Context())
		if traceID != "" {
			w.Header().Set(TraceHeaderName, traceID)
		}

		span := trace.SpanFromContext(r.Context())
		if span.SpanContext().IsValid() && cfg.surfaceAttr != nil {
			if s := cfg.surfaceAttr(r); s != "" {
				span.SetAttributes(attribute.String("cella.surface", s))
			}
		}

		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		h.ServeHTTP(sw, r)

		// The matched route is known only after the mux has run. An explicit
		// template wins; otherwise fall back to the Go 1.22 ServeMux pattern
		// (e.g. "GET /v1/parse/{id}"), which the mux sets on r once it matches.
		// This keeps http.route low-cardinality (bound IDs) without per-service
		// path normalizers.
		var route string
		if cfg.routeTemplate != nil {
			route = cfg.routeTemplate(r)
		} else {
			route = routeFromPattern(r.Pattern)
		}
		if route != "" && span.SpanContext().IsValid() {
			span.SetAttributes(attribute.String("http.route", route))
		}
		if cfg.metricsHook != nil {
			cfg.metricsHook(r.Context(), route, r.Method, statusClass(sw.code), time.Since(start))
		}
	})

	otelOpts := []otelhttp.Option{}
	if cfg.skip != nil {
		skip := cfg.skip
		otelOpts = append(otelOpts, otelhttp.WithFilter(func(r *http.Request) bool { return !skip(r) }))
	}
	if cfg.routeTemplate != nil {
		fn := cfg.routeTemplate
		otelOpts = append(otelOpts, otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + fn(r)
		}))
	}
	return otelhttp.NewHandler(inner, operation, otelOpts...)
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

// LogAttrs returns slog key/value attrs for trace_id and span_id when ctx
// carries a valid span, otherwise nil. Intended for splatting into slog calls:
//
//	logger.Info("http.request", append(attrs, otel.LogAttrs(ctx)...)...)
func LogAttrs(ctx context.Context) []any {
	traceID, spanID := TraceIDs(ctx)
	if traceID == "" {
		return nil
	}
	return []any{"trace_id", traceID, "span_id", spanID}
}

// routeFromPattern strips the optional leading method token from a Go 1.22
// ServeMux pattern, leaving just the path template: "GET /v1/x/{id}" becomes
// "/v1/x/{id}". An empty pattern (no route matched, e.g. a 404) yields "".
func routeFromPattern(pattern string) string {
	if pattern == "" {
		return ""
	}
	if _, path, ok := strings.Cut(pattern, " "); ok {
		return path
	}
	return pattern
}

func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijack")
	}
	return h.Hijack()
}
