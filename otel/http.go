// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
// request (e.g. "/v1/sandboxes/:id"), or "" for a request no route serves. It
// is a function of the request as it arrives, so it also names the span before
// the handler runs. The template decides the route unless the handler records
// one with SetRoute: a ServeMux pattern matched inside the handler, which is
// often a coarse mount such as "/" or "/v1/", never replaces it. See Handler
// for where the route goes.
func WithRouteTemplate(fn func(*http.Request) string) HandlerOption {
	return func(c *handlerConfig) { c.routeTemplate = fn }
}

// UnmatchedRoute is the route label a service's own metrics and logs give a
// request no route serves, so every service counts those under one value.
// OpenTelemetry signals carry no http.route for such a request instead, as the
// semantic conventions ask.
const UnmatchedRoute = "unmatched"

type routeKey struct{}

// routeHolder carries the route SetRoute records from inside the handler back
// to Handler. A handler may record it from another goroutine.
type routeHolder struct{ route atomic.Pointer[string] }

// SetRoute records the route that serves the request, for a handler behind
// Handler that learns it only once it has routed the request: a router behind
// middleware that copies the request (r.WithContext and the like), whose
// matched pattern never reaches the request Handler holds, or one that refines
// a matched pattern. route is a path template or a ServeMux pattern; a method
// or host in front of the path is dropped. The last call wins, which is the
// innermost router when each calls SetRoute from the handler it matched. A
// route recorded here takes precedence over WithRouteTemplate and over the
// pattern of a ServeMux. Outside Handler it does nothing.
func SetRoute(ctx context.Context, route string) {
	if h, ok := ctx.Value(routeKey{}).(*routeHolder); ok {
		r := routeFromPattern(route)
		h.route.Store(&r)
	}
}

func (h *routeHolder) get() string {
	if r := h.route.Load(); r != nil {
		return *r
	}
	return ""
}

// WithSurfaceAttr sets a function returning a coarse-grained surface label
// (e.g. "public-api", "auth", "static"). The result is set as the cella.surface
// span attribute. Optional.
func WithSurfaceAttr(fn func(*http.Request) string) HandlerOption {
	return func(c *handlerConfig) { c.surfaceAttr = fn }
}

// WithSkip filters requests that should not be observed at all: no span, no
// request metrics, no metrics hook, no X-Trace-Id header. The wrapped handler
// still runs. Use for liveness / readiness probes that would otherwise
// dominate trace volume.
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
// Every request gets one route, decided once the handler returns, in this
// order: the route the handler recorded with SetRoute; the WithRouteTemplate
// result; the pattern of a ServeMux that matched the request, inside the
// handler or in front of Handler. The route is http.route on the span and on
// the request metrics (http.server.request.duration and the rest), the span is
// named "METHOD route", and the metrics hook receives it. A request no route
// serves has no http.route, a span named by its method alone, and "" in the
// hook. Options add surface attribution, probe skipping, and a metrics
// callback so products can share the boilerplate without giving up their own
// metrics registry shape.
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

		// net/http recovers handler panics at the connection level, far
		// outside this span, so an unrecorded panic is the most severe thing
		// a service can do and the least visible in a trace. Record it, then
		// let it keep unwinding: swallowing it here would turn a crash into a
		// half-written response the client waits on.
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if span.SpanContext().IsValid() {
				span.SetStatus(codes.Error, "panic")
				span.RecordError(fmt.Errorf("panic: %v", rec), trace.WithStackTrace(true))
			}
			panic(rec)
		}()

		if span.SpanContext().IsValid() && cfg.surfaceAttr != nil {
			if s := cfg.surfaceAttr(r); s != "" {
				span.SetAttributes(attribute.String("cella.surface", s))
			}
		}

		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		// The handler gets its own copy of the request, carrying the holder
		// SetRoute writes to. A ServeMux sets the pattern it matched on the
		// request it was handed, so the copy keeps a mount's coarse pattern
		// off r until the route is decided below.
		holder := &routeHolder{}
		served := r.WithContext(context.WithValue(r.Context(), routeKey{}, holder))
		h.ServeHTTP(sw, served)

		route := holder.get()
		if route == "" {
			if cfg.routeTemplate != nil {
				route = routeFromPattern(cfg.routeTemplate(r))
			} else {
				route = routeFromPattern(served.Pattern)
			}
		}
		// r is the request otelhttp handed this handler. Once the handler
		// returns, otelhttp takes http.route on the request metrics, which it
		// records for every request sampled or not, from r.Pattern, and
		// renames the span through the formatter when r.Pattern is set. The
		// decided route replaces whatever a ServeMux in front of Handler
		// matched; "" leaves the metrics without a route.
		r.Pattern = route
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
	// otelhttp names the span when it starts and again once the handler has
	// returned with r.Pattern set, which is when it carries the decided
	// route. At the start the name comes from a ServeMux in front of Handler
	// or from the template, whichever is known.
	template := cfg.routeTemplate
	otelOpts = append(otelOpts, otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
		route := routeFromPattern(r.Pattern)
		if route == "" && template != nil {
			route = routeFromPattern(template(r))
		}
		if route == "" {
			return r.Method
		}
		return r.Method + " " + route
	}))
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

// routeFromPattern is the path of a Go 1.22 ServeMux pattern or a route
// template, from its first slash, as otelhttp reads a pattern: the method and
// host in front go, so "GET /v1/x/{id}" and "GET example.com/v1/x/{id}" both
// become "/v1/x/{id}". A value without a path, such as "" for a request no
// route matched, yields "".
func routeFromPattern(pattern string) string {
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		return pattern[i:]
	}
	return ""
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
	code       int
	wroteFinal bool
}

func (w *statusWriter) WriteHeader(code int) {
	if code >= 100 && code <= 199 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if w.wroteFinal {
		return
	}
	w.wroteFinal = true
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wroteFinal {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if !w.wroteFinal {
			w.WriteHeader(http.StatusOK)
		}
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
