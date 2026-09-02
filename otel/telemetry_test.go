// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

// recordingSpanExporter records whether Shutdown was invoked, so a test can
// assert the trace provider was given a live context to flush through.
type recordingSpanExporter struct {
	shutdownCalled atomic.Bool
}

func (e *recordingSpanExporter) ExportSpans(context.Context, []trace.ReadOnlySpan) error {
	return nil
}

func (e *recordingSpanExporter) Shutdown(ctx context.Context) error {
	e.shutdownCalled.Store(true)
	return ctx.Err()
}

func otlpServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSetup_NoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown := Setup(context.Background(), "svc", "0.1.0")
	shutdown()
}

func TestSetup_WithEndpoint(t *testing.T) {
	srv := otlpServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	shutdown := Setup(context.Background(), "svc", "0.1.0")
	shutdown()
}

func TestSetup_ResourceError(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	orig := newResource
	t.Cleanup(func() { newResource = orig })
	newResource = func(ctx context.Context, name, version string) (*resource.Resource, error) {
		return nil, errors.New("injected")
	}
	shutdown := Setup(context.Background(), "svc", "0.1.0")
	shutdown()
}

func TestSetup_TraceExporterError(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	orig := newTraceExporter
	t.Cleanup(func() { newTraceExporter = orig })
	newTraceExporter = func(ctx context.Context) (trace.SpanExporter, error) {
		return nil, errors.New("injected")
	}
	shutdown := Setup(context.Background(), "svc", "0.1.0")
	shutdown()
}

func TestSetup_MetricExporterError(t *testing.T) {
	srv := otlpServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	orig := newMetricExporter
	t.Cleanup(func() { newMetricExporter = orig })
	newMetricExporter = func(ctx context.Context) (metric.Exporter, error) {
		return nil, errors.New("injected")
	}
	shutdown := Setup(context.Background(), "svc", "0.1.0")
	shutdown()
}

// TestSetup_MetricErrorShutdownFlushesTraces: when the metric exporter fails,
// the returned shutdown must still flush the already-live trace provider on a
// fresh context, not the (possibly cancelled) caller context.
func TestSetup_MetricErrorShutdownFlushesTraces(t *testing.T) {
	srv := otlpServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)

	exp := &recordingSpanExporter{}
	origT, origM := newTraceExporter, newMetricExporter
	t.Cleanup(func() { newTraceExporter, newMetricExporter = origT, origM })
	newTraceExporter = func(context.Context) (trace.SpanExporter, error) { return exp, nil }
	newMetricExporter = func(context.Context) (metric.Exporter, error) {
		return nil, errors.New("injected")
	}

	// Caller context is already cancelled — the shutdown must not depend on it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	shutdown := Setup(ctx, "svc", "0.1.0")
	shutdown()

	if !exp.shutdownCalled.Load() {
		t.Error("trace exporter Shutdown not invoked: metric-error branch tied shutdown to the cancelled caller context")
	}
}

func TestSetup_ShutdownIdempotent(t *testing.T) {
	srv := otlpServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	shutdown := Setup(context.Background(), "svc", "0.1.0")
	shutdown()
	shutdown() // double-call must not panic
}

func TestSamplerFromEnv(t *testing.T) {
	cases := map[string]string{
		"unset":    "",
		"valid":    "0.5",
		"one":      "1.0",
		"zero":     "0",
		"invalid":  "not-a-number",
		"negative": "-0.3",
	}
	for name, arg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OTEL_TRACES_SAMPLER_ARG", arg)
			if s := samplerFromEnv(); s == nil {
				t.Fatal("nil sampler")
			}
		})
	}
}

func FuzzSetup(f *testing.F) {
	f.Add("service", "1.0.0")
	f.Add("", "")
	f.Add("a/b/c", "v0.0.0-dev")
	f.Add("svc-!@#$%", "99.99.99")

	f.Fuzz(func(t *testing.T, name, version string) {
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
		shutdown := Setup(context.Background(), name, version)
		shutdown()
	})
}
