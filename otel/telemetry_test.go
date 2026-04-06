package otel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

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

func TestSetup_ShutdownIdempotent(t *testing.T) {
	srv := otlpServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	shutdown := Setup(context.Background(), "svc", "0.1.0")
	shutdown()
	shutdown() // double-call must not panic
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
