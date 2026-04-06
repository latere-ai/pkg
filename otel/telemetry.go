// Package otel sets up OpenTelemetry tracing and metrics.
//
// By default, telemetry is disabled (noop). Set OTEL_EXPORTER_OTLP_ENDPOINT
// to enable export to an OTLP-compatible backend (Grafana Cloud, Jaeger, etc).
//
// Example:
//
//	OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp-gateway-prod-eu-west-2.grafana.net/otlp
//	OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic <base64>
package otel

import (
	"context"
	"log"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

var (
	newResource = func(ctx context.Context, name, version string) (*resource.Resource, error) {
		env := os.Getenv("LATERE_ENV")
		if env == "" {
			env = "production"
		}
		return resource.New(ctx,
			resource.WithAttributes(
				semconv.ServiceName(name),
				semconv.ServiceVersion(version),
				attribute.String("deployment.environment", env),
			),
		)
	}
	newTraceExporter = func(ctx context.Context) (trace.SpanExporter, error) {
		return otlptracehttp.New(ctx)
	}
	newMetricExporter = func(ctx context.Context) (metric.Exporter, error) {
		return otlpmetrichttp.New(ctx)
	}
)

// Setup initializes OpenTelemetry. If OTEL_EXPORTER_OTLP_ENDPOINT is set,
// traces and metrics are exported via OTLP/HTTP. Otherwise, telemetry is
// a noop (no overhead). Returns a shutdown function.
func Setup(ctx context.Context, serviceName, serviceVersion string) func() {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		return func() {}
	}

	res, err := newResource(ctx, serviceName, serviceVersion)
	if err != nil {
		log.Printf("telemetry: resource error: %v", err)
		return func() {}
	}

	traceExp, err := newTraceExporter(ctx)
	if err != nil {
		log.Printf("telemetry: trace exporter error: %v", err)
		return func() {}
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(traceExp, trace.WithBatchTimeout(5*time.Second)),
		trace.WithResource(res),
		trace.WithSampler(trace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	metricExp, err := newMetricExporter(ctx)
	if err != nil {
		log.Printf("telemetry: metric exporter error: %v", err)
		return func() { tp.Shutdown(ctx) }
	}

	mp := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExp, metric.WithInterval(30*time.Second))),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	log.Printf("telemetry: exporting to %s", endpoint)

	return func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tp.Shutdown(shutCtx)
		mp.Shutdown(shutCtx)
	}
}
