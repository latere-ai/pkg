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
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// defaultSampleRatio is the head-sampling ratio applied to root spans when
// OTEL_TRACES_SAMPLER_ARG is unset or unparseable. Set to 1.0 to sample every
// trace. The platform default trades some trace volume for backend headroom as
// more services come online.
const defaultSampleRatio = 0.2

// samplerFromEnv builds a ParentBased(TraceIDRatioBased) sampler. ParentBased
// honours a parent's sampling decision so a distributed trace is kept or
// dropped as a whole; the ratio only governs root spans. The ratio comes from
// OTEL_TRACES_SAMPLER_ARG (a float in [0,1]), defaulting to defaultSampleRatio.
func samplerFromEnv() trace.Sampler {
	ratio := defaultSampleRatio
	if v := os.Getenv("OTEL_TRACES_SAMPLER_ARG"); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed >= 0 {
			ratio = parsed
		}
	}
	return trace.ParentBased(trace.TraceIDRatioBased(ratio))
}

// serviceResource builds the OTel resource shared by every signal (traces,
// metrics, and logs) so all three carry identical service and environment
// attributes and correlate per-environment in the backend. The environment
// comes from LATERE_ENV, defaulting to "production".
func serviceResource(ctx context.Context, name, version string) (*resource.Resource, error) {
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

var (
	newResource      = serviceResource
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
		trace.WithSampler(samplerFromEnv()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	metricExp, err := newMetricExporter(ctx)
	if err != nil {
		log.Printf("telemetry: metric exporter error: %v", err)
		// The trace provider is already live with a background batcher; flush
		// it on a fresh timeout context, not the caller ctx (which may be
		// cancelled), mirroring the happy-path shutdown's flush budget.
		return func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tp.Shutdown(shutCtx)
		}
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
