// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package otel sets up OpenTelemetry tracing and metrics.
//
// By default, telemetry is disabled (noop). Set OTEL_EXPORTER_OTLP_ENDPOINT to
// enable export to any OTLP/HTTP backend. Nothing here is vendor-specific: the
// endpoint, its credentials, and the sampling ratio all come from the
// environment, which is what lets the backend change without touching a
// service.
//
// Example, exporting directly to a hosted backend:
//
//	OTEL_EXPORTER_OTLP_ENDPOINT=https://ingress.example.com
//	OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20<token>
//
// Under a Kubernetes operator that injects the endpoint (the Dash0 operator,
// the OpenTelemetry operator), leave both variables unset in the manifest and
// let the operator supply them. Such operators generally skip a container that
// already sets them, so a hardcoded endpoint reads as configured while the
// telemetry goes somewhere else.
package otel

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
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
//
// The detectors carry as much weight as the attributes. WithFromEnv reads
// OTEL_RESOURCE_ATTRIBUTES and OTEL_SERVICE_NAME, the two variables every OTel
// SDK is expected to honour; without it a deployment that sets them gets
// silence. WithTelemetrySDK records which SDK emitted the signal, which is how
// a backend separates these services from the collector's own pipeline.
//
// Options apply in order and later attributes win, so the explicit service
// name and version override anything the environment sets for those two keys
// while every other environment attribute survives.
//
// The semconv version must track the one WithTelemetrySDK emits. Merging two
// resources that disagree on schema URL is an error, not a warning, and it
// fails the whole detection rather than dropping one attribute.
func serviceResource(ctx context.Context, name, version string) (*resource.Resource, error) {
	env := os.Getenv("LATERE_ENV")
	if env == "" {
		env = "production"
	}
	return resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithSchemaURL(semconv.SchemaURL),
		resource.WithAttributes(
			semconv.ServiceName(name),
			semconv.ServiceVersion(version),
			semconv.DeploymentEnvironmentNameKey.String(env),
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

// exportDisabled reports whether OTEL_SDK_DISABLED turns the SDK off. The
// OTel specification defines this as the one switch that disables every signal
// regardless of how the rest of the environment is configured, which is what
// makes it useful: a deployment can silence a service without editing the
// endpoint out of its manifest and losing the configuration.
//
// The spec defines "true" (case-insensitive) as the only enabling value, so
// anything else, including garbage, leaves the SDK on.
func exportDisabled() bool {
	return strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true")
}

// Setup initializes OpenTelemetry. If OTEL_EXPORTER_OTLP_ENDPOINT is set,
// traces and metrics are exported via OTLP/HTTP. Otherwise, telemetry is
// a noop (no overhead). Returns a shutdown function.
//
// OTEL_SDK_DISABLED=true forces the noop path even when an endpoint is set.
func Setup(ctx context.Context, serviceName, serviceVersion string) func() {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" || exportDisabled() {
		return func() {}
	}

	res, err := newResource(ctx, serviceName, serviceVersion)
	if err != nil {
		slog.ErrorContext(ctx, "telemetry: resource error; export disabled", "error", err)
		return func() {}
	}

	traceExp, err := newTraceExporter(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "telemetry: trace exporter error; export disabled", "error", err)
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
		slog.ErrorContext(ctx, "telemetry: metric exporter error; traces still export", "error", err)
		// The trace provider is already live with a background batcher; flush
		// it on a timeout context detached from the caller ctx (which may be
		// cancelled by then), mirroring the happy-path shutdown's flush budget.
		return func() {
			shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if err := tp.Shutdown(shutCtx); err != nil {
				slog.ErrorContext(shutCtx, "telemetry: trace provider shutdown", "error", err)
			}
		}
	}

	mp := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExp, metric.WithInterval(30*time.Second))),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	slog.InfoContext(ctx, "telemetry: exporting", "endpoint", endpoint)

	// The shutdown runs after the caller's ctx is typically cancelled, so it
	// detaches from that cancellation and keeps only the values.
	return func() {
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(shutCtx); err != nil {
			slog.ErrorContext(shutCtx, "telemetry: trace provider shutdown", "error", err)
		}
		if err := mp.Shutdown(shutCtx); err != nil {
			slog.ErrorContext(shutCtx, "telemetry: meter provider shutdown", "error", err)
		}
	}
}
