// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// recordingMetricExporter keeps the name of every metric it is asked to
// export. The reader reuses the ResourceMetrics it passes, so only the names
// are copied out.
type recordingMetricExporter struct {
	mu    sync.Mutex
	names map[string]bool
}

func newRecordingMetricExporter() *recordingMetricExporter {
	return &recordingMetricExporter{names: map[string]bool{}}
}

func (e *recordingMetricExporter) Temporality(k metric.InstrumentKind) metricdata.Temporality {
	return metric.DefaultTemporalitySelector(k)
}

func (e *recordingMetricExporter) Aggregation(k metric.InstrumentKind) metric.Aggregation {
	return metric.DefaultAggregationSelector(k)
}

func (e *recordingMetricExporter) Export(_ context.Context, rm *metricdata.ResourceMetrics) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			e.names[m.Name] = true
		}
	}
	return nil
}

func (e *recordingMetricExporter) ForceFlush(context.Context) error { return nil }
func (e *recordingMetricExporter) Shutdown(context.Context) error   { return nil }

func (e *recordingMetricExporter) has(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.names[name]
}

// useMetricExporter routes Setup's metrics to exp for the rest of the test.
func useMetricExporter(t *testing.T, exp metric.Exporter) {
	t.Helper()
	orig := newMetricExporter
	t.Cleanup(func() { newMetricExporter = orig })
	newMetricExporter = func(context.Context) (metric.Exporter, error) { return exp, nil }
}

// countRuntimeStarts replaces the runtime instrumentation with a counter that
// returns err, and reports how often Setup started it.
func countRuntimeStarts(t *testing.T, err error) *int {
	t.Helper()
	orig := startRuntimeMetrics
	t.Cleanup(func() { startRuntimeMetrics = orig })
	n := 0
	startRuntimeMetrics = func(*metric.MeterProvider) error {
		n++
		return err
	}
	return &n
}

// TestBootstrap_ExportsRuntimeMetrics: with export on, the metrics a service
// sends include the Go runtime's, under the semantic-convention names. The
// shutdown runs the reader's final collection, so no ticker is waited on.
func TestBootstrap_ExportsRuntimeMetrics(t *testing.T) {
	srv := otlpServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	exp := newRecordingMetricExporter()
	useMetricExporter(t, exp)

	_, shutdown, err := Bootstrap(context.Background(), Config{ServiceName: "svc", Version: "1.0.0", Replica: "pod-1"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	for _, name := range []string{
		"go.goroutine.count",
		"go.memory.used",
		"go.memory.allocated",
		"go.memory.gc.goal",
		"go.config.gogc",
		"go.processor.limit",
		"go.schedule.duration",
	} {
		if !exp.has(name) {
			t.Errorf("metric %s not exported; got %v", name, exp.names)
		}
	}
}

// TestSetup_RuntimeMetricsOnlyWithExport: the runtime instrumentation starts
// with the exporting meter provider and never otherwise, so a service without
// an endpoint, or with the SDK disabled, pays nothing for it.
func TestSetup_RuntimeMetricsOnlyWithExport(t *testing.T) {
	srv := otlpServer(t)
	cases := []struct {
		name     string
		endpoint string
		disabled string
		want     int
	}{
		{"no endpoint", "", "", 0},
		{"sdk disabled", srv.URL, "true", 0},
		{"exporting", srv.URL, "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", tc.endpoint)
			t.Setenv("OTEL_SDK_DISABLED", tc.disabled)
			useMetricExporter(t, newRecordingMetricExporter())
			starts := countRuntimeStarts(t, nil)

			Setup(context.Background(), "svc", "1.0.0")()

			if *starts != tc.want {
				t.Fatalf("runtime instrumentation started %d times, want %d", *starts, tc.want)
			}
		})
	}
}

// TestSetup_RuntimeMetricsErrorIsLogged: a runtime instrumentation that fails
// to register is logged, and the rest of the metrics pipeline keeps working.
func TestSetup_RuntimeMetricsErrorIsLogged(t *testing.T) {
	srv := otlpServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	exp := newRecordingMetricExporter()
	useMetricExporter(t, exp)
	countRuntimeStarts(t, errors.New("injected"))

	var buf bytes.Buffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))

	Setup(context.Background(), "svc", "1.0.0")()

	if got := buf.String(); !strings.Contains(got, "runtime metrics error") || !strings.Contains(got, "injected") {
		t.Errorf("runtime instrumentation error not logged; log was %q", got)
	}
	// The producer is attached to the reader, not to the failed registration,
	// so the scheduling histogram still reaches the exporter.
	if !exp.has("go.schedule.duration") {
		t.Errorf("metrics pipeline stopped after the runtime error; got %v", exp.names)
	}
}
