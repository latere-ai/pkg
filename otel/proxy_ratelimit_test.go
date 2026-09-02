// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	otelapi "go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"golang.org/x/time/rate"
)

// countingUpstream returns a server that reports how many payloads reached it.
func countingUpstream(t *testing.T) (*httptest.Server, func() int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, n.Load
}

// post drives the relay once and returns the recorder.
func post(h http.Handler, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-protobuf")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestTelemetryProxy_BudgetRejectsFlood is the cost control on the one route
// that is anonymous by construction. Pointing the relay at a backend that bills
// by volume ingested makes an unbounded relay an open path into the invoice,
// so a spent budget must stop the payload before it is forwarded.
func TestTelemetryProxy_BudgetRejectsFlood(t *testing.T) {
	upstream, forwarded := countingUpstream(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)
	t.Setenv(telemetryRateEnv, "1")

	h := TelemetryProxy("/v1/telemetry")

	// One maximum payload drains the burst.
	if rec := post(h, bytes.Repeat([]byte("x"), maxTelemetryBody)); rec.Code != http.StatusOK {
		t.Fatalf("first payload status = %d, want 200", rec.Code)
	}
	// At one byte per second the bucket cannot refill within the test.
	rec := post(h, []byte("xx"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second payload status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want %q", got, "2")
	}
	if n := forwarded(); n != 1 {
		t.Errorf("forwarded %d payloads, want 1: the rejected payload still reached the backend", n)
	}
}

// TestTelemetryProxy_MaxPayloadFitsBurst pins the burst floor. rate.Limiter
// rejects any reservation above its burst outright, so a burst below the body
// cap would make a legal maximum-size payload permanently unforwardable rather
// than delayed, and the relay would fail only on the largest real batches.
func TestTelemetryProxy_MaxPayloadFitsBurst(t *testing.T) {
	upstream, forwarded := countingUpstream(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)
	// A budget far below the body cap: the burst floor, not the rate, is what
	// has to admit this payload.
	t.Setenv(telemetryRateEnv, "16")

	h := TelemetryProxy("/v1/telemetry")
	if rec := post(h, bytes.Repeat([]byte("x"), maxTelemetryBody)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if n := forwarded(); n != 1 {
		t.Errorf("forwarded %d payloads, want 1", n)
	}
}

// TestTelemetryProxy_BudgetDisabled keeps the in-cluster deployment able to opt
// out: against a collector that is not billed by volume, the budget is only a
// cap on your own telemetry.
func TestTelemetryProxy_BudgetDisabled(t *testing.T) {
	upstream, forwarded := countingUpstream(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)
	t.Setenv(telemetryRateEnv, "0")

	h := TelemetryProxy("/v1/telemetry")
	body := bytes.Repeat([]byte("x"), maxTelemetryBody)
	for i := range 3 {
		if rec := post(h, body); rec.Code != http.StatusOK {
			t.Fatalf("payload %d status = %d, want 200", i, rec.Code)
		}
	}
	if n := forwarded(); n != 3 {
		t.Errorf("forwarded %d payloads, want 3", n)
	}
}

// TestNewTelemetryLimiter covers the environment parsing, including the case
// that decides whether a typo is free: an unparseable budget must keep the
// default rather than fall through to unlimited.
func TestNewTelemetryLimiter(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want rate.Limit // -1 means "expect no limiter"
	}{
		{name: "unset uses the default", env: "", want: defaultTelemetryRate},
		{name: "explicit budget", env: "4096", want: 4096},
		{name: "whitespace is trimmed", env: "  4096  ", want: 4096},
		{name: "zero disables", env: "0", want: -1},
		{name: "negative disables", env: "-1", want: -1},
		{name: "garbage keeps the default", env: "abc", want: defaultTelemetryRate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(telemetryRateEnv, tc.env)
			got := newTelemetryLimiter()
			if tc.want == -1 {
				if got != nil {
					t.Fatalf("limiter = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("limiter = nil, want a limiter")
			}
			if got.Limit() != tc.want {
				t.Errorf("rate = %v, want %v", got.Limit(), tc.want)
			}
			if got.Burst() < maxTelemetryBody {
				t.Errorf("burst = %d, want at least %d", got.Burst(), maxTelemetryBody)
			}
		})
	}
}

// TestTelemetryProxy_BudgetDoesNotMaskDisabledEndpoint keeps the ordering
// honest: an unconfigured relay reports 503, not a budget rejection.
func TestTelemetryProxy_BudgetDoesNotMaskDisabledEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv(telemetryRateEnv, "1")

	h := TelemetryProxy("/v1/telemetry")
	req := httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestTelemetryProxy_RejectionIsCounted covers the difference between a budget
// and a silent hole. Without the counter, a budget set too low and an SPA that
// stopped exporting look identical from the backend.
func TestTelemetryProxy_RejectionIsCounted(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	prev := otelapi.GetMeterProvider()
	otelapi.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otelapi.SetMeterProvider(prev) })

	upstream, _ := countingUpstream(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)
	t.Setenv(telemetryRateEnv, "1")

	h := TelemetryProxy("/v1/telemetry")
	if rec := post(h, bytes.Repeat([]byte("x"), maxTelemetryBody)); rec.Code != http.StatusOK {
		t.Fatalf("first payload status = %d, want 200", rec.Code)
	}
	if rec := post(h, []byte("xx")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second payload status = %d, want 429", rec.Code)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	got := counterValue(t, &rm, "latere.telemetry_proxy.rejected")
	if got != 1 {
		t.Errorf("rejected counter = %d, want 1", got)
	}
}

// counterValue reads a single Int64 sum out of the collected metrics.
func counterValue(t *testing.T, rm *metricdata.ResourceMetrics, name string) int64 {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is %T, want Sum[int64]", name, m.Data)
			}
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			return total
		}
	}
	t.Fatalf("metric %q was not recorded", name)
	return 0
}
