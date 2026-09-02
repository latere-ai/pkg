// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
)

// TestSetup_SendsVendorAuthHeaders pins the property the move to a backend
// with native OTLP ingestion depends on. Such a backend is reached over the
// public internet and authenticates by header, supplied through the standard
// OTEL_EXPORTER_OTLP_HEADERS variable. If Setup did not pass that through,
// every export would be rejected and the failure would be invisible from the
// service side, because the exporter drops its own errors.
func TestSetup_SendsVendorAuthHeaders(t *testing.T) {
	// Traces and metrics both post to this server, so record per path rather
	// than last-wins: the metric reader's export would otherwise mask the one
	// under test.
	var (
		mu   sync.Mutex
		auth = map[string]string{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer%20vendor-token")
	// Sample everything so the span is guaranteed to reach the exporter.
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "1.0")

	shutdown := Setup(context.Background(), "svc", "v1")

	_, span := otel.GetTracerProvider().Tracer("test").Start(context.Background(), "op")
	span.End()

	// Shutdown flushes the batcher synchronously.
	shutdown()

	mu.Lock()
	defer mu.Unlock()
	got, ok := auth["/v1/traces"]
	if !ok {
		t.Fatalf("no export reached /v1/traces; paths seen: %v", auth)
	}
	if got != "Bearer vendor-token" {
		t.Errorf("Authorization = %q, want %q; a vendor endpoint would reject this export",
			got, "Bearer vendor-token")
	}
}

// TestSetup_HonoursEndpointPath covers a vendor that serves OTLP under a path
// prefix rather than at the host root, which several do.
func TestSetup_HonoursEndpointPath(t *testing.T) {
	var (
		mu    sync.Mutex
		paths = map[string]bool{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path] = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL+"/otlp")
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "1.0")

	shutdown := Setup(context.Background(), "svc", "v1")
	_, span := otel.GetTracerProvider().Tracer("test").Start(context.Background(), "op")
	span.End()
	shutdown()

	mu.Lock()
	defer mu.Unlock()
	if !paths["/otlp/v1/traces"] {
		t.Errorf("no export reached /otlp/v1/traces; paths seen: %v", paths)
	}
}

// TestSetupLogs_SendsVendorAuthHeaders covers the log path, which builds its
// own exporter and so could regress independently of traces.
func TestSetupLogs_SendsVendorAuthHeaders(t *testing.T) {
	var (
		mu      sync.Mutex
		gotAuth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer%20vendor-token")

	logger, shutdown, err := SetupLogs(context.Background(), LogsConfig{ServiceName: "svc", Version: "v1"})
	if err != nil {
		t.Fatalf("SetupLogs: %v", err)
	}
	logger.Info("hello")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer vendor-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer vendor-token")
	}
}
