// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestSetup_SDKDisabledSkipsExport pins the spec-defined kill switch: with an
// endpoint configured, OTEL_SDK_DISABLED=true must still leave the SDK noop,
// so a deployment can silence a service without editing its manifest.
func TestSetup_SDKDisabledSkipsExport(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	t.Cleanup(srv.Close)

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_SDK_DISABLED", "true")

	orig := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(orig) })
	otel.SetTracerProvider(noop.NewTracerProvider())

	shutdown := Setup(context.Background(), "svc", "v1")
	shutdown()

	if _, ok := otel.GetTracerProvider().(noop.TracerProvider); !ok {
		t.Error("Setup installed a live tracer provider despite OTEL_SDK_DISABLED=true")
	}
	if reached {
		t.Error("exporter contacted the collector despite OTEL_SDK_DISABLED=true")
	}
}

// TestSetupLogs_SDKDisabledStaysLocal covers the same switch on the log path.
func TestSetupLogs_SDKDisabledStaysLocal(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_SDK_DISABLED", "true")

	var buf bytes.Buffer
	logger, shutdown, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
		Stdout:      slog.NewJSONHandler(&buf, nil),
	})
	if err != nil {
		t.Fatalf("SetupLogs: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	logger.Info("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Error("local logging stopped working when the SDK was disabled")
	}
}

// TestExportDisabled_OnlyTrueDisables keeps the switch spec-conformant. Any
// value other than a case-insensitive "true" leaves the SDK on, so a typo
// cannot silently blind a service.
func TestExportDisabled_OnlyTrueDisables(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"false", false},
		{"1", false},
		{"yes", false},
		{"", false},
		{"  true  ", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("OTEL_SDK_DISABLED", tc.value)
			if got := exportDisabled(); got != tc.want {
				t.Errorf("exportDisabled() with %q = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}
