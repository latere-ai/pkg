// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

func TestTelemetryProxy_BodyReadError(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
	h := TelemetryProxy("/v1/telemetry")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", errReader{})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestTelemetryProxy_Forwards(t *testing.T) {
	var gotPath, gotCT, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)

	h := TelemetryProxy("/v1/telemetry")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", strings.NewReader("payload"))
	req.Header.Set("Content-Type", "application/x-protobuf")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotPath != "/v1/traces" {
		t.Errorf("forwarded path = %q, want /v1/traces", gotPath)
	}
	if gotCT != "application/x-protobuf" {
		t.Errorf("content-type = %q", gotCT)
	}
	if gotBody != "payload" {
		t.Errorf("body = %q", gotBody)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("response body = %q, want ok", rec.Body.String())
	}
}

func TestTelemetryProxy_DisabledWhenEndpointUnset(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	h := TelemetryProxy("/v1/telemetry")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestTelemetryProxy_RejectsNonPost(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
	h := TelemetryProxy("/v1/telemetry")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/telemetry/v1/traces", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestTelemetryProxy_UpstreamError(t *testing.T) {
	// Point at a closed server so the forward fails.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL
	dead.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", url)

	h := TelemetryProxy("/v1/telemetry")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", strings.NewReader("x")))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestTelemetryProxy_BuildRequestError(t *testing.T) {
	// A control character in the endpoint makes http.NewRequest fail.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector\x7f:4318")
	h := TelemetryProxy("/v1/telemetry")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", strings.NewReader("x")))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestTelemetryProxy_SubpathWithoutLeadingSlash(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)

	// Prefix equals the whole path → empty subpath gets a leading slash added.
	h := TelemetryProxy("/v1/telemetry/v1/traces")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", strings.NewReader("x")))
	if gotPath != "/" {
		t.Errorf("forwarded path = %q, want /", gotPath)
	}
}

func TestTelemetryProxy_EnforcesBodyLimitBeforeForwarding(t *testing.T) {
	var calls, gotBytes int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		gotBytes = len(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)
	h := TelemetryProxy("/v1/telemetry")

	tooLarge := httptest.NewRecorder()
	h.ServeHTTP(tooLarge, httptest.NewRequest(
		http.MethodPost,
		"/v1/telemetry/v1/traces",
		strings.NewReader(strings.Repeat("x", maxTelemetryBody+1)),
	))
	if tooLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d, want 413", tooLarge.Code)
	}
	if calls != 0 {
		t.Fatalf("oversized payload made %d upstream calls, want 0", calls)
	}

	exact := httptest.NewRecorder()
	h.ServeHTTP(exact, httptest.NewRequest(
		http.MethodPost,
		"/v1/telemetry/v1/traces",
		strings.NewReader(strings.Repeat("x", maxTelemetryBody)),
	))
	if exact.Code != http.StatusOK {
		t.Fatalf("exact-limit status = %d, want 200", exact.Code)
	}
	if calls != 1 || gotBytes != maxTelemetryBody {
		t.Fatalf("upstream calls=%d bytes=%d, want 1 call with %d bytes", calls, gotBytes, maxTelemetryBody)
	}
}
