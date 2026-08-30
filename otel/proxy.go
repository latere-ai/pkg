package otel

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// maxTelemetryBody caps a single forwarded browser payload. OTLP/HTTP batches
// from @opentelemetry/web are small; the cap bounds abuse of the public route.
const maxTelemetryBody = 1 << 20 // 1 MiB

// telemetryClient forwards browser payloads to the collector. A package var so
// tests can adjust the timeout/transport without a live backend.
var telemetryClient = &http.Client{Timeout: 10 * time.Second}

// TelemetryProxy returns an http.Handler that forwards browser-originated
// OTLP/HTTP payloads to the in-cluster collector named by
// OTEL_EXPORTER_OTLP_ENDPOINT. Browsers cannot reach the internal collector, so
// a service mounts this on a same-origin route (e.g. "/v1/telemetry/") and the
// SPA's @opentelemetry/web exporter posts to it. Being same-origin, it needs no
// CORS and rides the service's existing TLS and ingress controls.
//
// The subpath after prefix is appended to the collector base, so a POST to
// "{prefix}/v1/traces" is forwarded to "{collector}/v1/traces". Only POST is
// accepted and bodies are capped at 1 MiB. When the endpoint is unset the
// handler returns 503 so the SPA degrades quietly.
func TelemetryProxy(prefix string) http.Handler {
	endpoint := strings.TrimRight(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if endpoint == "" {
			http.Error(w, "telemetry disabled", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sub := strings.TrimPrefix(r.URL.Path, prefix)
		if !strings.HasPrefix(sub, "/") {
			sub = "/" + sub
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxTelemetryBody+1))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		if len(body) > maxTelemetryBody {
			http.Error(w, "telemetry payload too large", http.StatusRequestEntityTooLarge)
			return
		}

		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint+sub, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "build request", http.StatusInternalServerError)
			return
		}
		// Preserve the OTLP content negotiation headers the SDK set.
		if ct := r.Header.Get("Content-Type"); ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		if ce := r.Header.Get("Content-Encoding"); ce != "" {
			req.Header.Set("Content-Encoding", ce)
		}

		resp, err := telemetryClient.Do(req)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, maxTelemetryBody))
	})
}
