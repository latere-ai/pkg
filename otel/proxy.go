package otel

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
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

// exporterHeaders parses OTEL_EXPORTER_OTLP_HEADERS the way the specification
// defines it: comma-separated key=value pairs, each side percent-encoded, with
// surrounding whitespace ignored.
//
// The SDK's own exporters read this variable themselves. The relay does not go
// through an SDK exporter, so it has to read it too, or browser telemetry is
// the one signal that arrives unauthenticated.
//
// A pair that does not parse is skipped rather than failing the handler. A
// malformed entry should cost that one header, not every browser span.
func exporterHeaders() map[string]string {
	return parseExporterHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))
}

// parseExporterHeaders is the parsing half, split out so it can be exercised
// without the environment. An env var cannot hold every byte a fuzzer will
// try, so a target that goes through os.Setenv tests the harness rather than
// the parser.
func parseExporterHeaders(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	out := map[string]string{}
	for pair := range strings.SplitSeq(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		key, err := url.QueryUnescape(strings.TrimSpace(k))
		if err != nil || !validHeaderName(key) {
			continue
		}
		val, err := url.QueryUnescape(strings.TrimSpace(v))
		if err != nil || strings.ContainsAny(val, "\r\n\x00") {
			continue
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validHeaderName reports whether s is a legal HTTP field name, the RFC 7230
// token production.
//
// Percent-decoding is what makes this necessary rather than paranoid: the
// value is decoded before it becomes a header name, so "%09" arrives as a tab
// and "%0d%0a" as a line break. Either would produce a malformed request, and
// a decoded CRLF in a name is header injection into the request the relay
// sends onward.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

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
		// Then the collector's own credentials. A backend reached over the
		// public internet authenticates by header, and the browser has no way
		// to hold that secret: the whole point of relaying through the service
		// is that the credential stays server side. Without this the relay
		// works against an in-cluster collector and 401s against a vendor,
		// which is a failure that only appears at the cutover.
		for k, v := range exporterHeaders() {
			req.Header.Set(k, v)
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
