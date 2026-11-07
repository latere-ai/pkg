// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// Transport wraps base with OpenTelemetry instrumentation: it creates a client
// span per outbound request and injects the W3C trace context headers so the
// receiving service (instrumented with Handler) continues the same trace. Pass
// nil to wrap http.DefaultTransport.
//
// Use this for every service-to-service call. Without it, server spans exist on
// both sides but are not linked, so traces stay islanded per service.
//
// A span's url.full holds the scheme, host and path of the request, never its
// query or fragment: a query can carry a token, a cursor or a name a caller
// chose, and a telemetry backend is no place for any of them.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(queryless{base})
}

// queryless sits under otelhttp's transport, which has started the client
// span and set url.full from the whole URL by the time it calls through, and
// sets url.full again without the query and the fragment.
type queryless struct{ base http.RoundTripper }

func (q queryless) RoundTrip(r *http.Request) (*http.Response, error) {
	if span := trace.SpanFromContext(r.Context()); span.IsRecording() && r.URL != nil {
		u := *r.URL
		u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
		span.SetAttributes(semconv.URLFull(u.String()))
	}
	return q.base.RoundTrip(r)
}

// HTTPClient returns an *http.Client whose Transport is instrumented via
// Transport. It is a convenience for callers that do not otherwise customize
// the client.
func HTTPClient() *http.Client {
	return &http.Client{Transport: Transport(nil)}
}
