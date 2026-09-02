// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/codes"
)

// TestHandlerRecordsPanic pins that a handler panic reaches the span before it
// unwinds. net/http recovers panics at the connection level, well outside the
// span, so without this the most severe failure a service can have is the one
// least visible in traces.
func TestHandlerRecordsPanic(t *testing.T) {
	sr := installRecorder(t)

	h := Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("kaboom")
	}), "svc")

	func() {
		// The panic must still propagate: net/http's own recovery closes the
		// connection, and swallowing it here would turn a crash into a hang.
		defer func() {
			if recover() == nil {
				t.Error("panic did not propagate past Handler")
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/boom", nil))
	}()

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	span := spans[0]

	if got := span.Status().Code; got != codes.Error {
		t.Errorf("span status = %v, want %v", got, codes.Error)
	}

	var found bool
	for _, e := range span.Events() {
		if e.Name == "exception" {
			found = true
			var hasMessage bool
			for _, kv := range e.Attributes {
				if string(kv.Key) == "exception.message" && strings.Contains(kv.Value.AsString(), "kaboom") {
					hasMessage = true
				}
			}
			if !hasMessage {
				t.Error("exception event does not carry the panic value")
			}
		}
	}
	if !found {
		t.Error("no exception event recorded on the span")
	}
}
