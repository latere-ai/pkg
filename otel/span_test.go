// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	otelglobal "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestChildSpanFromHTTP(t *testing.T) {
	recorder := installRecorder(t)
	handler := Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, end := StartScoped(r.Context(), "service/storage", "read", attribute.String("key", "pack"))
		SetAttributes(ctx, attribute.Int("bytes", 42))
		end(errors.New("storage unavailable"))
		w.WriteHeader(http.StatusServiceUnavailable)
	}), "request")
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	spans := recorder.Ended()
	if len(spans) != 2 {
		t.Fatalf("spans = %d", len(spans))
	}
	child, parent := spans[0], spans[1]
	if child.Name() != "read" || child.InstrumentationScope().Name != "service/storage" || child.Parent().SpanID() != parent.SpanContext().SpanID() || child.SpanContext().TraceID() != parent.SpanContext().TraceID() {
		t.Fatal("child span lost parent or scope")
	}
	if child.Status().Code != codes.Error || len(child.Events()) != 1 || len(child.Attributes()) != 2 {
		t.Fatalf("error/attributes missing: %+v", child)
	}
}

func TestStartDefaultScopeAndSuccess(t *testing.T) {
	recorder := installRecorder(t)
	_, end := Start(context.Background(), "work")
	end(nil)
	spans := recorder.Ended()
	if len(spans) != 1 || spans[0].Status().Code != codes.Unset || len(spans[0].Events()) != 0 || spans[0].InstrumentationScope().Name != "latere.ai/x/pkg/otel" {
		t.Fatal("wrong successful span")
	}
}

func TestStartNoop(t *testing.T) {
	prev := otelglobal.GetTracerProvider()
	otelglobal.SetTracerProvider(noop.NewTracerProvider())
	t.Cleanup(func() { otelglobal.SetTracerProvider(prev) })
	ctx, end := Start(context.Background(), "work")
	SetAttributes(ctx, attribute.String("key", "value"))
	end(errors.New("ignored"))
	if tid, _ := TraceIDs(ctx); tid != "" {
		t.Fatal("noop generated a trace")
	}
}

func FuzzSpanNames(f *testing.F) {
	f.Add("work", "scope")
	f.Fuzz(func(t *testing.T, name, scope string) {
		ctx, end := StartScoped(context.Background(), scope, name)
		SetAttributes(ctx)
		end(nil)
	})
}
