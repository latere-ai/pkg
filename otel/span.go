// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Start opens a child span using the provider configured by Bootstrap or Setup.
// Call end once when the operation finishes; a non-nil error records an exception
// and error status. Without a provider, tracing is a no-op. Use StartScoped to
// identify the consumer's instrumentation library separately.
func Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, func(error)) {
	return StartScoped(ctx, "latere.ai/x/pkg/otel", name, attrs...)
}

// StartScoped is Start with an explicit instrumentation scope (usually a package
// or module path). It resolves the provider on each call, including after Setup.
func StartScoped(ctx context.Context, scope, name string, attrs ...attribute.KeyValue) (context.Context, func(error)) {
	ctx, span := otel.Tracer(scope).Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, func(err error) {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}
}

// SetAttributes attaches attributes to the current span. Without a span it is a no-op.
func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	trace.SpanFromContext(ctx).SetAttributes(attrs...)
}
