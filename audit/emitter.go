// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
)

// Emitter sinks an audit Event. Implementations must not block the caller on
// I/O beyond a short bounded write; long-running operations belong behind a
// queue or a separate goroutine.
type Emitter interface {
	Emit(ctx context.Context, ev Event) error
}

// MultiEmitter fans an event into N emitters. All are always called even when
// one returns an error; every error is collected and returned joined via
// errors.Join (use errors.Is/As to inspect them).
type MultiEmitter []Emitter

// Emit calls every non-nil child Emit and returns all of their errors joined
// via errors.Join so callers can recover the full set with errors.Is/As.
func (m MultiEmitter) Emit(ctx context.Context, ev Event) error {
	var errs []error
	for _, e := range m {
		if e == nil {
			continue
		}
		if err := e.Emit(ctx, ev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// EmitterFunc adapts a plain function into an Emitter.
type EmitterFunc func(ctx context.Context, ev Event) error

// Emit invokes f.
func (f EmitterFunc) Emit(ctx context.Context, ev Event) error {
	return f(ctx, ev)
}
