// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
)

// StdoutEmitter writes events as NDJSON (one JSON object per line) to the
// configured writer. It is the default sink and the fallback used in dev /
// kind environments without a downstream collector.
//
// A Redact callback, when set, is given the event before serialization so
// callers can scrub credential-shaped substrings out of the payload (or
// modify any other field). The redact callback is responsible for cloning
// values it does not want to mutate in-place.
type StdoutEmitter struct {
	w      io.Writer
	redact func(Event) Event
	mu     sync.Mutex
}

// StdoutOption configures NewStdoutEmitter.
type StdoutOption func(*StdoutEmitter)

// WithRedact installs a callback that may transform the event before
// serialization (e.g. scrub credential-shaped substrings out of Payload).
func WithRedact(fn func(Event) Event) StdoutOption {
	return func(s *StdoutEmitter) { s.redact = fn }
}

// NewStdoutEmitter returns an emitter that writes events as NDJSON to w.
func NewStdoutEmitter(w io.Writer, opts ...StdoutOption) *StdoutEmitter {
	s := &StdoutEmitter{w: w}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Emit serializes ev and writes it as a single line followed by '\n'. The
// underlying writer is held under a mutex so concurrent Emit calls do not
// interleave bytes.
func (s *StdoutEmitter) Emit(_ context.Context, ev Event) error {
	if s.redact != nil {
		ev = s.redact(ev)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(b, '\n'))
	return err
}
