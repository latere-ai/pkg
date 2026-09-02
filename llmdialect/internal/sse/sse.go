// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package sse implements minimal server-sent-events framing shared by
// the llmdialect codecs: a Reader that yields one event per call and a
// Writer that emits `event:`/`data:` frames. It covers exactly the SSE
// subset the OpenAI and Anthropic streaming APIs use (single-line JSON
// data, optional event name, comment keep-alives) — it is not a general
// SSE client.
package sse

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

// Event is one server-sent event. Name is empty when the frame carried
// no `event:` line (the OpenAI style). Data joins multi-line `data:`
// fields with \n per the SSE spec.
type Event struct {
	Name string
	Data []byte
}

// Reader decodes events from a stream.
type Reader struct {
	sc *bufio.Scanner
}

// NewReader wraps r. Lines longer than maxLine (1 MiB) fail the scan;
// provider deltas are far smaller.
func NewReader(r io.Reader) *Reader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	return &Reader{sc: sc}
}

// Next returns the next event, or io.EOF when the stream ends cleanly.
// A frame with neither name nor data (trailing blank lines) is skipped.
func (r *Reader) Next() (Event, error) {
	var (
		ev   Event
		got  bool
		data [][]byte
	)
	for r.sc.Scan() {
		line := bytes.TrimSuffix(r.sc.Bytes(), []byte("\r"))
		switch {
		case len(line) == 0:
			if got {
				ev.Data = bytes.Join(data, []byte("\n"))
				return ev, nil
			}
		case line[0] == ':': // comment / keep-alive
		case bytes.HasPrefix(line, []byte("event:")):
			ev.Name = string(bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("event:")), []byte(" ")))
			got = true
		case bytes.HasPrefix(line, []byte("data:")):
			d := bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" "))
			data = append(data, bytes.Clone(d))
			got = true
		}
	}
	if err := r.sc.Err(); err != nil {
		return Event{}, err
	}
	if got {
		ev.Data = bytes.Join(data, []byte("\n"))
		return ev, nil
	}
	return Event{}, io.EOF
}

// Writer encodes events to a stream.
type Writer struct {
	w io.Writer
}

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// WriteEvent writes one frame. An empty name omits the `event:` line.
func (w *Writer) WriteEvent(name string, data []byte) error {
	if name != "" {
		if _, err := fmt.Fprintf(w.w, "event: %s\n", name); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w.w, "data: %s\n\n", data)
	return err
}
