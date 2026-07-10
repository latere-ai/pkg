package sse

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReaderNamedEvents(t *testing.T) {
	in := "event: message_start\ndata: {\"a\":1}\n\nevent: ping\ndata: {}\n\n"
	r := NewReader(strings.NewReader(in))

	ev, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if ev.Name != "message_start" || string(ev.Data) != `{"a":1}` {
		t.Fatalf("got %q %q", ev.Name, ev.Data)
	}
	ev, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if ev.Name != "ping" || string(ev.Data) != `{}` {
		t.Fatalf("got %q %q", ev.Name, ev.Data)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReaderUnnamedAndDone(t *testing.T) {
	in := "data: {\"x\":1}\n\ndata: [DONE]\n\n"
	r := NewReader(strings.NewReader(in))
	ev, err := r.Next()
	if err != nil || ev.Name != "" || string(ev.Data) != `{"x":1}` {
		t.Fatalf("got %q %q err=%v", ev.Name, ev.Data, err)
	}
	ev, err = r.Next()
	if err != nil || string(ev.Data) != "[DONE]" {
		t.Fatalf("got %q err=%v", ev.Data, err)
	}
}

func TestReaderCRLFCommentsAndNoSpace(t *testing.T) {
	in := ": keep-alive\r\nevent:foo\r\ndata:bar\r\n\r\n"
	r := NewReader(strings.NewReader(in))
	ev, err := r.Next()
	if err != nil || ev.Name != "foo" || string(ev.Data) != "bar" {
		t.Fatalf("got %q %q err=%v", ev.Name, ev.Data, err)
	}
}

func TestReaderMultiLineData(t *testing.T) {
	in := "data: one\ndata: two\n\n"
	r := NewReader(strings.NewReader(in))
	ev, err := r.Next()
	if err != nil || string(ev.Data) != "one\ntwo" {
		t.Fatalf("got %q err=%v", ev.Data, err)
	}
}

func TestReaderUnterminatedFinalEvent(t *testing.T) {
	// Stream cut before the trailing blank line still yields the event.
	in := "data: tail"
	r := NewReader(strings.NewReader(in))
	ev, err := r.Next()
	if err != nil || string(ev.Data) != "tail" {
		t.Fatalf("got %q err=%v", ev.Data, err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReaderEmptyStream(t *testing.T) {
	r := NewReader(strings.NewReader(""))
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

type failReader struct{ err error }

func (f failReader) Read([]byte) (int, error) { return 0, f.err }

func TestReaderPropagatesError(t *testing.T) {
	want := errors.New("boom")
	r := NewReader(failReader{err: want})
	if _, err := r.Next(); !errors.Is(err, want) {
		t.Fatalf("want %v, got %v", want, err)
	}
}

func TestWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteEvent("ping", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteEvent("", []byte("[DONE]")); err != nil {
		t.Fatal(err)
	}
	want := "event: ping\ndata: {}\n\ndata: [DONE]\n\n"
	if buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}
}

type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) {
	f.n++
	return 0, errors.New("sink closed")
}

func TestWriterPropagatesError(t *testing.T) {
	w := NewWriter(&failWriter{})
	if err := w.WriteEvent("e", []byte("d")); err == nil {
		t.Fatal("want error on event line")
	}
	if err := w.WriteEvent("", []byte("d")); err == nil {
		t.Fatal("want error on data line")
	}
}

func FuzzReader(f *testing.F) {
	f.Add([]byte("event: a\ndata: b\n\n"))
	f.Add([]byte("data: [DONE]\n\n"))
	f.Add([]byte(": c\r\ndata:x"))
	f.Fuzz(func(t *testing.T, in []byte) {
		r := NewReader(bytes.NewReader(in))
		for i := 0; i < 1000; i++ {
			if _, err := r.Next(); err != nil {
				return
			}
		}
	})
}
