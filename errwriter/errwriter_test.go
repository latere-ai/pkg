package errwriter_test

import (
	"errors"
	"strings"
	"testing"

	"latere.ai/x/pkg/errwriter"
)

// failAfter fails every write past the nth, which is how a closed pipe or a
// full disk behaves: fine until it is not.
type failAfter struct {
	n     int
	count int
	err   error
	buf   strings.Builder
}

func (f *failAfter) Write(p []byte) (int, error) {
	f.count++
	if f.count > f.n {
		return 0, f.err
	}
	return f.buf.Write(p)
}

func TestWritesReachTheWriterAndErrIsNil(t *testing.T) {
	var sb strings.Builder
	w := errwriter.New(&sb)
	w.Printf("%s=%d\n", "packages", 48)
	w.Println("done")
	w.Print("no newline")
	if err := w.Err(); err != nil {
		t.Fatalf("Err = %v, want nil", err)
	}
	if got, want := sb.String(), "packages=48\ndone\nno newline"; got != want {
		t.Errorf("wrote %q, want %q", got, want)
	}
}

// The point of latching: the caller checks once, at the end.
func TestTheFirstErrorIsReported(t *testing.T) {
	boom := errors.New("broken pipe")
	f := &failAfter{n: 1, err: boom}
	w := errwriter.New(f)
	w.Println("first")
	w.Println("second")
	if !errors.Is(w.Err(), boom) {
		t.Fatalf("Err = %v, want %v", w.Err(), boom)
	}
}

// A later error must not replace the one that started it: the first failure is
// the diagnosis, the rest are symptoms.
func TestALaterErrorDoesNotReplaceTheFirst(t *testing.T) {
	first := errors.New("first")
	f := &failAfter{n: 0, err: first}
	w := errwriter.New(f)
	w.Println("a")
	f.err = errors.New("second")
	w.Println("b")
	if !errors.Is(w.Err(), first) {
		t.Errorf("Err = %v, want the first error", w.Err())
	}
}

// After a failure the writer stops touching the underlying writer, so a
// half-broken terminal is not written to repeatedly.
func TestNothingIsWrittenAfterAFailure(t *testing.T) {
	f := &failAfter{n: 1, err: errors.New("nope")}
	w := errwriter.New(f)
	w.Println("kept")
	w.Println("dropped")
	w.Printf("also %s", "dropped")
	w.Print("dropped")
	if f.count != 2 {
		t.Errorf("underlying writer called %d times, want 2 (one success, one failure)", f.count)
	}
	if strings.Contains(f.buf.String(), "dropped") {
		t.Errorf("wrote after failing: %q", f.buf.String())
	}
}

// It is an io.Writer, so it composes with anything that takes one.
func TestWriteImplementsIOWriter(t *testing.T) {
	var sb strings.Builder
	w := errwriter.New(&sb)
	n, err := w.Write([]byte("bytes"))
	if err != nil || n != 5 {
		t.Fatalf("Write = %d, %v", n, err)
	}

	boom := errors.New("gone")
	f := &failAfter{n: 0, err: boom}
	bad := errwriter.New(f)
	if _, err := bad.Write([]byte("x")); !errors.Is(err, boom) {
		t.Errorf("Write err = %v, want %v", err, boom)
	}
	// A second Write reports the latched error without calling through.
	if _, err := bad.Write([]byte("y")); !errors.Is(err, boom) {
		t.Errorf("second Write err = %v, want the latched %v", err, boom)
	}
	if f.count != 1 {
		t.Errorf("underlying writer called %d times, want 1", f.count)
	}
}
