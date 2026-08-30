// Package errwriter writes a stream of output and remembers the first error,
// so a caller checks once instead of at every call.
//
// It exists because the alternative is worse in both directions. Checking each
// write is unreadable when the output is a report:
//
//	if _, err := fmt.Fprintf(w, "  %-40s %6.1f%%\n", pkg, pct); err != nil {
//		return err
//	}
//
// and discarding each one hides a real failure, which is what `_, _ =` does no
// matter how deliberate it looks. A closed pipe, a full disk, or a broken
// terminal makes the first write fail and every write after it a no-op, and a
// program that ignored them reports success over output nobody received.
//
// So writes are recorded and skipped after the first failure, and [Writer.Err]
// answers once at the end:
//
//	out := errwriter.New(os.Stdout)
//	for _, p := range packages {
//		out.Printf("  %-40s %6.1f%%\n", p.Name, p.Coverage)
//	}
//	out.Printf("\n%d packages measured\n", len(packages))
//	return out.Err()
//
// This is the shape Rob Pike's "Errors are values" describes, and the same one
// bufio.Writer uses for its own sticky error.
//
// It is for output a person reads: a CLI report, a usage message, a table on
// stdout. Service logging wants log/slog and the otel bridge in
// latere.ai/x/pkg/otel instead, where a record carries fields and a trace id
// rather than a formatted line.
package errwriter

import (
	"fmt"
	"io"
)

// Writer is an io.Writer that latches its first error.
//
// The zero value is not usable; call [New].
type Writer struct {
	w   io.Writer
	err error
}

// New returns a Writer over w.
func New(w io.Writer) *Writer { return &Writer{w: w} }

// Write implements io.Writer. It reports the latched error rather than
// attempting a write that has already been shown to fail.
func (e *Writer) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

// Printf formats and writes. After the first failure it does nothing, so the
// error a caller eventually reads is the one that started it rather than a
// later symptom.
func (e *Writer) Printf(format string, a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}

// Print writes its operands in the manner of fmt.Fprint.
func (e *Writer) Print(a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprint(e.w, a...)
}

// Println writes its operands in the manner of fmt.Fprintln.
func (e *Writer) Println(a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintln(e.w, a...)
}

// Err returns the first write error, or nil.
func (e *Writer) Err() error { return e.err }
