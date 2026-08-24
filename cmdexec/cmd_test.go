package cmdexec

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestNew_Run verifies that a successful command returns nil.
func TestNew_Run(t *testing.T) {
	if err := New("true").Run(); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

// TestNew_RunFail verifies that a failing command returns a non-nil error.
func TestNew_RunFail(t *testing.T) {
	if err := New("false").Run(); err == nil {
		t.Fatal("expected error from 'false'")
	}
}

// TestNew_Output verifies that Output captures and returns trimmed stdout.
func TestNew_Output(t *testing.T) {
	out, err := New("echo", "hello").Output()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello" {
		t.Fatalf("expected 'hello', got %q", out)
	}
}

// TestNew_Output_Trimmed verifies that Output strips leading/trailing whitespace.
func TestNew_Output_Trimmed(t *testing.T) {
	out, err := New("echo", "  spaces  ").Output()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// echo adds newline; Output trims
	if out != "spaces" {
		t.Fatalf("expected 'spaces', got %q", out)
	}
}

// TestNew_Combined verifies that Combined merges stdout and stderr into one string.
func TestNew_Combined(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not available on windows")
	}
	out, err := New("bash", "-c", "echo out; echo err >&2").Combined()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "out\nerr" {
		t.Fatalf("expected 'out\\nerr', got %q", out)
	}
}

// TestWithContext_Cancellation verifies that a pre-cancelled context causes Run to fail.
func TestWithContext_Cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // already cancelled

	err := New("sleep", "10").WithContext(ctx).Run()
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

// TestWithContext_Timeout verifies that a short context timeout kills a long-running command.
func TestWithContext_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	err := New("sleep", "10").WithContext(ctx).Run()
	if err == nil {
		t.Fatal("expected error from timed-out context")
	}
}

// TestGit_PrependsArgs verifies that Git prepends "-C <dir>" to the argument list.
func TestGit_PrependsArgs(t *testing.T) {
	cmd := Git("/tmp", "status")
	if cmd.name != "git" {
		t.Fatalf("expected name 'git', got %q", cmd.name)
	}
	if len(cmd.args) != 3 || cmd.args[0] != "-C" || cmd.args[1] != "/tmp" || cmd.args[2] != "status" {
		t.Fatalf("unexpected args: %v", cmd.args)
	}
}

// OutputBytes must return stdout byte-for-byte. The two cases below are the
// ones that made the trimming a real defect rather than a convenience: a
// leading space that is data, and a trailing newline that separates records.
func TestOutputBytesPreservesLeadingAndTrailingBytes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("printf and sh are not available on windows")
	}
	// Reproduces the shape of "git status --porcelain": the first column is
	// the status character and may be blank for a worktree-only change.
	const porcelain = " M internal/pkg/cmdexec/cmd.go\n?? scratch.txt\n"

	raw, err := New("printf", "%s", porcelain).OutputBytes()
	if err != nil {
		t.Fatalf("OutputBytes: %v", err)
	}
	if string(raw) != porcelain {
		t.Fatalf("OutputBytes = %q, want %q", raw, porcelain)
	}

	// The same command through Output loses both ends, which is exactly why a
	// positional parser cannot use it: the status character would be read out
	// of the path.
	trimmed, err := New("printf", "%s", porcelain).Output()
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if trimmed == porcelain {
		t.Fatal("Output did not trim; this test no longer demonstrates the difference")
	}
	if got := trimmed[0]; got != 'M' {
		t.Fatalf("first byte of trimmed output = %q, want the shifted %q", got, 'M')
	}
}

// Concatenating two chunks read through Output fuses the last line of one onto
// the first line of the next. OutputBytes keeps them separate records.
func TestOutputBytesSurvivesConcatenation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("printf and sh are not available on windows")
	}
	const a = "first\n"
	const b = "second\n"

	var joinedRaw []byte
	for _, chunk := range []string{a, b} {
		out, err := New("printf", "%s", chunk).OutputBytes()
		if err != nil {
			t.Fatalf("OutputBytes: %v", err)
		}
		joinedRaw = append(joinedRaw, out...)
	}
	if lines := strings.Count(string(joinedRaw), "\n"); lines != 2 {
		t.Fatalf("raw concatenation has %d newlines, want 2:\n%q", lines, joinedRaw)
	}

	var joinedTrimmed string
	for _, chunk := range []string{a, b} {
		out, err := New("printf", "%s", chunk).Output()
		if err != nil {
			t.Fatalf("Output: %v", err)
		}
		joinedTrimmed += out
	}
	if joinedTrimmed != "firstsecond" {
		t.Fatalf("trimmed concatenation = %q; the test no longer shows the fusion", joinedTrimmed)
	}
}

// CombinedBytes carries both streams through untrimmed.
func TestCombinedBytesPreservesBytes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("printf and sh are not available on windows")
	}
	raw, err := New("sh", "-c", "printf ' out\n'; printf ' err\n' 1>&2").CombinedBytes()
	if err != nil {
		t.Fatalf("CombinedBytes: %v", err)
	}
	if !strings.HasPrefix(string(raw), " ") {
		t.Fatalf("CombinedBytes = %q, want the leading space preserved", raw)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Fatalf("CombinedBytes = %q, want the trailing newline preserved", raw)
	}
}

// A failing command still reports its error through the byte variants, and the
// caller keeps whatever was written before the failure.
func TestOutputBytesReportsCommandFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("printf and sh are not available on windows")
	}
	if _, err := New("sh", "-c", "exit 3").OutputBytes(); err == nil {
		t.Fatal("expected an error from a non-zero exit")
	}
	if _, err := New("sh", "-c", "exit 3").CombinedBytes(); err == nil {
		t.Fatal("expected an error from a non-zero exit")
	}
}
