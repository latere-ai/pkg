package cmdexec

import (
	"context"
	"os/exec"
	"strings"
)

// Cmd is a prepared command that can be executed in different output modes.
type Cmd struct {
	name string
	args []string
	ctx  context.Context
}

// New creates a Cmd for the given binary and arguments.
func New(name string, args ...string) *Cmd {
	return &Cmd{name: name, args: args}
}

// Git creates a Cmd for `git -C <dir> <args...>`.
func Git(dir string, args ...string) *Cmd {
	full := make([]string, 0, 2+len(args))
	full = append(full, "-C", dir)
	full = append(full, args...)
	return &Cmd{name: "git", args: full}
}

// WithContext returns a copy of c that uses ctx for cancellation/timeout.
func (c *Cmd) WithContext(ctx context.Context) *Cmd {
	cp := *c
	cp.ctx = ctx
	return &cp
}

// build constructs the underlying os/exec.Cmd, using CommandContext if a
// context was set via WithContext, or plain Command otherwise.
func (c *Cmd) build() *exec.Cmd {
	if c.ctx != nil {
		return exec.CommandContext(c.ctx, c.name, c.args...)
	}
	return exec.Command(c.name, c.args...)
}

// Run executes the command and discards output. Returns nil on success.
func (c *Cmd) Run() error {
	return c.build().Run()
}

// Output executes the command and returns its stdout with leading and trailing
// whitespace removed, which is what a caller reading a single value (a hash, a
// branch name, a path) wants.
//
// The trim is wrong whenever position or repetition carries meaning, and it is
// wrong silently -- the result still looks plausible. Two cases that bite:
//
//   - Column-oriented output where the first column can be blank.
//     "git status --porcelain" writes " M file" for a worktree-only change;
//     trimming shifts the first line one byte left, so the status character is
//     read from the path and the path loses a character.
//   - Output that will be concatenated. Dropping the trailing newline glues the
//     last line of one chunk onto the first line of the next, which turns two
//     records into one malformed record.
//
// Use [Cmd.OutputBytes] for those.
func (c *Cmd) Output() (string, error) {
	out, err := c.build().Output()
	return strings.TrimSpace(string(out)), err
}

// OutputBytes executes the command and returns stdout exactly as written, with
// no trimming. Use it when the bytes are parsed positionally or concatenated;
// see [Cmd.Output] for why trimming corrupts those.
func (c *Cmd) OutputBytes() ([]byte, error) {
	return c.build().Output()
}

// Combined executes the command and returns stdout+stderr interleaved, with
// leading and trailing whitespace removed. The same trimming caveats as
// [Cmd.Output] apply; use [Cmd.CombinedBytes] when they matter.
func (c *Cmd) Combined() (string, error) {
	out, err := c.build().CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// CombinedBytes executes the command and returns stdout+stderr interleaved,
// exactly as written, with no trimming.
func (c *Cmd) CombinedBytes() ([]byte, error) {
	return c.build().CombinedOutput()
}
