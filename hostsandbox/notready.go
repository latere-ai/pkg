// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strings"
)

// Platform is an operating system the remediation text is written for. It is
// a parameter rather than a call to runtime.GOOS so that every message can be
// tested on one machine.
type Platform string

// The platforms. Windows is present so that it can be refused with a reason.
const (
	Darwin  Platform = "darwin"
	Linux   Platform = "linux"
	Windows Platform = "windows"
)

// CurrentPlatform is the platform this binary runs on.
func CurrentPlatform() Platform { return Platform(runtime.GOOS) }

// Condition is the reason a machine is not ready. Each condition needs a
// different instruction, so the set is closed and the message is chosen from
// it rather than assembled from an exec failure. A consumer whose driver has
// further conditions (an engine that is installed but stopped, an image that
// cannot be pulled) declares its own constants of this type and writes their
// Remediation itself.
type Condition string

// The conditions this package produces.
const (
	// ConditionMissing is a component that is not installed.
	ConditionMissing Condition = "missing"
	// ConditionUnsupported is a platform the driver refuses outright.
	ConditionUnsupported Condition = "unsupported"
)

// NotReadyError is a refusal that carries its own remedy. The remediation is
// data on the error rather than text a caller assembles, so a CLI, a batch
// driver and a test all read the same message.
type NotReadyError struct {
	// Driver is the driver that could not start.
	Driver DriverName
	// Condition is the reason it could not start.
	Condition Condition
	// Components are the components in that condition, in the order they
	// should be fixed.
	Components []string
	// Remediation is the instructions, ready to print.
	Remediation string
	// Alternative is the consumer's own text naming what to do instead, if
	// anything. It is printed after the remediation.
	Alternative string
	// Detail is the underlying output, kept for the operator and never
	// parsed.
	Detail string
}

func (e *NotReadyError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "the %s sandbox is not ready", e.Driver)
	if len(e.Components) > 0 {
		fmt.Fprintf(&b, " (%s: %s)", strings.Join(e.Components, ", "), e.Condition)
	}
	for _, section := range []string{e.Remediation, e.Alternative, strings.TrimSpace(e.Detail)} {
		if section != "" {
			b.WriteString("\n\n")
			b.WriteString(section)
		}
	}
	return b.String()
}

func (e *NotReadyError) Unwrap() error { return ErrNotReady }

// Remedy is how one component is installed on each platform and how the
// install is confirmed.
type Remedy struct {
	// Install maps a platform to the commands that install the component
	// there, in order. A platform with no entry gets a line naming the
	// platforms the component is packaged for.
	Install map[Platform][]string
	// Verify is the command that confirms the component works. It is
	// printed after the install lines so an operator checks the install
	// without re-running the whole program.
	Verify string
}

// Remedies maps a component to its Remedy. A component with no entry gets a
// generic line rather than an empty message, because a missing table row must
// not produce a refusal with no instructions.
type Remedies map[string]Remedy

// DefaultRemedies is the table for srt and what srt needs. It returns a fresh
// map on every call, so a consumer adds its own rows without changing the
// table another consumer reads.
func DefaultRemedies() Remedies {
	return Remedies{
		"srt": {
			Install: map[Platform][]string{
				Darwin: {"npm install -g @anthropic-ai/sandbox-runtime", "brew install ripgrep"},
				Linux:  {"npm install -g @anthropic-ai/sandbox-runtime"},
			},
			// The command is given as bare words, not a quoted string. srt
			// accepts a string only after -c, so `srt "echo ok"` fails with
			// "command not found: echo ok".
			Verify: "srt echo ok",
		},
		"bubblewrap": {Install: map[Platform][]string{
			Linux: {"sudo apt-get install -y bubblewrap      # Debian, Ubuntu", "sudo dnf install -y bubblewrap          # Fedora, RHEL"},
		}},
		"socat": {Install: map[Platform][]string{
			Linux: {"sudo apt-get install -y socat           # Debian, Ubuntu", "sudo dnf install -y socat               # Fedora, RHEL"},
		}},
		"rg": {Install: map[Platform][]string{
			Darwin: {"brew install ripgrep"},
			Linux:  {"sudo apt-get install -y ripgrep        # Debian, Ubuntu", "sudo dnf install -y ripgrep             # Fedora, RHEL"},
		}},
	}
}

// With returns a copy of r with the rows in extra added, an existing row
// replaced by one of the same name.
func (r Remedies) With(extra Remedies) Remedies {
	merged := make(Remedies, len(r)+len(extra))
	maps.Copy(merged, r)
	maps.Copy(merged, extra)
	return merged
}

// NotReady builds the refusal for components in one condition on one
// platform. Windows yields ConditionUnsupported whatever condition is asked
// for, because srt marks its Windows support as alpha, which is not an
// isolation boundary. Any other condition than ConditionMissing and
// ConditionUnsupported yields an error with no Remediation, for the caller to
// fill in.
func (r Remedies) NotReady(platform Platform, driver DriverName, condition Condition, components ...string) *NotReadyError {
	err := &NotReadyError{Driver: driver, Condition: condition, Components: slices.Clone(components)}
	switch {
	case platform == Windows:
		err.Condition = ConditionUnsupported
		err.Remediation = "Windows is not supported: srt marks its Windows support as alpha, which is not an isolation boundary. Run inside WSL2, where the sandbox works."
	case condition == ConditionUnsupported:
		err.Remediation = fmt.Sprintf("The %s sandbox does not run on %s.", driver, platform)
	case condition == ConditionMissing:
		err.Remediation = r.missing(platform, components)
	}
	return err
}

func (r Remedies) missing(platform Platform, components []string) string {
	var b strings.Builder
	for index, component := range components {
		if index > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s is not installed. Install it with:\n\n", component)
		for _, line := range r.installLines(platform, component) {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	for _, component := range components {
		if verify := r[component].Verify; verify != "" {
			fmt.Fprintf(&b, "\nThen confirm with: %s\n", verify)
			break
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// installLines looks up the install commands for a component, with a generic
// fallback so that a component with no table row still produces an
// actionable instruction.
func (r Remedies) installLines(platform Platform, component string) []string {
	remedy, ok := r[component]
	if !ok || len(remedy.Install) == 0 {
		return []string{fmt.Sprintf("# install %s and put it on PATH", component)}
	}
	if lines, ok := remedy.Install[platform]; ok {
		return lines
	}
	platforms := slices.Sorted(maps.Keys(remedy.Install))
	names := make([]string, 0, len(platforms))
	for _, known := range platforms {
		names = append(names, string(known))
	}
	return []string{fmt.Sprintf("# %s is packaged for %s; install it for %s from its own documentation",
		component, strings.Join(names, ", "), platform)}
}
