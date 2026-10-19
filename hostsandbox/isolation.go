// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

// Isolation is the operating system mechanism a Driver confines a stage
// with. Both run the same Profile and keep the same handles, status files and
// process groups, so a stage launched under one is observed, read, stopped
// and discarded by a driver composed with the other.
type Isolation string

// The isolations.
const (
	// IsolationAuto picks IsolationSeatbelt on macOS in a program whose
	// main called Main, and IsolationSRT otherwise: a program that has not
	// adopted Seatbelt keeps the mechanism it had.
	IsolationAuto Isolation = ""
	// IsolationSeatbelt runs a stage under macOS's Seatbelt through
	// /usr/bin/sandbox-exec, with a profile this package renders. It needs
	// nothing installed. A stage with a network allowlist reaches the
	// network through a proxy that runs beside it in a launcher process,
	// which needs the consumer's main to call Main first.
	IsolationSeatbelt Isolation = "seatbelt"
	// IsolationSRT runs a stage under srt, Anthropic's sandbox runtime:
	// Seatbelt on macOS, bubblewrap with seccomp on Linux.
	IsolationSRT Isolation = "srt"
)

// resolve is the isolation a Config with this value runs on platform, in a
// program whose main called Main when launcher is true.
func (i Isolation) resolve(platform Platform, launcher bool) Isolation {
	if i != IsolationAuto {
		return i
	}
	if platform == Darwin && launcher {
		return IsolationSeatbelt
	}
	return IsolationSRT
}
