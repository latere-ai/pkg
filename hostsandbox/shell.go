// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import "strings"

// ShellQuote wraps a value in single quotes and escapes any single quote it
// contains, so that a POSIX shell interprets nothing inside it. The wrapper
// script the Driver runs is built with it, and a consumer that composes a
// shell script of its own for a stage uses the same rule.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// ShellJoin renders an argv as one command line with every element quoted by
// ShellQuote.
func ShellJoin(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, arg := range argv {
		parts = append(parts, ShellQuote(arg))
	}
	return strings.Join(parts, " ")
}
