// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package envutil

import (
	"strings"
	"testing"
)

// FuzzIsTruthy holds the predicate to its stated shape: case-insensitive,
// space-insensitive, and closed over exactly four spellings. Anything else,
// including the empty string, is false, so an unset variable reads as off.
func FuzzIsTruthy(f *testing.F) {
	for _, s := range []string{
		"", "1", "true", "yes", "on", "TRUE", " On ", "0", "false",
		"enabled", "\ttrue\n", "y", "a\xffb", "TRUE ",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got := IsTruthy(s)

		norm := strings.ToLower(strings.TrimSpace(s))
		want := norm == "1" || norm == "true" || norm == "yes" || norm == "on"
		if got != want {
			t.Fatalf("IsTruthy(%q) = %v, want %v", s, got, want)
		}
		// Case and surrounding space must not change the answer.
		if IsTruthy(strings.ToUpper(s)) != got {
			t.Fatalf("IsTruthy is case sensitive on %q", s)
		}
		if IsTruthy("  "+s+"\t") != got {
			t.Fatalf("IsTruthy is sensitive to surrounding space on %q", s)
		}
	})
}
