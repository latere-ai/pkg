// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"os/exec"
	"testing"
	"unicode/utf8"
)

func TestShellJoinQuotesEveryElement(t *testing.T) {
	got := ShellJoin([]string{"echo", "it's", "$HOME", "a b", ""})
	want := `'echo' 'it'\''s' '$HOME' 'a b' ''`
	if got != want {
		t.Fatalf("ShellJoin = %s, want %s", got, want)
	}
}

// FuzzShellQuoteRoundTrips checks that a quoted value reaches a real shell
// unchanged: nothing inside it is expanded, split or interpreted.
func FuzzShellQuoteRoundTrips(f *testing.F) {
	for _, seed := range []string{"", "plain", "it's", "$HOME `id` $(id)", "a b\tc", "'", `\`, "new\nline", "*?[]", "-n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if !utf8.ValidString(value) || len(value) > 512 {
			t.Skip("the shell round trip is about quoting, not about invalid UTF-8 or long arguments")
		}
		output, err := exec.Command("/bin/sh", "-c", "printf %s "+ShellQuote(value)).Output()
		if err != nil {
			t.Fatalf("sh: %v", err)
		}
		if string(output) != value {
			t.Fatalf("round trip of %q gave %q", value, output)
		}
	})
}
