// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package sanitize

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestOneLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"empty", "", 0, ""},
		{"only space", " \t\r\n ", 0, ""},
		{"plain", "hello world", 0, "hello world"},
		{"newline", "a\nb", 0, "a b"},
		{"crlf and tab", "a\r\n\tb", 0, "a b"},
		{"separators", "a b c\u0085d", 0, "a b c d"},
		{"trim", "  a  b  ", 0, "a b"},
		{"cut", "one two three", 7, "one two…"},
		{"no cut when short", "a b", 10, "a b"},
		{"negative is no cut", "a   b", -1, "a b"},
		{"multibyte cut", "你好 世界 再见", 3, "你好…"},
		{"no space before the ellipsis", "hello world foo", 6, "hello…"},
		{"invalid utf8", "a\xff\xfeb", 0, "a�b"},
		{"invalid utf8 cut", "ab\xffcd", 3, "ab�…"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OneLine(tt.in, tt.n)
			if got != tt.want {
				t.Fatalf("OneLine(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("OneLine(%q, %d) = %q is not valid UTF-8", tt.in, tt.n, got)
			}
		})
	}
}

// FuzzOneLine pins that the result is valid UTF-8, holds no whitespace other
// than a plain space, and never has two spaces in a row.
func FuzzOneLine(f *testing.F) {
	for _, s := range []string{"", "a b", " a\r\n\tb ", "a b c", "a\xffb", "你好\n世界", " x　y"} {
		for _, n := range []int{-1, 0, 1, 5, 100} {
			f.Add(s, n)
		}
	}
	f.Fuzz(func(t *testing.T, s string, n int) {
		got := OneLine(s, n)
		if !utf8.ValidString(got) {
			t.Fatalf("OneLine(%q, %d) = %q is not valid UTF-8", s, n, got)
		}
		for _, r := range got {
			if unicode.IsSpace(r) && r != ' ' {
				t.Fatalf("OneLine(%q, %d) = %q holds whitespace %U", s, n, got, r)
			}
		}
		if strings.Contains(got, "  ") {
			t.Fatalf("OneLine(%q, %d) = %q holds two spaces in a row", s, n, got)
		}
	})
}
