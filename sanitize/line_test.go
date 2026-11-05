// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package sanitize

import "testing"

func TestIsLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", true},
		{"plain", "hello world", true},
		{"multibyte", "你好 世界 é", true},
		{"tab", "a\tb", false},
		{"newline", "a\nb", false},
		{"carriage return", "a\rb", false},
		{"nul", "a\x00b", false},
		{"c1 control", "a\u0085b", false},
		{"line separator", "a b", false},
		{"paragraph separator", "a b", false},
		{"right-to-left override", "a‮b", false},
		{"embedding", "a‪b", false},
		{"isolate", "a⁦b", false},
		{"left-to-right mark", "a‎b", false},
		{"arabic letter mark", "a؜b", false},
		{"invalid utf8", "a\xffb", false},
		{"no-break space is fine", "a b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLine(tt.in); got != tt.want {
				t.Fatalf("IsLine(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// FuzzIsLine pins that IsLine never panics and that a line survives
// OneLine's whitespace rules only when it holds no space other than ' '.
func FuzzIsLine(f *testing.F) {
	for _, s := range []string{"", "a", "a\tb", "a b", "a‮b", "a\xffb", "你好"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if IsLine(s) && IsLine(s+"\n") {
			t.Fatalf("IsLine accepts %q with a newline appended", s)
		}
	})
}
