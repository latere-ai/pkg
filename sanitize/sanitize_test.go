package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		n     int
		want  string
	}{
		{"short string unchanged", "hello", 10, "hello"},
		{"exact length unchanged", "hello", 5, "hello"},
		{"truncated adds ellipsis", "hello world", 5, "hello…"},
		{"empty string", "", 5, ""},
		{"max zero", "hello", 0, "…"},
		{"single char truncation", "abc", 1, "a…"},
		{"multi-byte rune handling", "αβγδε", 3, "αβγ…"},
		{"exact rune count no ellipsis", "αβγ", 3, "αβγ"},
		{"toolong", "toolong", 4, "tool…"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Truncate(tc.input, tc.n)
			if got != tc.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tc.input, tc.n, got, tc.want)
			}
		})
	}
}

func TestTruncateTrimRight(t *testing.T) {
	tests := []struct {
		name  string
		input string
		n     int
		want  string
	}{
		{"short string unchanged", "hello-", 10, "hello-"},
		{"trims punctuation at boundary", "hello- world", 6, "hello…"},
		{"trims unicode safely", "你好，世界", 3, "你好…"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TruncateTrimRight(tc.input, tc.n, " \t,，;:-")
			if got != tc.want {
				t.Errorf("TruncateTrimRight(%q, %d) = %q, want %q", tc.input, tc.n, got, tc.want)
			}
		})
	}
}

func TestSlug(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"simple words", "Add dark mode", 30, "add-dark-mode"},
		{"special chars", "Fix bug: in #42!", 20, "fix-bug-in-42"},
		{"leading spaces", "  hello world", 20, "hello-world"},
		{"consecutive spaces", "a  b  c", 20, "a-b-c"},
		{"empty string", "", 20, "task"},
		{"all special", "!@#$%", 20, "task"},
		{"truncate", "abcdefghijklmnopqrstuvwxyz", 10, "abcdefghij"},
		{"truncate at dash boundary", "add dark mode toggle feature", 12, "add-dark-mod"},
		{"numbers preserved", "fix issue 123", 20, "fix-issue-123"},
		{"Hello World", "Hello World", 64, "hello-world"},
		{"special chars only fallback", "!!! @@@", 64, "task"},
		{"leading trailing special", "--hello--", 64, "hello"},
		{"collapses dashes", "hello   world", 64, "hello-world"},
		{"mixed input", "Fix bug in v1.2.3!", 64, "fix-bug-in-v1-2-3"},
		{"numbers", "task 42", 64, "task-42"},
		{"leading whitespace", "   abc", 64, "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Slug(tc.input, tc.maxLen)
			if got != tc.want {
				t.Errorf("Slug(%q, %d) = %q, want %q", tc.input, tc.maxLen, got, tc.want)
			}
		})
	}
}

func TestSlugMaxLen(t *testing.T) {
	input := "this is a long prompt that should be truncated"
	got := Slug(input, 10)
	if len(got) > 10 {
		t.Errorf("Slug result length %d exceeds maxLen 10: %q", len(got), got)
	}
}

// A negative budget used to slice the rune array at a negative index and panic.
// It now reads as zero, which is the only interpretation that keeps the
// "at most n runes" contract meaningful.
func TestTruncateNegativeBudget(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", -1, ""},
		{"hello", -1, "…"},
		{"hello", -100, "…"},
		{"αβγ", -1, "…"},
	}
	for _, c := range cases {
		if got := Truncate(c.in, c.n); got != c.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
		if got := TruncateTrimRight(c.in, c.n, " -"); got != c.want {
			t.Errorf("TruncateTrimRight(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestTruncateBytes(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"hello", 0, ""},
		{"hello", -1, ""},
		{"héllo", 2, "h"},  // é is 2 bytes; cutting at 2 would split it
		{"héllo", 3, "hé"}, // whole rune fits
		{"日本語", 4, "日"},    // each rune is 3 bytes
		{"日本語", 6, "日本"},
		{"日本語", 9, "日本語"},
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := TruncateBytes(c.in, c.n); got != c.want {
			t.Errorf("TruncateBytes(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func FuzzTruncateBytes(f *testing.F) {
	f.Add("héllo wörld 日本語", 5)
	f.Add("plain", 3)
	f.Fuzz(func(t *testing.T, s string, n int) {
		got := TruncateBytes(s, n)
		if !strings.HasPrefix(s, got) {
			t.Fatalf("%q is not a prefix of %q", got, s)
		}
		if n >= 0 && len(got) > n {
			t.Fatalf("len(%q) = %d > %d", got, len(got), n)
		}
		if utf8.ValidString(s) && !utf8.ValidString(got) {
			t.Fatalf("valid input %q produced invalid %q", s, got)
		}
	})
}

func TestIsSlug(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		why  string
	}{
		{"ab", true, "minimum length 2"},
		{"a", false, "below minimum length"},
		{"", false, "empty"},
		{"abc-def", true, "interior hyphen ok"},
		{"abc--def", true, "consecutive interior hyphens ok"},
		{"-abc", false, "leading hyphen"},
		{"abc-", false, "trailing hyphen"},
		{"Abc", false, "uppercase rejected"},
		{"abc_def", false, "underscore rejected"},
		{"abc def", false, "space rejected"},
		{"abc1", true, "digit ok"},
		{"1abc", true, "leading digit ok"},
		{"abc.def", false, "dot rejected"},
		{"abcdefghijklmnopqrstuvwxyz0123456789-abc", true, "exactly 40 chars"},
		{"abcdefghijklmnopqrstuvwxyz0123456789-abcd", false, "41 chars over limit"},
	}
	for _, c := range cases {
		if got := IsSlug(c.in); got != c.want {
			t.Errorf("IsSlug(%q) = %v, want %v (%s)", c.in, got, c.want, c.why)
		}
	}
}

func FuzzIsSlug(f *testing.F) {
	f.Add("abc-def")
	f.Add("-abc")
	f.Add("Hello World")
	f.Fuzz(func(t *testing.T, s string) {
		if g := Slug(s, SlugMaxLen); g != Fallback && len(g) >= SlugMinLen && !IsSlug(g) {
			t.Fatalf("Slug(%q) = %q, which IsSlug rejects", s, g)
		}
	})
}
