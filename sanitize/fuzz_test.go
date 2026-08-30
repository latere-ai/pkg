package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzTruncate pins the two properties callers rely on: the result is a rune
// prefix of the input (plus an ellipsis when trimmed), and it never exceeds the
// requested rune count by more than that one marker.
func FuzzTruncate(f *testing.F) {
	for _, s := range []string{"", "hello", "αβγδε", "你好，世界", "a\xffb", "\x00\x00"} {
		for _, n := range []int{-1, 0, 1, 3, 100} {
			f.Add(s, n)
		}
	}

	f.Fuzz(func(t *testing.T, s string, n int) {
		got := Truncate(s, n)
		n = max(n, 0) // the function clamps; the properties below follow the clamped budget

		if !utf8.ValidString(s) {
			// Invalid bytes decode to U+FFFD, so byte-level prefix reasoning does
			// not apply. The rune-count bound still must.
			if utf8.RuneCountInString(got) > n+1 {
				t.Fatalf("Truncate(%q, %d) = %q, over the rune budget", s, n, got)
			}
			return
		}

		if utf8.RuneCountInString(s) <= n {
			if got != s {
				t.Fatalf("Truncate(%q, %d) = %q, want the input unchanged", s, n, got)
			}
			return
		}

		trimmed, ok := strings.CutSuffix(got, "…")
		if !ok {
			t.Fatalf("Truncate(%q, %d) = %q, want an ellipsis on a shortened result", s, n, got)
		}
		if !strings.HasPrefix(s, trimmed) {
			t.Fatalf("Truncate(%q, %d) = %q, which is not a prefix of the input", s, n, got)
		}
		if utf8.RuneCountInString(trimmed) != n {
			t.Fatalf("Truncate(%q, %d) kept %d runes, want %d", s, n, utf8.RuneCountInString(trimmed), n)
		}
	})
}

// FuzzTruncateTrimRight holds the trimming variant to the same prefix property.
// Trimming only ever removes runes, so the result stays a prefix of the input.
func FuzzTruncateTrimRight(f *testing.F) {
	for _, s := range []string{"", "hello- world", "你好，世界", "----", "a\xffb"} {
		for _, cutset := range []string{"", " \t,，;:-", "abc"} {
			f.Add(s, 3, cutset)
		}
	}

	f.Fuzz(func(t *testing.T, s string, n int, cutset string) {
		got := TruncateTrimRight(s, n, cutset)
		n = max(n, 0)

		if !utf8.ValidString(s) {
			return
		}
		if utf8.RuneCountInString(s) <= n {
			if got != s {
				t.Fatalf("TruncateTrimRight(%q, %d, %q) = %q, want the input unchanged", s, n, cutset, got)
			}
			return
		}
		trimmed, ok := strings.CutSuffix(got, "…")
		if !ok {
			t.Fatalf("TruncateTrimRight(%q, %d, %q) = %q, want an ellipsis", s, n, cutset, got)
		}
		if !strings.HasPrefix(s, trimmed) {
			t.Fatalf("TruncateTrimRight(%q, %d, %q) = %q, not a prefix of the input", s, n, cutset, got)
		}
		if utf8.RuneCountInString(trimmed) > n {
			t.Fatalf("TruncateTrimRight(%q, %d, %q) = %q, over the rune budget", s, n, cutset, got)
		}
	})
}

// FuzzSlug pins the guarantee container and branch names depend on: whatever
// the input, the result is a non-empty [a-z0-9-] string with no edge hyphen and
// no doubled hyphen, and it is bounded by maxLen except for the literal
// fallback. Arbitrary bytes, unicode, and control characters all have to land
// inside that set.
func FuzzSlug(f *testing.F) {
	for _, s := range []string{"", "Add dark mode", "!@#$%", "--hello--", "你好", "a\xffb", "\x00"} {
		for _, n := range []int{0, 1, 4, 12, 64} {
			f.Add(s, n)
		}
	}

	f.Fuzz(func(t *testing.T, s string, maxLen int) {
		got := Slug(s, maxLen)

		if got == "" {
			t.Fatalf("Slug(%q, %d) returned an empty slug", s, maxLen)
		}
		for i := 0; i < len(got); i++ {
			c := got[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				t.Fatalf("Slug(%q, %d) = %q, which contains %q", s, maxLen, got, c)
			}
		}
		if strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") {
			t.Fatalf("Slug(%q, %d) = %q, which has an edge hyphen", s, maxLen, got)
		}
		if strings.Contains(got, "--") {
			t.Fatalf("Slug(%q, %d) = %q, which has a doubled hyphen", s, maxLen, got)
		}
		// The length bound is documented as "at most maxLen", with two stated
		// exceptions: the loop appends before it checks, so one character always
		// gets through, and the fallback is returned verbatim.
		if got != Fallback && len(got) > max(maxLen, 1) {
			t.Fatalf("Slug(%q, %d) = %q, over the length bound", s, maxLen, got)
		}
	})
}
