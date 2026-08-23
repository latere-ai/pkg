package slugutil

import (
	"strings"
	"testing"
)

// FuzzIsValid re-derives the slug grammar from its prose statement and holds
// IsValid to it. The implementation walks runes but bounds length in bytes, so
// the two disagree on any multi-byte input unless the rune check rejects it
// first; this pins that they do not.
func FuzzIsValid(f *testing.F) {
	for _, s := range []string{
		"", "a", "ab", "abc-def", "abc--def", "-abc", "abc-", "Abc",
		"abc_def", "abc def", "1abc", "abc.def", "é", "a\xffb",
		strings.Repeat("a", MaxLen), strings.Repeat("a", MaxLen+1),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got := IsValid(s)

		want := len(s) >= MinLen && len(s) <= MaxLen
		if want {
			for i := 0; i < len(s); i++ {
				c := s[i]
				switch {
				case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
				case c == '-':
					if i == 0 || i == len(s)-1 {
						want = false
					}
				default:
					want = false
				}
				if !want {
					break
				}
			}
		}

		if got != want {
			t.Fatalf("IsValid(%q) = %v, want %v", s, got, want)
		}

		// A valid slug must survive a round trip through the grammar it claims
		// to satisfy: lowercase-stable and free of any character outside the set.
		if got {
			if s != strings.ToLower(s) {
				t.Fatalf("IsValid(%q) accepted a string that is not lowercase", s)
			}
			if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
				t.Fatalf("IsValid(%q) accepted an edge hyphen", s)
			}
		}
	})
}
