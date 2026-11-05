// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package sanitize

import (
	"strings"
	"unicode"
)

// OneLine collapses s to a single display line: every run of whitespace
// (anything unicode.IsSpace reports, so carriage return, tab, U+2028 and
// U+2029 included) becomes one space, and leading and trailing whitespace is
// dropped. Invalid UTF-8 is replaced with U+FFFD, so the result is always
// valid UTF-8 and a later cut can never split a character. When n > 0 the
// result is cut to n runes with [TruncateTrimRight], so a cut that lands
// after a space leaves no space before the ellipsis; n <= 0 means no cut.
func OneLine(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	out := strings.Join(strings.FieldsFunc(s, unicode.IsSpace), " ")
	if n > 0 {
		return TruncateTrimRight(out, n, " ")
	}
	return out
}
