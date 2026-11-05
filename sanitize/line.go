// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package sanitize

import (
	"unicode"
	"unicode/utf8"
)

// IsLine reports whether s is one clean line of display text: valid UTF-8
// with no control character (tab and newline included), no line or paragraph
// separator, and no bidirectional control that could reorder the text around
// it. The empty string is a line; callers check emptiness themselves.
func IsLine(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Zl, r) ||
			unicode.Is(unicode.Zp, r) || unicode.Is(unicode.Bidi_Control, r) {
			return false
		}
	}
	return true
}
