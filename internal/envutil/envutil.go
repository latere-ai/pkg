// Package envutil holds small internal helpers for interpreting environment
// variables. It is internal so it stays off the public API surface.
package envutil

import "strings"

// IsTruthy reports whether an env var spells an affirmative ("1", "true",
// "yes", "on"; case-insensitive).
func IsTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
