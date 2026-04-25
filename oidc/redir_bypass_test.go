package oidc

import "testing"

// TestIsSafeRedirect_Backslash documents an open-redirect bypass: Chrome
// (and some other browsers) normalize backslashes in URL paths to forward
// slashes, so a target like "/\evil.com" is followed as "//evil.com" — a
// protocol-relative redirect to evil.com. isSafeRedirect must reject any
// target whose second character is a backslash.
func TestIsSafeRedirect_Backslash(t *testing.T) {
	bypasses := []string{
		`/\evil.com`,
		`/\\evil.com`,
		`/\.evil.com`,
	}
	for _, c := range bypasses {
		if isSafeRedirect(c) {
			t.Errorf("isSafeRedirect(%q) = true; should be false (backslash bypass)", c)
		}
	}
}
