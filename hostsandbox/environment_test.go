// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"slices"
	"strings"
	"testing"
)

// TestEnvironmentAdmitsOnlyTheAllowlist checks that the environment a stage
// inherits is built from the allowlist and never copied, so that a credential
// exported in the operator's shell does not reach the stage whatever it is
// named.
func TestEnvironmentAdmitsOnlyTheAllowlist(t *testing.T) {
	operator := map[string]string{
		"PATH":                  "/usr/bin:/bin",
		"LANG":                  "en_GB.UTF-8",
		"ANTHROPIC_API_KEY":     "sk-ant-secret",
		"OPENAI_API_KEY":        "sk-secret",
		"GITHUB_TOKEN":          "ghp_secret",
		"AWS_SECRET_ACCESS_KEY": "aws-secret",
		"HOME":                  "/Users/x",
		"TERM":                  "xterm-256color",
	}
	lookup := func(name string) (string, bool) {
		value, ok := operator[name]
		return value, ok
	}
	got := Environment(lookup)
	if !slices.Contains(got, "PATH=/usr/bin:/bin") || !slices.Contains(got, "LANG=en_GB.UTF-8") {
		t.Fatalf("the stage lost what it needs to run: %v", got)
	}
	for _, entry := range got {
		name, value, _ := strings.Cut(entry, "=")
		if !slices.Contains(AllowedEnvironment, name) {
			t.Errorf("%s reached the stage and is not on the allowlist", name)
		}
		if strings.Contains(value, "secret") {
			t.Errorf("a credential reached the stage: %s", entry)
		}
		// The driver sets HOME and TERM, so the operator's values are not
		// copied even though a stage will have both.
		if name == "HOME" || name == "TERM" {
			t.Errorf("the operator's %s was inherited rather than set by the driver", entry)
		}
		// An unset variable is absent rather than present and empty.
		if name == "TZ" {
			t.Errorf("an unset variable was materialized: %s", entry)
		}
	}
	if Environment(nil) != nil {
		t.Error("a nil lookup produced an environment")
	}
}
