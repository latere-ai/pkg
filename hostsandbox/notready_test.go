// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"errors"
	"strings"
	"testing"
)

// TestEveryRefusalNamesItsRemedy checks that every refusal is reachable with
// nothing installed. The message is a pure function of platform and
// condition, so the operator-facing text is tested rather than observed on a
// broken machine.
func TestEveryRefusalNamesItsRemedy(t *testing.T) {
	remedies := DefaultRemedies()
	cases := []struct {
		platform   Platform
		components []string
		want       []string
	}{
		{Darwin, []string{"srt"},
			// The verify command is bare words, not a quoted string. srt
			// accepts a string only after -c.
			[]string{"srt is not installed", "npm install -g @anthropic-ai/sandbox-runtime", "brew install ripgrep", "Then confirm with: srt echo ok"}},
		{Linux, []string{"bubblewrap", "socat"},
			[]string{"apt-get install -y bubblewrap", "dnf install -y socat"}},
		{Linux, []string{"rg"}, []string{"apt-get install -y ripgrep"}},
	}
	for _, c := range cases {
		err := remedies.NotReady(c.platform, Host, ConditionMissing, c.components...)
		if !errors.Is(err, ErrNotReady) {
			t.Fatalf("%s/%v does not unwrap to ErrNotReady", c.platform, c.components)
		}
		message := err.Error()
		if !strings.HasPrefix(message, "the host sandbox is not ready ("+strings.Join(c.components, ", ")+": missing)") {
			t.Errorf("%s/%v header:\n%s", c.platform, c.components, message)
		}
		for _, want := range c.want {
			if !strings.Contains(message, want) {
				t.Errorf("%s/%v message missing %q:\n%s", c.platform, c.components, want, message)
			}
		}
	}
	// A component with no verify line yields no confirm line rather than an
	// empty one.
	if message := remedies.NotReady(Linux, Host, ConditionMissing, "socat").Error(); strings.Contains(message, "confirm") {
		t.Errorf("a component with no verify command printed a confirm line:\n%s", message)
	}
}

// TestAnUntabulatedComponentStillSaysSomething checks that a component with
// no install row still gets an actionable line, and that a component packaged
// for another platform names that platform.
func TestAnUntabulatedComponentStillSaysSomething(t *testing.T) {
	remedies := DefaultRemedies()
	message := remedies.NotReady(Linux, Host, ConditionMissing, "some-new-tool").Error()
	if !strings.Contains(message, "some-new-tool") || !strings.Contains(message, "PATH") {
		t.Fatalf("no fallback instruction:\n%s", message)
	}
	message = remedies.NotReady(Darwin, Host, ConditionMissing, "bubblewrap").Error()
	if !strings.Contains(message, "packaged for linux") {
		t.Fatalf("cross-platform fallback lost the platform it is packaged for:\n%s", message)
	}
	// A row with a verify command and no install lines still falls back.
	empty := Remedies{"tool": {Verify: "tool --version"}}
	message = empty.NotReady(Darwin, Host, ConditionMissing, "tool").Error()
	if !strings.Contains(message, "# install tool and put it on PATH") || !strings.Contains(message, "tool --version") {
		t.Fatalf("an install-less row:\n%s", message)
	}
}

// TestAConsumerAddsItsOwnRows checks that With merges a consumer's rows over
// the defaults without changing the defaults another consumer reads.
func TestAConsumerAddsItsOwnRows(t *testing.T) {
	merged := DefaultRemedies().With(Remedies{
		"claude": {Install: map[Platform][]string{Darwin: {"npm install -g @anthropic-ai/claude-code"}}, Verify: "claude --version"},
		"srt":    {Install: map[Platform][]string{Darwin: {"a mirror"}}},
	})
	message := merged.NotReady(Darwin, Host, ConditionMissing, "claude").Error()
	for _, want := range []string{"claude is not installed", "npm install -g @anthropic-ai/claude-code", "claude --version"} {
		if !strings.Contains(message, want) {
			t.Errorf("missing %q:\n%s", want, message)
		}
	}
	if message := merged.NotReady(Darwin, Host, ConditionMissing, "srt").Error(); !strings.Contains(message, "a mirror") {
		t.Errorf("a consumer's row did not replace the default:\n%s", message)
	}
	if message := DefaultRemedies().NotReady(Darwin, Host, ConditionMissing, "srt").Error(); strings.Contains(message, "a mirror") {
		t.Errorf("With changed the default table:\n%s", message)
	}
}

// TestWindowsIsRefusedWithAReason checks that Windows yields the unsupported
// condition whatever was asked for, and names WSL2.
func TestWindowsIsRefusedWithAReason(t *testing.T) {
	err := DefaultRemedies().NotReady(Windows, Host, ConditionMissing, "srt")
	if err.Condition != ConditionUnsupported {
		t.Errorf("condition = %s", err.Condition)
	}
	if message := err.Error(); !strings.Contains(message, "WSL2") || !strings.Contains(message, "(srt: unsupported)") {
		t.Errorf("windows refusal:\n%s", message)
	}
	other := DefaultRemedies().NotReady(Linux, Host, ConditionUnsupported, "srt")
	if !strings.Contains(other.Error(), "The host sandbox does not run on linux.") {
		t.Errorf("unsupported refusal:\n%s", other.Error())
	}
}

// TestTheErrorPrintsEverySectionItCarries checks the message layout: header,
// remediation, alternative, detail, each present only when set, and that a
// consumer's own condition yields a header with no remediation to fill in.
func TestTheErrorPrintsEverySectionItCarries(t *testing.T) {
	err := DefaultRemedies().NotReady(Linux, "container", Condition("stopped"), "podman")
	if err.Remediation != "" {
		t.Fatalf("a foreign condition was given a remediation: %q", err.Remediation)
	}
	if got := err.Error(); got != "the container sandbox is not ready (podman: stopped)" {
		t.Fatalf("bare header = %q", got)
	}
	err.Remediation = "systemctl --user start podman"
	err.Alternative = "Or use the host sandbox."
	err.Detail = "  cannot connect to podman socket  \n"
	want := "the container sandbox is not ready (podman: stopped)\n\nsystemctl --user start podman\n\nOr use the host sandbox.\n\ncannot connect to podman socket"
	if got := err.Error(); got != want {
		t.Fatalf("message:\n%s\nwant:\n%s", got, want)
	}
	if got := (&NotReadyError{Driver: Host}).Error(); got != "the host sandbox is not ready" {
		t.Fatalf("empty error = %q", got)
	}
	if CurrentPlatform() == "" {
		t.Fatal("no current platform")
	}
}
