// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A stage reaches only the Mach services a program needs to run: no
// preferences service, which answers whatever the file policy says, and the
// trust service a TLS client needs.

// TestSeatbeltLooksUpNoPreferences checks the profile: no preferences
// service and no preference reads, so preferences come only from files the
// stage is granted.
func TestSeatbeltLooksUpNoPreferences(t *testing.T) {
	literalPaths(t)
	text, err := RenderSeatbelt(Profile{Home: "/Users/op"}, 0)
	if err != nil {
		t.Fatalf("RenderSeatbelt: %v", err)
	}
	for _, forbidden := range []string{"cfprefsd", "user-preference", "com.apple.SecurityServer"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the profile names %s:\n%s", forbidden, text)
		}
	}
}

// TestAStageReadsNoPreferencesOfTheOperator reads the operator's global
// preferences under the real Seatbelt, which a preferences service would
// answer whatever the file policy says, and checks the stage learns none of
// them.
func TestAStageReadsNoPreferencesOfTheOperator(t *testing.T) {
	// The operator's own home directory is the one denied, as in use: the
	// preferences live in it.
	realSeatbelt(t)
	operator, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	operator, err = filepath.EvalSymlinks(operator)
	if err != nil {
		t.Fatal(err)
	}
	driver := New(Config{Isolation: IsolationSeatbelt, Home: operator, Lookup: os.LookupEnv})
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside, err := exec.Command("/usr/bin/defaults", "read", "-g").Output() //nolint:noctx // a test
	if err != nil || len(strings.TrimSpace(string(outside))) == 0 {
		t.Skipf("the operator has no global preferences to compare: %v", err)
	}
	inside, err := attached(t, driver, StageSpec{
		Name: "preferences", Argv: []string{"/usr/bin/defaults", "read", "-g"}, Workdir: home,
		Paths: []Path{{Host: home, Access: ReadWrite}}, Network: Network{Mode: NetworkNone},
	})
	if err == nil && strings.Contains(inside, firstLineAfterBrace(string(outside))) {
		t.Fatalf("a stage read the operator's global preferences:\n%s", inside)
	}
}

// firstLineAfterBrace is the first entry of a defaults dump, a line that
// names one of the operator's preferences.
func firstLineAfterBrace(dump string) string {
	for line := range strings.SplitSeq(dump, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && trimmed != "{" {
			return trimmed
		}
	}
	return dump
}

// TestATLSClientVerifiesThroughTrustdAlone runs this test binary as a stage
// under the real Seatbelt to verify a certificate chain through macOS's
// verifier, as Go's TLS client does: it verifies, and without the trust
// service it cannot, which is why that service is the one TLS needs.
func TestATLSClientVerifiesThroughTrustdAlone(t *testing.T) {
	driver, home := realSeatbelt(t)
	chain, err := filepath.Abs(filepath.Join("testdata", "example.com.pem"))
	if err != nil {
		t.Fatal(err)
	}
	env := coverage(t)
	env[verifyVariable] = chain
	verify := func() string {
		output, _ := attached(t, driver, StageSpec{
			Name: "verify", Argv: []string{os.Args[0]}, Workdir: home, Env: env,
			Paths: []Path{{Host: home, Access: ReadWrite}}, Network: Network{Mode: NetworkNone},
		})
		return output
	}
	if output := verify(); !strings.Contains(output, "verified") || strings.Contains(output, "not verified") {
		t.Fatalf("a TLS client could not verify under Seatbelt: %q", output)
	}
	saved := seatbeltServices
	seatbeltServices = slices.DeleteFunc(slices.Clone(saved), func(name string) bool { return name == "com.apple.trustd.agent" })
	t.Cleanup(func() { seatbeltServices = saved })
	if output := verify(); !strings.Contains(output, "not verified") {
		t.Fatalf("a TLS client verified without the trust service, so the profile need not grant it: %q", output)
	}
}
