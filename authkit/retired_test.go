// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// retired are the wire words the identity epic took out of the family's
// tokens and routes. Each was a real field or a real endpoint, and each
// is now a thing no service may read, mint, or call:
//
//	agent_id                  the delegated-agent claim (id-07). An agent
//	                          is a service account, and the acting agent
//	                          is a product's own column beside the bearer,
//	                          not a claim a verifier hands out
//	grantor_id                the second subject of a delegated token
//	                          (id-03). One hop, one subject
//	"act"                     RFC 8693's actor claim, which is the same
//	                          delegation said another way
//	actor: true               the flag that turned a token into an actor's
//	/tokeninfo                the issuer round trip a verifier made per
//	                          request; verification is offline
//	/userinfo/permissions     permissions fetched from the issuer;
//	                          access is by role (id-09)
//	/v1/tokens/exchange       the exchange that minted a delegated token
//
// A word here reaching a token again is the epic reopening, so the check
// is a test and not a memory.
var retired = []string{
	"agent_id",
	"grantor_id",
	`"act"`,
	"actor: true",
	"/tokeninfo",
	"/userinfo/permissions",
	"/v1/tokens/exchange",
}

// TestNoRetiredIdentityWireWordsSurvive reads every non-test Go file of
// this module and fails on a retired word. Test files are exempt on
// purpose: a test that mints a token carrying a retired claim is how a
// package proves it refuses one, and refusing it is the point.
func TestNoRetiredIdentityWireWordsSurvive(t *testing.T) {
	root := moduleRoot(t)
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		for n, line := range strings.Split(string(raw), "\n") {
			for _, word := range retired {
				if strings.Contains(line, word) {
					found = append(found, rel+":"+itoa(n+1)+": "+word)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the module: %v", err)
	}
	if len(found) > 0 {
		t.Fatalf("the identity epic retired these words, and this module still writes them:\n\t%s",
			strings.Join(found, "\n\t"))
	}
}

// TestTheRetiredCheckMatchesEveryWord is the positive control. The check
// above passes because the tree is clean, and a matcher that matched
// nothing would pass for the same reason; this one holds the word list
// against a line that carries each word, so the list is tested apart from
// whatever the tree happens to say today.
func TestTheRetiredCheckMatchesEveryWord(t *testing.T) {
	// One line per word, in the shape the word had where it lived.
	for _, tc := range []struct{ word, line string }{
		{"agent_id", "\tAgentID string `json:\"agent_id,omitempty\"`"},
		{"grantor_id", "\tGrantorID string `json:\"grantor_id,omitempty\"`"},
		{`"act"`, `	if act, ok := claims["act"].(string); ok {`},
		{"actor: true", "\treq := tokenRequest{actor: true}"},
		{"/tokeninfo", `	resp, err := c.Get(issuer + "/tokeninfo")`},
		{"/userinfo/permissions", `	resp, err := c.Get(issuer + "/userinfo/permissions")`},
		{"/v1/tokens/exchange", `	req.URL.Path = "/v1/tokens/exchange"`},
	} {
		t.Run(tc.word, func(t *testing.T) {
			if !slices.Contains(retired, tc.word) {
				t.Fatalf("%q is not on the retired list; the list is what the walk reads", tc.word)
			}
			if !strings.Contains(tc.line, tc.word) {
				t.Fatalf("the walk would not find %q in %q", tc.word, tc.line)
			}
		})
	}
	if len(retired) != 7 {
		t.Fatalf("the retired list holds %d words and this control covers 7; a word added there is a case added here", len(retired))
	}
}

// TestTheRetiredCheckReadsSomething: a walk that matched no file would
// pass whatever the tree said, so the check counts what it read.
func TestTheRetiredCheckReadsSomething(t *testing.T) {
	root := moduleRoot(t)
	read := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".go") && !strings.HasSuffix(d.Name(), "_test.go") {
			read++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the module: %v", err)
	}
	if read < 100 {
		t.Fatalf("the walk read %d non-test Go files; this module holds far more, so the walk is not reaching them", read)
	}
}

// moduleRoot is the directory holding go.mod, found by walking up from
// the test's own. It reaches no toolchain, so the check runs under the
// hermetic gate, where the only binaries on PATH are the system's.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// itoa renders a line number without pulling in a formatter for one int.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
