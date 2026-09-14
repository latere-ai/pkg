// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"latere.ai/x/pkg/llmdialect"
)

// fixture reads one file under testdata.
func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixtureIfPresent reads one file under testdata, or nil when there is
// no such file.
func fixtureIfPresent(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkError is the fuzz invariant on a failure: an *Error with a code
// and a sentence, and a scope for DecodeRequest.
func checkError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("not an *Error: %v", err)
	}
	if e.Code == "" || e.Message() == "" {
		t.Fatalf("no code or sentence: %+v", e)
	}
	if (e.Code == DecodeRequest) != (e.Scope != llmdialect.ScopeNone) {
		t.Fatalf("scope %q on %s", e.Scope, e.Code)
	}
}
