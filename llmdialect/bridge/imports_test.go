// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestImportsAreTheAllowedSet: the package imports nothing beyond the
// standard library and what llmdialect already imports, plus httpjson
// for the lux envelope. Every source file is parsed rather than the
// build listed, so the test runs with no tool on PATH.
func TestImportsAreTheAllowedSet(t *testing.T) {
	allowed := map[string]bool{
		"latere.ai/x/pkg/llmdialect":              true,
		"latere.ai/x/pkg/llmdialect/ir":           true,
		"latere.ai/x/pkg/llmdialect/anthropic":    true,
		"latere.ai/x/pkg/llmdialect/lux":          true,
		"latere.ai/x/pkg/llmdialect/openaichat":   true,
		"latere.ai/x/pkg/llmdialect/openairesp":   true,
		"latere.ai/x/pkg/llmdialect/tokencount":   true,
		"latere.ai/x/pkg/llmdialect/internal/sse": true,
		"latere.ai/x/pkg/httpjson":                true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var sources int
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		sources++
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			first, _, _ := strings.Cut(path, "/")
			if !strings.Contains(first, ".") {
				continue // the standard library
			}
			if !allowed[path] {
				t.Errorf("%s imports %s, which is outside the allowed set", file, path)
			}
		}
	}
	if sources == 0 {
		t.Fatal("no source files parsed")
	}
}
