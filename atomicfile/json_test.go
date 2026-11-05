// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSONIsIndentedWithSortedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.json")
	if err := WriteJSON(path, map[string]any{"b": []int{1}, "a": "<x>"}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\n  \"a\": \"<x>\",\n  \"b\": [\n    1\n  ]\n}"
	if string(got) != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
