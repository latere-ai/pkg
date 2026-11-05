// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package ndjson

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileAcceptsForeignLines(t *testing.T) {
	type row struct {
		Role string `json:"role"`
		Text string
	}
	path := filepath.Join(t.TempDir(), "log.jsonl")
	body := "{\"role\":\"a\",\"role\":\"b\",\"text\":\"x\xffy\"}\n{\"ROLE\":\"c\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile[row](path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Role != "b" || got[0].Text != "x�y" || got[1].Role != "c" {
		t.Errorf("got %+v", got)
	}
}

func TestAppendFileWritesSortedKeysAndReplacesInvalidUTF8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	rec := map[string]any{"b": 1, "a": "x\xffy"}
	if err := AppendFile(path, rec); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\":\"x�y\",\"b\":1}\n"; !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}
