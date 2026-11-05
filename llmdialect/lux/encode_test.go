// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package lux

import (
	"encoding/json/v2"
	"testing"

	"latere.ai/x/pkg/llmdialect/internal/wirejson"
)

// A block that sets no cache hint carries no cache_hint member, and a foreign
// raw value inside it keeps its repeated name.
func TestEncodeOmitsUnsetFlagsAndKeepsForeignRawValue(t *testing.T) {
	blk := Block{Type: "opaque", Opaque: &Opaque{Dialect: "x", Raw: []byte(`{"a":1,"a":2}`)}}
	got, err := json.Marshal(blk, wirejson.Out)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"type":"opaque","opaque":{"dialect":"x","raw":{"a":1,"a":2}}}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
