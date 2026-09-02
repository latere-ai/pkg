// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package servertool

import (
	"encoding/json"
	"reflect"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want ir.ServerTool
	}{
		{
			name: "type and name only",
			raw:  `{"type":"web_search_20250305","name":"web_search"}`,
			want: ir.ServerTool{Type: "web_search_20250305", Name: "web_search"},
		},
		{
			name: "options are kept unread",
			raw:  `{"type":"web_fetch_20250910","name":"web_fetch","max_uses":5}`,
			want: ir.ServerTool{Type: "web_fetch_20250910", Name: "web_fetch", Config: json.RawMessage(`{"max_uses":5}`)},
		},
		{
			name: "nested options survive",
			raw:  `{"type":"web_search","web_search":{"allowed_domains":["a.com"]}}`,
			want: ir.ServerTool{Type: "web_search", Config: json.RawMessage(`{"web_search":{"allowed_domains":["a.com"]}}`)},
		},
		{
			name: "no type is still a tool",
			raw:  `{"name":"x"}`,
			want: ir.ServerTool{Name: "x"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(json.RawMessage(tt.raw))
			if err != nil {
				t.Fatalf("Decode() error: %v", err)
			}
			if got.Type != tt.want.Type || got.Name != tt.want.Name {
				t.Fatalf("Decode() = %+v, want %+v", got, tt.want)
			}
			if !jsonEqual(t, got.Config, tt.want.Config) {
				t.Fatalf("Config = %s, want %s", got.Config, tt.want.Config)
			}
		})
	}
}

// TestDecodeNilConfigWhenNothingRemains keeps a bare tool from growing an
// empty object that would then encode back as one.
func TestDecodeNilConfigWhenNothingRemains(t *testing.T) {
	got, err := Decode(json.RawMessage(`{"type":"t","name":"n"}`))
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}
	if got.Config != nil {
		t.Fatalf("Config = %s, want nil", got.Config)
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, raw := range []string{`not json`, `[]`, `{"type":5}`, `{"name":{}}`} {
		t.Run(raw, func(t *testing.T) {
			if _, err := Decode(json.RawMessage(raw)); err == nil {
				t.Fatalf("Decode(%s) = nil error, want one", raw)
			}
		})
	}
}

func TestEncode(t *testing.T) {
	got, err := Encode(ir.ServerTool{
		Type:   "web_fetch_20250910",
		Name:   "web_fetch",
		Config: json.RawMessage(`{"max_uses":5}`),
	})
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}
	want := map[string]any{"type": "web_fetch_20250910", "name": "web_fetch", "max_uses": float64(5)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Encode() = %v, want %v", got, want)
	}
}

// TestEncodeStructFieldsWin is the property that makes a round trip safe: a
// stale type or name left inside Config must never override the real one.
func TestEncodeStructFieldsWin(t *testing.T) {
	got, err := Encode(ir.ServerTool{
		Type:   "real_type",
		Name:   "real_name",
		Config: json.RawMessage(`{"type":"stale","name":"stale","max_uses":2}`),
	})
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}
	if got["type"] != "real_type" || got["name"] != "real_name" {
		t.Fatalf("Encode() = %v, want the struct fields to win", got)
	}
}

// TestEncodeDropsNameWhenUnset avoids emitting a tool named "" when Config
// carried a name the struct did not.
func TestEncodeDropsNameWhenUnset(t *testing.T) {
	got, err := Encode(ir.ServerTool{Type: "t", Config: json.RawMessage(`{"name":"stale"}`)})
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}
	if _, ok := got["name"]; ok {
		t.Fatalf("Encode() = %v, want no name", got)
	}
}

func TestEncodeMalformedConfig(t *testing.T) {
	if _, err := Encode(ir.ServerTool{Type: "t", Config: json.RawMessage(`[1,2]`)}); err == nil {
		t.Fatal("Encode() = nil error, want one for a non-object config")
	}
}

// TestRoundTrip is the invariant the two halves exist to hold: whatever a
// provider sent arrives at the far side unchanged.
func TestRoundTrip(t *testing.T) {
	for _, raw := range []string{
		`{"type":"web_search_20250305","name":"web_search"}`,
		`{"type":"web_fetch_20250910","name":"web_fetch","max_uses":5}`,
		`{"type":"web_search_20250305","name":"web_search","allowed_domains":["a.com","b.org"],"max_uses":3}`,
	} {
		t.Run(raw, func(t *testing.T) {
			st, err := Decode(json.RawMessage(raw))
			if err != nil {
				t.Fatalf("Decode() error: %v", err)
			}
			enc, err := Encode(st)
			if err != nil {
				t.Fatalf("Encode() error: %v", err)
			}
			out, err := json.Marshal(enc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !jsonEqual(t, out, json.RawMessage(raw)) {
				t.Fatalf("round trip = %s, want %s", out, raw)
			}
		})
	}
}

// FuzzDecode asserts Decode never panics and that anything it accepts encodes
// back to a JSON object.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		`{"type":"t"}`, `{}`, `{"type":"t","name":"n","x":1}`, `null`, `{"a":[1,{"b":null}]}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		st, err := Decode(json.RawMessage(s))
		if err != nil {
			return
		}
		enc, err := Encode(st)
		if err != nil {
			t.Fatalf("Encode() rejected what Decode(%q) accepted: %v", s, err)
		}
		if _, err := json.Marshal(enc); err != nil {
			t.Fatalf("Encode() produced unmarshalable output for %q: %v", s, err)
		}
	})
}

func jsonEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &y); err != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
