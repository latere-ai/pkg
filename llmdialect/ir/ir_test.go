// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package ir

import (
	"encoding/json"
	"math"
	"math/bits"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestLossAddDedup(t *testing.T) {
	var l Loss
	if got := l.Fields(); got != nil {
		t.Fatalf("empty loss should have nil fields, got %v", got)
	}
	l.Add(LossTopK)
	l.Add(LossCacheControl)
	l.Add(LossTopK)
	want := []LossField{LossTopK, LossCacheControl}
	if !reflect.DeepEqual(l.Fields(), want) {
		t.Fatalf("got %v want %v", l.Fields(), want)
	}
	if !reflect.DeepEqual(l.Strings(), []string{"top_k", "cache_control"}) {
		t.Fatalf("strings = %v", l.Strings())
	}
}

// TestLogProbJSONRoundTrip pins the one thing JSON cannot say for
// itself: a masked token scores -Inf, encoding/json refuses to marshal
// it, and null is the honest wire value.
func TestLogProbJSONRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   LogProb
		want string
	}{
		{"finite", LogProb(-0.3125), "-0.3125"},
		{"certain", LogProb(0), "0"},
		{"masked", LogProb(math.Inf(-1)), "null"},
		{"positive infinity", LogProb(math.Inf(1)), "null"},
		{"not a number", LogProb(math.NaN()), "null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(raw) != tc.want {
				t.Fatalf("got %s want %s", raw, tc.want)
			}
			var back LogProb
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			switch {
			case tc.want == "null":
				// Every non-finite value comes back as the one that
				// means "could not be drawn".
				if !math.IsInf(float64(back), -1) {
					t.Fatalf("null decoded to %v, want -Inf", float64(back))
				}
			case back != tc.in:
				t.Fatalf("round trip changed %v to %v", float64(tc.in), float64(back))
			}
		})
	}
}

// TestLogProbUnmarshalRejectsNonNumbers keeps a malformed member an
// error rather than a silent zero, which reads as certainty.
func TestLogProbUnmarshalRejectsNonNumbers(t *testing.T) {
	var l LogProb
	if err := json.Unmarshal([]byte(`"-0.5"`), &l); err == nil {
		t.Fatal("want error for a string logprob")
	}
}

// TestTokenLogProbMarshalsInsideAStructure is the failure a happy-path
// test misses: a -Inf nested in a response body must not fail the whole
// encode.
func TestTokenLogProbMarshalsInsideAStructure(t *testing.T) {
	tp := TokenLogProb{
		Token: "hel", Bytes: []byte("hel"), LogProb: LogProb(math.Inf(-1)),
		Top: []TokenLogProb{{Token: "hi", LogProb: LogProb(-1.5)}},
	}
	raw, err := json.Marshal(map[string]any{"logprobs": []TokenLogProb{tp}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"LogProb":null`) {
		t.Fatalf("masked token did not encode as null: %s", raw)
	}
}

// TestPrefixCacheKeys pins the hash to its documented input on one
// literal, and the boundary rule: a key covers the blocks up to and
// including its breakpoint and nothing after, one key per breakpoint in
// order, none without one.
func TestPrefixCacheKeys(t *testing.T) {
	sys := []Block{{Type: BlockText, Text: "sys", CacheHint: true}}
	// SHA-256 of "6:system,4:text,3:sys,0:,0:," -- role, type, text,
	// signature, redacted, each as length:bytes, -- which is the whole
	// input for one hinted system text block.
	const sysKey = "832387ec6bfc85197501375b8e9b1c3477b77fdb8d272e61a4bc12fff214f619"
	if got := PrefixCacheKeys(sys, nil); !reflect.DeepEqual(got, []string{sysKey}) {
		t.Fatalf("system-only key = %v", got)
	}
	if got := PrefixCacheKeys(nil, nil); got != nil {
		t.Fatalf("no breakpoint must yield no key, got %v", got)
	}
	if got := PrefixCacheKeys([]Block{{Type: BlockText, Text: "sys"}}, []Message{{Role: RoleUser, Blocks: []Block{{Type: BlockText, Text: "hi"}}}}); got != nil {
		t.Fatalf("no breakpoint must yield no key, got %v", got)
	}

	// Whatever follows the breakpoint leaves its key alone.
	later := []Message{{Role: RoleUser, Blocks: []Block{{Type: BlockText, Text: "anything"}}}}
	if got := PrefixCacheKeys(sys, later); !reflect.DeepEqual(got, []string{sysKey}) {
		t.Fatalf("a suffix changed the key: %v", got)
	}

	// A second breakpoint adds a second key and keeps the first; the
	// second covers the blocks before it in its message and not the ones
	// after.
	msgs := []Message{
		{Role: RoleUser, Blocks: []Block{
			{Type: BlockText, Text: "before"},
			{Type: BlockImage, Image: &Image{MediaType: "image/png", Data: "aGk="}, CacheHint: true},
			{Type: BlockText, Text: "after"},
		}},
		{Role: RoleAssistant, Blocks: []Block{
			{Type: BlockToolUse, ToolUse: &ToolUse{ID: "t", Name: "f", Args: json.RawMessage(`{}`)}},
		}},
	}
	two := PrefixCacheKeys(sys, msgs)
	if len(two) != 2 || two[0] != sysKey || two[1] == sysKey {
		t.Fatalf("two breakpoints = %v", two)
	}
	msgs[0].Blocks[2].Text = "changed after"
	if again := PrefixCacheKeys(sys, msgs); !reflect.DeepEqual(again, two) {
		t.Fatalf("a block after the last breakpoint changed a key: %v vs %v", again, two)
	}
	msgs[0].Blocks[0].Text = "changed before"
	if again := PrefixCacheKeys(sys, msgs); again[0] != sysKey || again[1] == two[1] {
		t.Fatalf("a block before the last breakpoint left its key unchanged: %v vs %v", again, two)
	}

	// Every content field is part of the input: two blocks that differ
	// in one field only differ in key.
	base := Block{Type: BlockToolResult, ToolResult: &ToolResult{ToolUseID: "t", Blocks: []Block{{Type: BlockText, Text: "x"}}}, CacheHint: true}
	variants := []Block{
		{Type: BlockToolResult, ToolResult: &ToolResult{ToolUseID: "t", IsError: true, Blocks: []Block{{Type: BlockText, Text: "x"}}}, CacheHint: true},
		{Type: BlockToolResult, ToolResult: &ToolResult{ToolUseID: "u", Blocks: []Block{{Type: BlockText, Text: "x"}}}, CacheHint: true},
		{Type: BlockToolResult, ToolResult: &ToolResult{ToolUseID: "t", Blocks: []Block{{Type: BlockText, Text: "y"}}}, CacheHint: true},
		{Type: BlockThinking, Text: "x", Signature: "s", CacheHint: true},
		{Type: BlockThinking, Text: "x", Signature: "r", CacheHint: true},
		{Type: BlockRedactedThinking, Redacted: "r", CacheHint: true},
		{Type: BlockImage, Image: &Image{URL: "https://x/y.png"}, CacheHint: true},
		{Type: BlockToolUse, ToolUse: &ToolUse{ID: "t", Name: "f", Args: json.RawMessage(`{"a":1}`)}, CacheHint: true},
	}
	seen := map[string]bool{PrefixCacheKeys(nil, []Message{{Role: RoleUser, Blocks: []Block{base}}})[0]: true}
	for _, v := range variants {
		k := PrefixCacheKeys(nil, []Message{{Role: RoleUser, Blocks: []Block{v}}})[0]
		if seen[k] {
			t.Fatalf("block %+v shares a key with another", v)
		}
		seen[k] = true
	}
}

var hexKey = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FuzzPrefixCacheKeys holds the boundary rule under any content: one
// key per breakpoint, each 64 hex digits, deterministic, unchanged by
// anything after the last breakpoint, and the first key the same
// whichever later breakpoints are set.
func FuzzPrefixCacheKeys(f *testing.F) {
	f.Add("sys", "hello", "hi there", "more", uint8(1))
	f.Add("", "", "", "", uint8(15))
	f.Add("s", "u", "a", "u2", uint8(10))
	f.Add("x:y,", "1:", ",", "0:,", uint8(5))
	f.Fuzz(func(t *testing.T, sys, u1, a1, u2 string, hints uint8) {
		build := func(mask uint8) ([]Block, []Message) {
			system := []Block{{Type: BlockText, Text: sys, CacheHint: mask&1 != 0}}
			msgs := []Message{
				{Role: RoleUser, Blocks: []Block{{Type: BlockText, Text: u1, CacheHint: mask&2 != 0}}},
				{Role: RoleAssistant, Blocks: []Block{{Type: BlockText, Text: a1, CacheHint: mask&4 != 0}}},
				{Role: RoleUser, Blocks: []Block{{Type: BlockText, Text: u2, CacheHint: mask&8 != 0}}},
			}
			return system, msgs
		}
		mask := hints & 15
		system, msgs := build(mask)
		keys := PrefixCacheKeys(system, msgs)
		if len(keys) != bits.OnesCount8(mask) {
			t.Fatalf("%d breakpoints gave %d keys", bits.OnesCount8(mask), len(keys))
		}
		for i, k := range keys {
			if !hexKey.MatchString(k) {
				t.Fatalf("key %q is not 64 hex digits", k)
			}
			for _, other := range keys[:i] {
				if other == k {
					t.Fatalf("two prefixes of different length share key %q", k)
				}
			}
		}
		if again := PrefixCacheKeys(system, msgs); !reflect.DeepEqual(again, keys) {
			t.Fatalf("not deterministic: %v then %v", keys, again)
		}
		extended := append(msgs, Message{Role: RoleUser, Blocks: []Block{{Type: BlockText, Text: "tail"}}})
		if after := PrefixCacheKeys(system, extended); !reflect.DeepEqual(after, keys) {
			t.Fatalf("a block after the last breakpoint changed the keys: %v vs %v", after, keys)
		}
		if mask != 0 {
			firstOnly := mask & -mask
			system1, msgs1 := build(firstOnly)
			if first := PrefixCacheKeys(system1, msgs1); first[0] != keys[0] {
				t.Fatalf("the first key depends on later breakpoints: %q vs %q", first[0], keys[0])
			}
		}
	})
}
