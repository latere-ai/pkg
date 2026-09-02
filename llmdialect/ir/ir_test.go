// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package ir

import (
	"encoding/json"
	"math"
	"reflect"
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
