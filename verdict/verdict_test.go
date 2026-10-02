// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package verdict

import (
	"math"
	"testing"
)

func TestLeast(t *testing.T) {
	cases := []struct {
		in   []Verdict
		want Verdict
	}{
		{nil, Block},
		{[]Verdict{Allow}, Allow},
		{[]Verdict{Allow, Flag}, Flag},
		{[]Verdict{Ask, Allow}, Ask},
		{[]Verdict{Allow, Block, Ask}, Block},
		{[]Verdict{Allow, "maybe"}, Block},
		{[]Verdict{"maybe", Allow}, Block},
		{[]Verdict{""}, Block},
	}
	for _, c := range cases {
		if got := Least(c.in...); got != c.want {
			t.Errorf("Least(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidShownParse(t *testing.T) {
	for _, v := range []Verdict{Allow, Flag, Ask, Block} {
		if !v.Valid() {
			t.Errorf("%q is not valid", v)
		}
		if p, ok := Parse(string(v)); !ok || p != v {
			t.Errorf("Parse(%q) = %q, %v", v, p, ok)
		}
	}
	for _, s := range []string{"", "deny", "ALLOW"} {
		if _, ok := Parse(s); ok {
			t.Errorf("Parse(%q) is ok", s)
		}
	}
	for v, want := range map[Verdict]bool{Allow: false, Flag: true, Ask: true, Block: false, "x": false} {
		if v.Shown() != want {
			t.Errorf("%q.Shown() = %v", v, !want)
		}
	}
}

func TestOnFailure(t *testing.T) {
	for ceiling, want := range map[Verdict]Verdict{Allow: Ask, Flag: Ask, Ask: Ask, Block: Block, "": Block} {
		if got := OnFailure(ceiling); got != want {
			t.Errorf("OnFailure(%q) = %q, want %q", ceiling, got, want)
		}
	}
}

func TestDecide(t *testing.T) {
	const rate = 0.05
	cases := []struct {
		name               string
		suggested, ceiling Verdict
		rate, u            float64
		want               Verdict
		probability        float64
	}{
		{"allow, not drawn", Allow, Allow, rate, 0.5, Allow, rate},
		{"allow, drawn", Allow, Allow, rate, 0.01, Flag, rate},
		{"block, not drawn", Block, Allow, rate, 0.5, Block, rate},
		{"block, drawn", Block, Allow, rate, 0.01, Ask, rate},
		{"ask is always shown", Ask, Allow, rate, 0.5, Ask, 1},
		{"a flag ceiling forces review", Allow, Flag, rate, 0.5, Flag, 1},
		{"an ask ceiling holds", Allow, Ask, rate, 0.01, Ask, 1},
		{"a block ceiling is final", Allow, Block, rate, 0.01, Block, 0},
		{"a block ceiling is final for an ask", Ask, Block, rate, 0.5, Block, 0},
		{"an invalid ceiling blocks", Allow, "", rate, 0.01, Block, 0},
		{"no suggestion is a failure", "", Allow, rate, 0.01, Ask, 1},
		{"no suggestion under a block ceiling", "", Block, rate, 0.01, Block, 0},
		{"no audits", Allow, Allow, 0, 0, Allow, 0},
		{"negative rate", Allow, Allow, -1, 0, Allow, 0},
		{"NaN rate", Allow, Allow, math.NaN(), 0, Allow, 0},
		{"rate above one", Allow, Allow, 2, 0.99, Flag, 1},
		{"u at one draws nothing", Allow, Allow, 1, 1, Allow, 0},
		{"negative u draws nothing", Allow, Allow, rate, -0.1, Allow, 0},
		{"NaN u draws nothing", Block, Allow, rate, math.NaN(), Block, 0},
		{"u equal to the rate is not drawn", Allow, Allow, rate, rate, Allow, rate},
	}
	for _, c := range cases {
		got, p := Decide(c.suggested, c.ceiling, c.rate, c.u)
		if got != c.want || p != c.probability {
			t.Errorf("%s: Decide(%q, %q, %v, %v) = %q, %v; want %q, %v",
				c.name, c.suggested, c.ceiling, c.rate, c.u, got, p, c.want, c.probability)
		}
	}
}

// The probability Decide reports is the frequency with which the action
// is shown, over the draws a caller would make.
func TestDecideProbabilityIsTheShowFrequency(t *testing.T) {
	const n, rate = 10000, 0.2
	shown := 0
	for i := range n {
		u := (float64(i) + 0.5) / n
		v, p := Decide(Allow, Allow, rate, u)
		if p != rate {
			t.Fatalf("probability %v, want %v", p, rate)
		}
		if v.Shown() {
			shown++
		}
	}
	if got := float64(shown) / n; math.Abs(got-rate) > 1e-9 {
		t.Errorf("shown %v of the time, want %v", got, rate)
	}
}

// Whatever the inputs, the result is never more permissive than the
// ceiling, a shown verdict has a positive probability, and an unshown one
// a probability below one.
func FuzzDecide(f *testing.F) {
	f.Add("allow", "allow", 0.05, 0.01)
	f.Add("block", "ask", 0.5, 0.2)
	f.Add("", "flag", 1.0, 0.0)
	f.Fuzz(func(t *testing.T, s, c string, rate, u float64) {
		v, p := Decide(Verdict(s), Verdict(c), rate, u)
		if !v.Valid() {
			t.Fatalf("Decide returned %q", v)
		}
		if Least(v, Verdict(c)) != v && Verdict(c).Valid() {
			t.Fatalf("%q exceeds the ceiling %q", v, c)
		}
		if math.IsNaN(p) || p < 0 || p > 1 {
			t.Fatalf("probability %v", p)
		}
		if v.Shown() && p == 0 {
			t.Fatalf("%q shown with probability zero", v)
		}
		if !v.Shown() && p == 1 {
			t.Fatalf("%q not shown with probability one", v)
		}
	})
}

func FuzzLeast(f *testing.F) {
	f.Add("allow", "ask")
	f.Fuzz(func(t *testing.T, a, b string) {
		got := Least(Verdict(a), Verdict(b))
		if !got.Valid() {
			t.Fatalf("Least returned %q", got)
		}
		if got != Least(Verdict(b), Verdict(a)) {
			t.Fatal("Least is not symmetric")
		}
	})
}
