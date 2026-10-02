// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package verdict is the vocabulary every decision point shares when it
// decides whether an automated action runs: an agent's tool call, a
// sandbox's network request, a push, a payment.
//
// There are four verdicts, ordered from most to least permissive: [Allow]
// runs the action, [Flag] runs it and shows it to a person afterwards,
// [Ask] holds it until a person answers, and [Block] refuses it. A
// decision point composes the opinions of its layers with [Least], so a
// layer can narrow a verdict and never widen one; a layer whose verdict is
// unknown counts as [Block]. A decision point that cannot reach a layer it
// relies on decides [OnFailure], which is never more permissive than
// [Ask].
//
// [Decide] is the whole composition: a suggested verdict, the ceiling the
// deterministic layers leave open, and the share of automatic verdicts a
// person reviews at random. It returns the verdict to apply and the
// probability, fixed before the action runs, that a person sees the
// action. Recording that probability with every decision is what makes the
// error rate of any decision source estimable without bias: a person's
// answer to an action seen with probability p counts with weight 1/p.
package verdict

import "math"

// Verdict is what a decision point does with one action.
type Verdict string

const (
	// Allow runs the action.
	Allow Verdict = "allow"
	// Flag runs the action and shows it to a person afterwards.
	Flag Verdict = "flag"
	// Ask holds the action until a person answers.
	Ask Verdict = "ask"
	// Block refuses the action.
	Block Verdict = "block"
)

// rank orders the verdicts from most to least permissive.
var rank = map[Verdict]int{Allow: 0, Flag: 1, Ask: 2, Block: 3}

// Valid reports whether v is one of the four verdicts.
func (v Verdict) Valid() bool {
	_, ok := rank[v]
	return ok
}

// Shown reports whether a person sees an action under v: before it runs
// for [Ask], after it runs for [Flag].
func (v Verdict) Shown() bool { return v == Flag || v == Ask }

// Parse returns the verdict s names, and false for any other string.
func Parse(s string) (Verdict, bool) {
	v := Verdict(s)
	return v, v.Valid()
}

// Least returns the least permissive of the verdicts. A verdict outside
// the four counts as [Block], so a malformed opinion can only narrow the
// result, and Least with no verdicts is [Block] for the same reason.
func Least(vs ...Verdict) Verdict {
	if len(vs) == 0 {
		return Block
	}
	out := Allow
	for _, v := range vs {
		if !v.Valid() {
			return Block
		}
		if rank[v] > rank[out] {
			out = v
		}
	}
	return out
}

// OnFailure is the verdict of a decision point that could not obtain an
// opinion it relies on: [Ask], narrowed by the ceiling. A failure never
// allows.
func OnFailure(ceiling Verdict) Verdict { return Least(Ask, ceiling) }

// Decide composes one decision. suggested is the opinion of the layer that
// knows the action best, a learned model or a rule; ceiling is the most
// permissive verdict the deterministic layers leave open; rate is the
// share of automatic verdicts a person reviews at random; u is a uniform
// draw from [0, 1) made once for this action. It returns the verdict to
// apply and the probability, in [0, 1], that a person sees the action:
//
//   - a ceiling of [Block] is a deterministic deny: Block, never shown;
//   - an [Ask] or a [Flag] is shown with probability one;
//   - an automatic [Allow] becomes [Flag] when u < rate, and an automatic
//     [Block] becomes [Ask], so a person reviews it; either way the
//     probability of being shown is rate, drawn or not, because that is
//     the probability the action had.
//
// A suggestion that is not a verdict counts as a failure ([OnFailure]). A
// rate outside [0, 1] is clamped, and NaN is zero. A u outside [0, 1), or
// NaN, is no draw: the action is not sampled and its probability is zero.
// The caller must draw u once per action and never
// again: drawing until the review misses would make the sample, and every
// estimate built on it, biased.
func Decide(suggested, ceiling Verdict, rate, u float64) (Verdict, float64) {
	if !ceiling.Valid() || ceiling == Block {
		return Block, 0
	}
	v := OnFailure(ceiling)
	if suggested.Valid() {
		v = Least(suggested, ceiling)
	}
	if v.Shown() {
		return v, 1
	}
	switch {
	case math.IsNaN(rate) || rate <= 0 || !(u >= 0 && u < 1):
		return v, 0
	case rate > 1:
		rate = 1
	}
	if u < rate {
		if v == Allow {
			return Flag, rate
		}
		return Ask, rate
	}
	return v, rate
}
