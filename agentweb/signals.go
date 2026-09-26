// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"fmt"
	"strings"
)

// Signal is one usage preference: granted, refused, or not stated.
type Signal uint8

const (
	// Unset states no preference. Content Signals reads an absent category
	// as neither granting nor restricting the use, so an unset category is
	// left out of the line rather than written as a default.
	Unset Signal = iota
	// Yes grants the use.
	Yes
	// No refuses the use.
	No
)

// String returns the value Content Signals writes for s: "yes", "no", or
// "" for Unset and for any value outside the three.
func (s Signal) String() string {
	switch s {
	case Yes:
		return "yes"
	case No:
		return "no"
	}
	return ""
}

// Signals is a site's usage preferences in the three Content Signals
// categories. The zero value states nothing and renders no line.
//
// The categories, as contentsignals.org defines them:
//
//   - Search: building a search index and providing search results, meaning
//     hyperlinks and short excerpts. It does not include AI-generated search
//     summaries.
//   - AIInput: inputting content into one or more AI models, such as
//     retrieval augmented generation, grounding, or other real-time use for
//     generative AI answers.
//   - AITrain: training or fine-tuning AI models.
//
// The values are a publisher's policy, so this package ships no default: a
// site states each category it has decided and leaves the rest Unset.
type Signals struct {
	Search  Signal
	AIInput Signal
	AITrain Signal
}

// IsZero reports whether s states no preference at all.
func (s Signals) IsZero() bool { return s == Signals{} }

// String renders the value of a Content-Signal line, for example
// "ai-train=no, search=yes, ai-input=yes". Unset categories are left out,
// and a zero Signals renders "".
//
// The categories are written in the order every example on
// contentsignals.org uses, ai-train, search, ai-input. The value is a
// dictionary, so a reader does not depend on the order; keeping one order
// keeps the rendered file stable.
func (s Signals) String() string {
	parts := make([]string, 0, 3)
	for _, c := range []struct {
		label string
		v     Signal
	}{
		{"ai-train", s.AITrain},
		{"search", s.Search},
		{"ai-input", s.AIInput},
	} {
		if v := c.v.String(); v != "" {
			parts = append(parts, c.label+"="+v)
		}
	}
	return strings.Join(parts, ", ")
}

// validate rejects a Signal outside Unset, Yes and No, which a conversion
// from an integer can produce and String would silently drop.
func (s Signals) validate() error {
	for _, c := range []struct {
		label string
		v     Signal
	}{
		{"search", s.Search},
		{"ai-input", s.AIInput},
		{"ai-train", s.AITrain},
	} {
		if c.v > No {
			return fmt.Errorf("%s signal %d is not Unset, Yes or No", c.label, c.v)
		}
	}
	return nil
}
