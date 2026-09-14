// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import "latere.ai/x/pkg/llmdialect/ir"

// Wire names an API family: its error shape, its model-list shape, its
// usage members, its count shape. There are four, one more than there
// are codec families, because Google is a wire that llmdialect cannot
// translate.
type Wire string

// The four wires.
const (
	WireOpenAI    Wire = "openai"
	WireAnthropic Wire = "anthropic"
	WireGoogle    Wire = "google"
	WireLux       Wire = "lux"
)

// wireOf is the wire a codec's dialect belongs to, and "" for a dialect
// that is none of the four.
func wireOf(d ir.Dialect) Wire {
	switch d {
	case ir.DialectOpenAIChat, ir.DialectOpenAIResponses:
		return WireOpenAI
	case ir.DialectAnthropicMessages:
		return WireAnthropic
	case ir.DialectLux:
		return WireLux
	}
	return ""
}
