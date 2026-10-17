// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"encoding/json"
	"slices"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// TestMessagesToChatKeepsBreakpointsForAnthropicModels is a Messages
// request from an agent loop sent to a gateway that serves the Anthropic
// model on Chat Completions: every breakpoint reaches the wire, the
// system one and the one after the latest tool result, so the provider
// can serve the conversation from its cache.
func TestMessagesToChatKeepsBreakpointsForAnthropicModels(t *testing.T) {
	body := []byte(`{
		"model": "claude",
		"max_tokens": 64,
		"system": [{"type": "text", "text": "You are an agent.", "cache_control": {"type": "ephemeral"}}],
		"messages": [
			{"role": "user", "content": "read a.txt"},
			{"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "read", "input": {"path": "a.txt"}}]},
			{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "contents", "cache_control": {"type": "ephemeral"}}]}
		]
	}`)
	out, loss, err := open(t, ir.DialectAnthropicMessages, ir.DialectOpenAIChat).Request(body, RequestOptions{Model: "anthropic/claude-sonnet-5.5"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(loss, "cache_control") {
		t.Fatalf("cache_control recorded as lost: %v", loss)
	}
	var got struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"system": `[{"cache_control":{"type":"ephemeral"},"text":"You are an agent.","type":"text"}]`,
		"tool":   `[{"cache_control":{"type":"ephemeral"},"text":"contents","type":"text"}]`,
	}
	for _, m := range got.Messages {
		if w, ok := want[m.Role]; ok && string(m.Content) != w {
			t.Errorf("%s content = %s, want %s", m.Role, m.Content, w)
		}
	}
}
