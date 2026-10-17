// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openaichat

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// agentTurn is a request as an agent loop sends it: a stable system
// prompt with a breakpoint, a dated tail after it, and the breakpoints
// on the last block of the latest user turns, which is a tool result.
func agentTurn(model string) *ir.Request {
	return &ir.Request{
		Model: model,
		System: []ir.Block{
			{Type: ir.BlockText, Text: "You are an agent.", CacheHint: true},
			{Type: ir.BlockText, Text: "Today is 2026-10-17."},
		},
		Messages: []ir.Message{
			{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "read a.txt", CacheHint: true}}},
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "t1", Name: "read", Args: json.RawMessage(`{"path":"a.txt"}`)}},
			}},
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockToolResult, CacheHint: true, ToolResult: &ir.ToolResult{
					ToolUseID: "t1", Blocks: []ir.Block{{Type: ir.BlockText, Text: "contents"}},
				}},
			}},
		},
	}
}

var ephemeral = map[string]any{"type": "ephemeral"}

// TestEncodeRequestCacheControlForVendorModels: a gateway that names
// models under their vendor takes cache_control for every model, and
// its Anthropic and Alibaba providers cache only what it marks, so each
// breakpoint must reach the wire on the part it was placed after: the
// stable system block, the user text, and the tool message. A provider
// that caches a repeated prefix on its own drops the mark.
func TestEncodeRequestCacheControlForVendorModels(t *testing.T) {
	for _, model := range []string{
		"anthropic/claude-sonnet-5.5", "openrouter/anthropic/claude-opus-5", "sponsored/anthropic/claude-haiku-5.5", "~anthropic/claude-sonnet-latest",
		"qwen/qwen3.6-plus", "free/qwen/qwen3.8-27b", "deepseek/deepseek-v4-flash", "openai/gpt-6.1-sol", "meta-llama/llama-3.3-70b-instruct", "moonshotai/kimi-k3",
	} {
		t.Run(model, func(t *testing.T) {
			req := agentTurn(model)
			got := encode(t, req, BackendOptions{})
			if slices.Contains(req.Loss.Fields(), "cache_control") {
				t.Fatalf("cache_control recorded as lost: %v", req.Loss.Fields())
			}
			msgs := got["messages"].([]any)
			want := []any{
				map[string]any{"role": "system", "content": []any{
					map[string]any{"type": "text", "text": "You are an agent.", "cache_control": ephemeral},
					map[string]any{"type": "text", "text": "Today is 2026-10-17."},
				}},
				map[string]any{"role": "user", "content": []any{
					map[string]any{"type": "text", "text": "read a.txt", "cache_control": ephemeral},
				}},
				msgs[2],
				map[string]any{"role": "tool", "tool_call_id": "t1", "content": []any{
					map[string]any{"type": "text", "text": "contents", "cache_control": ephemeral},
				}},
			}
			if !reflect.DeepEqual(msgs, want) {
				t.Fatalf("messages:\n got %v\nwant %v", msgs, want)
			}
		})
	}
}

// TestEncodeRequestCacheControlOtherModels: OpenAI's own endpoint and
// a runtime serving its models by bare name refuse an unknown member,
// and a mark on a Google model makes the gateway write a paid cache
// every turn instead of reading its implicit one, so these models get
// the plain shapes and the breakpoints are reported as lost.
func TestEncodeRequestCacheControlOtherModels(t *testing.T) {
	for _, model := range []string{
		"gpt-4.1", "qwen3-32b", "anthropic", "claude-sonnet-4-5", "", "anthropic/",
		"google/gemini-3.6-flash", "free/google/gemma-4-31b-it", "openrouter/google/gemini-2.5-pro", "~google/gemini-flash-latest",
	} {
		t.Run(model, func(t *testing.T) {
			req := agentTurn(model)
			raw, err := NewBackend(BackendOptions{}).EncodeRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "cache_control") {
				t.Fatalf("cache_control written for %q: %s", model, raw)
			}
			if !slices.Contains(req.Loss.Fields(), "cache_control") {
				t.Fatalf("cache_control loss missing: %v", req.Loss.Fields())
			}
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			msgs := got["messages"].([]any)
			if sys := msgs[0].(map[string]any); sys["content"] != "You are an agent.\n\nToday is 2026-10-17." {
				t.Fatalf("system = %v", sys)
			}
			if tool := msgs[3].(map[string]any); tool["content"] != "contents" {
				t.Fatalf("tool message = %v", tool)
			}
		})
	}
}

// TestEncodeRequestCacheControlNothingToMark: the Messages API refuses
// cache_control on an empty text block, so a breakpoint after empty
// text, a text-less tool result or an opaque item is lost rather than
// written; an image takes one.
func TestEncodeRequestCacheControlNothingToMark(t *testing.T) {
	req := &ir.Request{
		Model:  "anthropic/claude-sonnet-5.5",
		System: []ir.Block{{Type: ir.BlockText, Text: "", CacheHint: true}, {Type: ir.BlockImage, CacheHint: true, Image: &ir.Image{URL: "https://x/s.png"}}},
		Messages: []ir.Message{
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockText, Text: "", CacheHint: true},
				{Type: ir.BlockImage, CacheHint: true, Image: &ir.Image{URL: "https://x/y.png"}},
				{Type: ir.BlockOpaque, CacheHint: true, Opaque: &ir.Opaque{}},
				{Type: ir.BlockToolResult, CacheHint: true, ToolResult: &ir.ToolResult{ToolUseID: "t1"}},
			}},
		},
	}
	got := encode(t, req, BackendOptions{})
	msgs := got["messages"].([]any)
	if sys := msgs[0].(map[string]any); sys["content"] != "" {
		t.Fatalf("system = %v", sys)
	}
	user := msgs[1].(map[string]any)["content"].([]any)
	if _, ok := user[0].(map[string]any)["cache_control"]; ok {
		t.Fatalf("empty text marked: %v", user)
	}
	if !reflect.DeepEqual(user[1].(map[string]any)["cache_control"], ephemeral) {
		t.Fatalf("image not marked: %v", user)
	}
	if tool := msgs[2].(map[string]any); tool["content"] != "" {
		t.Fatalf("empty tool message = %v", tool)
	}
	if !slices.Contains(req.Loss.Fields(), "cache_control") {
		t.Fatalf("cache_control loss missing: %v", req.Loss.Fields())
	}
}

func TestTakesCacheControl(t *testing.T) {
	cases := map[string]bool{
		"anthropic/claude-sonnet-5.5":        true,
		"Anthropic/Claude-Opus-5":            true,
		" anthropic/claude-haiku-4.5 ":       true,
		"openrouter/anthropic/claude-opus-5": true,
		"~anthropic/claude-sonnet-latest":    true,
		"qwen/qwen3.6-plus":                  true,
		"sponsored/qwen/qwen3.8-27b":         true,
		"openai/gpt-5":                       true,
		"deepseek/deepseek-v4-flash":         true,
		"vendor/anthropic-like":              true,
		"google/gemini-3.6-flash":            false,
		"Google/Gemini-3.1-Flash-Lite":       false,
		"free/google/gemma-4-31b-it":         false,
		"~google/gemini-flash-latest":        false,
		"anthropic":                          false,
		"anthropic/":                         false,
		"/claude":                            false,
		"claude-sonnet-4-5":                  false,
		"gpt-4.1":                            false,
		"":                                   false,
	}
	for model, want := range cases {
		if got := takesCacheControl(model); got != want {
			t.Errorf("takesCacheControl(%q) = %v, want %v", model, got, want)
		}
	}
}

func FuzzTakesCacheControl(f *testing.F) {
	for _, s := range []string{"anthropic/claude", "/", "", "a/b/c", "~anthropic/", "google/gemini", "x/~google/y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, model string) {
		if !takesCacheControl(model) {
			return
		}
		segments := strings.Split(strings.ToLower(strings.TrimSpace(model)), "/")
		if len(segments) < 2 || segments[len(segments)-1] == "" {
			t.Fatalf("%q names no model under a vendor", model)
		}
		for _, s := range segments[:len(segments)-1] {
			if strings.TrimPrefix(s, "~") == "google" {
				t.Fatalf("%q is a Google model", model)
			}
		}
	})
}

// TestFrontendDecodesCacheControl: a caller on this dialect marks a
// breakpoint with cache_control on a part; it becomes the IR's cache
// hint so a translation to the Messages API keeps it.
func TestFrontendDecodesCacheControl(t *testing.T) {
	req, err := NewFrontend().DecodeRequest([]byte(`{
		"model": "m",
		"messages": [
			{"role": "system", "content": [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}]},
			{"role": "user", "content": [
				{"type": "text", "text": "look"},
				{"type": "image_url", "image_url": {"url": "https://x/y.png"}, "cache_control": {"type": "ephemeral"}},
				{"type": "text", "text": "read it", "cache_control": {"type": "ephemeral"}}
			]},
			{"role": "assistant", "content": [{"type": "text", "text": "ok", "cache_control": {"type": "ephemeral"}}], "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "read", "arguments": "{}"}}]},
			{"role": "tool", "tool_call_id": "t1", "content": [{"type": "text", "text": "data", "cache_control": {"type": "ephemeral"}}]},
			{"role": "user", "content": [{"type": "text", "text": "thanks", "cache_control": null}]}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if !req.System[0].CacheHint {
		t.Fatalf("system hint missing: %+v", req.System)
	}
	user := req.Messages[0].Blocks
	if user[0].CacheHint || !user[1].CacheHint || !user[2].CacheHint {
		t.Fatalf("user hints = %v %v %v", user[0].CacheHint, user[1].CacheHint, user[2].CacheHint)
	}
	if !req.Messages[1].Blocks[0].CacheHint {
		t.Fatalf("assistant hint missing: %+v", req.Messages[1].Blocks)
	}
	if tr := req.Messages[2].Blocks[0]; tr.Type != ir.BlockToolResult || !tr.CacheHint {
		t.Fatalf("tool result hint missing: %+v", tr)
	}
	if req.Messages[3].Blocks[0].CacheHint {
		t.Fatalf("a null cache_control is no breakpoint: %+v", req.Messages[3].Blocks)
	}
}
