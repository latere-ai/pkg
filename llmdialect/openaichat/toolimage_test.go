// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openaichat

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// toolImageRequest is an assistant turn calling two tools and the user
// turn answering it: the first result holds text and an inline PNG, the
// second only an image by URL, then the user's own text.
func toolImageRequest(model string, hint bool) *ir.Request {
	return &ir.Request{
		Model: model,
		Messages: []ir.Message{
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "call_1", Name: "read", Args: json.RawMessage(`{"path":"a.png"}`)}},
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "call_2", Name: "read", Args: json.RawMessage(`{"path":"b.png"}`)}},
			}},
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: "call_1", Blocks: []ir.Block{
					{Type: ir.BlockText, Text: "a.png, 2x2"},
					{Type: ir.BlockImage, Image: &ir.Image{MediaType: "image/png", Data: "iVBORw0K"}},
				}}},
				{Type: ir.BlockToolResult, CacheHint: hint, ToolResult: &ir.ToolResult{ToolUseID: "call_2", Blocks: []ir.Block{
					{Type: ir.BlockImage, Image: &ir.Image{URL: "https://example.com/b.png"}},
				}}},
				{Type: ir.BlockText, Text: "what do they show?"},
			}},
		},
	}
}

func imagePart(url string) map[string]any {
	return map[string]any{"type": "image_url", "image_url": map[string]any{"url": url}}
}

func textPart(text string) map[string]any {
	return map[string]any{"type": "text", "text": text}
}

// A tool result's images reach the model: the tool messages carry the
// text, stay contiguous after the assistant turn, and the user message
// after them opens with each result's images under its call's label.
func TestEncodeToolResultImages(t *testing.T) {
	req := toolImageRequest("gpt-4.1", false)
	got := encode(t, req, BackendOptions{})
	msgs := got["messages"].([]any)
	if len(msgs) != 4 {
		t.Fatalf("messages = %d, want 4: %v", len(msgs), msgs)
	}
	roles := make([]string, len(msgs))
	for i, m := range msgs {
		roles[i] = m.(map[string]any)["role"].(string)
	}
	if want := []string{"assistant", "tool", "tool", "user"}; !reflect.DeepEqual(roles, want) {
		t.Fatalf("roles = %v, want %v", roles, want)
	}
	tool1, tool2 := msgs[1].(map[string]any), msgs[2].(map[string]any)
	if tool1["tool_call_id"] != "call_1" || tool1["content"] != "a.png, 2x2" {
		t.Errorf("first tool message = %v", tool1)
	}
	if tool2["tool_call_id"] != "call_2" || tool2["content"] != toolImageOnly {
		t.Errorf("second tool message = %v", tool2)
	}
	want := []any{
		textPart(fmt.Sprintf(toolImageLabel, "call_1")),
		imagePart("data:image/png;base64,iVBORw0K"),
		textPart(fmt.Sprintf(toolImageLabel, "call_2")),
		imagePart("https://example.com/b.png"),
		textPart("what do they show?"),
	}
	if content := msgs[3].(map[string]any)["content"]; !reflect.DeepEqual(content, want) {
		t.Errorf("user content = %v, want %v", content, want)
	}
	if fields := req.Loss.Fields(); len(fields) != 0 {
		t.Errorf("loss = %v, want none", fields)
	}
}

// A user turn that is only an image-only tool result still gets the
// image, in a user message of its own after the tool message.
func TestEncodeToolResultImageOnly(t *testing.T) {
	req := &ir.Request{Model: "m", Messages: []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{
		{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: "call_9", Blocks: []ir.Block{
			{Type: ir.BlockImage, Image: &ir.Image{MediaType: "image/webp", Data: "UklGRg"}},
		}}},
	}}}}
	msgs := encode(t, req, BackendOptions{})["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("messages = %v, want a tool and a user message", msgs)
	}
	tool, user := msgs[0].(map[string]any), msgs[1].(map[string]any)
	if tool["role"] != "tool" || tool["content"] != toolImageOnly {
		t.Errorf("tool message = %v", tool)
	}
	content := user["content"].([]any)
	if user["role"] != "user" || len(content) != 2 {
		t.Fatalf("user message = %v", user)
	}
	if label := content[0].(map[string]any)["text"]; label != fmt.Sprintf(toolImageLabel, "call_9") {
		t.Errorf("label = %v", label)
	}
	if url := content[1].(map[string]any)["image_url"].(map[string]any)["url"]; url != "data:image/webp;base64,UklGRg" {
		t.Errorf("image url = %v", url)
	}
	if fields := req.Loss.Fields(); len(fields) != 0 {
		t.Errorf("loss = %v, want none", fields)
	}
}

// A cache hint on an image-only result rides on the tool message's
// text, so it is kept rather than recorded lost for an empty text.
func TestEncodeToolResultImageCacheHint(t *testing.T) {
	req := toolImageRequest("anthropic/claude-sonnet-4.5", true)
	msgs := encode(t, req, BackendOptions{})["messages"].([]any)
	want := []any{map[string]any{"type": "text", "text": toolImageOnly, "cache_control": map[string]any{"type": "ephemeral"}}}
	if got := msgs[2].(map[string]any)["content"]; !reflect.DeepEqual(got, want) {
		t.Errorf("hinted tool content = %v, want %v", got, want)
	}
	if fields := req.Loss.Fields(); len(fields) != 0 {
		t.Errorf("loss = %v, want none", fields)
	}
}

// The frontend reads what the backend writes: the tool results come
// back with their text, and the images as image blocks of the user turn
// that follows, since this wire has no image inside a tool message.
func TestToolResultImagesRoundTrip(t *testing.T) {
	raw, err := NewBackend(BackendOptions{}).EncodeRequest(toolImageRequest("m", false))
	if err != nil {
		t.Fatal(err)
	}
	back, err := NewFrontend().DecodeRequest(raw)
	if err != nil {
		t.Fatalf("frontend cannot read backend output: %v\n%s", err, raw)
	}
	if len(back.Messages) != 3 {
		t.Fatalf("messages = %d, want 3: %+v", len(back.Messages), back.Messages)
	}
	results := back.Messages[1].Blocks
	if len(results) != 2 || results[0].ToolResult.ToolUseID != "call_1" || results[1].ToolResult.ToolUseID != "call_2" {
		t.Fatalf("tool results = %+v", results)
	}
	if text := results[0].ToolResult.Blocks[0].Text; text != "a.png, 2x2" {
		t.Errorf("first result text = %q", text)
	}
	var images []ir.Image
	for _, b := range back.Messages[2].Blocks {
		if b.Type == ir.BlockImage {
			images = append(images, *b.Image)
		}
	}
	want := []ir.Image{{MediaType: "image/png", Data: "iVBORw0K"}, {URL: "https://example.com/b.png"}}
	if !reflect.DeepEqual(images, want) {
		t.Errorf("images = %+v, want %+v", images, want)
	}
	if fields := back.Loss.Fields(); len(fields) != 0 {
		t.Errorf("decode loss = %v, want none", fields)
	}
}
