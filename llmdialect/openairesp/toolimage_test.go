// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openairesp

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// toolImageRequest answers one function call with the given result
// blocks.
func toolImageRequest(blocks ...ir.Block) *ir.Request {
	return &ir.Request{
		Model: "gpt-5",
		Messages: []ir.Message{
			{Role: ir.RoleAssistant, Blocks: []ir.Block{
				{Type: ir.BlockToolUse, ToolUse: &ir.ToolUse{ID: "call_1", Name: "read", Args: json.RawMessage(`{"path":"a.png"}`)}},
			}},
			{Role: ir.RoleUser, Blocks: []ir.Block{
				{Type: ir.BlockToolResult, ToolResult: &ir.ToolResult{ToolUseID: "call_1", Blocks: blocks}},
			}},
		},
	}
}

// functionCallOutput encodes req and returns its function_call_output
// item's output member.
func functionCallOutput(t *testing.T, req *ir.Request) any {
	t.Helper()
	raw, err := NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range mustJSON(t, raw)["input"].([]any) {
		if m := it.(map[string]any); m["type"] == "function_call_output" {
			return m["output"]
		}
	}
	t.Fatalf("no function_call_output in %s", raw)
	return nil
}

var (
	pngBlock  = ir.Block{Type: ir.BlockImage, Image: &ir.Image{MediaType: "image/png", Data: "iVBORw0K"}}
	textBlock = ir.Block{Type: ir.BlockText, Text: "a.png, 2x2"}
)

// A tool result's image travels in the function_call_output itself, as
// the list form of output, in block order and with nothing lost.
func TestEncodeToolResultImages(t *testing.T) {
	cases := []struct {
		name   string
		blocks []ir.Block
		want   []any
	}{
		{"text and image", []ir.Block{textBlock, pngBlock}, []any{
			map[string]any{"type": "input_text", "text": "a.png, 2x2"},
			map[string]any{"type": "input_image", "image_url": "data:image/png;base64,iVBORw0K"},
		}},
		{"image only", []ir.Block{{Type: ir.BlockImage, Image: &ir.Image{URL: "https://example.com/b.png"}}}, []any{
			map[string]any{"type": "input_image", "image_url": "https://example.com/b.png"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := toolImageRequest(c.blocks...)
			if got := functionCallOutput(t, req); !reflect.DeepEqual(got, c.want) {
				t.Errorf("output = %v, want %v", got, c.want)
			}
			if fields := req.Loss.Fields(); len(fields) != 0 {
				t.Errorf("loss = %v, want none", fields)
			}
		})
	}
}

// A text-only result keeps the string form of output.
func TestEncodeToolResultTextOnly(t *testing.T) {
	if got := functionCallOutput(t, toolImageRequest(textBlock, textBlock)); got != "a.png, 2x2\n\na.png, 2x2" {
		t.Errorf("output = %v", got)
	}
}

// The frontend reads the list form of output back into the same tool
// result, so a translation through this dialect keeps the image.
func TestToolResultImagesRoundTrip(t *testing.T) {
	for _, blocks := range [][]ir.Block{{textBlock, pngBlock}, {pngBlock}} {
		raw, err := NewBackend().EncodeRequest(toolImageRequest(blocks...))
		if err != nil {
			t.Fatal(err)
		}
		back, err := NewFrontend().DecodeRequest(raw)
		if err != nil {
			t.Fatalf("frontend cannot read backend output: %v\n%s", err, raw)
		}
		if len(back.Messages) != 2 || len(back.Messages[1].Blocks) != 1 {
			t.Fatalf("messages = %+v", back.Messages)
		}
		tr := back.Messages[1].Blocks[0].ToolResult
		if tr == nil || tr.ToolUseID != "call_1" || !reflect.DeepEqual(tr.Blocks, blocks) {
			t.Errorf("tool result = %+v, want blocks %+v", tr, blocks)
		}
		if fields := back.Loss.Fields(); len(fields) != 0 {
			t.Errorf("decode loss = %v, want none", fields)
		}
	}
}

func decodeOutput(t *testing.T, output string) (*ir.Request, error) {
	t.Helper()
	body := `{"model":"m","input":[` +
		`{"type":"function_call","call_id":"c","name":"read","arguments":"{}"},` +
		`{"type":"function_call_output","call_id":"c"` + output + `}]}`
	return NewFrontend().DecodeRequest([]byte(body))
}

// The frontend takes every form of output the dialect allows: a string,
// none, null, and a part list, where a file part it cannot carry is
// recorded lost and the result still answers the call.
func TestDecodeFunctionCallOutputForms(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   []ir.Block
		loss   []ir.LossField
	}{
		{"string", `,"output":"ok"`, []ir.Block{{Type: ir.BlockText, Text: "ok"}}, nil},
		{"absent", ``, []ir.Block{{Type: ir.BlockText}}, nil},
		{"null", `,"output":null`, []ir.Block{{Type: ir.BlockText}}, nil},
		{"file only", `,"output":[{"type":"input_file","file_id":"f"}]`, []ir.Block{{Type: ir.BlockText}}, []ir.LossField{ir.LossContentTypeOf("input_file")}},
		{"text and image", `,"output":[{"type":"input_text","text":"a"},{"type":"input_image","image_url":"data:image/gif;base64,R0lG"}]`,
			[]ir.Block{{Type: ir.BlockText, Text: "a"}, {Type: ir.BlockImage, Image: &ir.Image{MediaType: "image/gif", Data: "R0lG"}}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := decodeOutput(t, c.output)
			if err != nil {
				t.Fatal(err)
			}
			if got := req.Messages[1].Blocks[0].ToolResult.Blocks; !reflect.DeepEqual(got, c.want) {
				t.Errorf("blocks = %+v, want %+v", got, c.want)
			}
			if got := req.Loss.Fields(); !slices.Equal(got, c.loss) {
				t.Errorf("loss = %v, want %v", got, c.loss)
			}
		})
	}
}

// An output that is neither a string nor a part list is refused, with
// the item and member named.
func TestDecodeFunctionCallOutputMalformed(t *testing.T) {
	for _, output := range []string{`,"output":42`, `,"output":[{"type":"input_image","image_url":"data:image/png,raw"}]`} {
		_, err := decodeOutput(t, output)
		if err == nil || !strings.Contains(err.Error(), "input[1]: output") {
			t.Errorf("output %s: err = %v, want an input[1] output error", output, err)
		}
	}
}
