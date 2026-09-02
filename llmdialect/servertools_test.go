// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package llmdialect

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"latere.ai/x/pkg/llmdialect/anthropic"
	"latere.ai/x/pkg/llmdialect/ir"
	"latere.ai/x/pkg/llmdialect/lux"
	"latere.ai/x/pkg/llmdialect/openaichat"
	"latere.ai/x/pkg/llmdialect/openairesp"
)

// groundedRequest is the shape a caller sends to ask for a grounded answer:
// a provider-executed fetch tool in the tools array, and the request-level
// search switch beside it. Both were dropped before server tools existed.
const groundedRequest = `{
	"model": "anthropic/claude-sonnet-4-5-20250929",
	"messages": [
		{"role": "system", "content": "cite your sources"},
		{"role": "user", "content": "what changed in Go 1.27"}
	],
	"web_search_options": {"search_context_size": "medium"},
	"tools": [{"type": "web_fetch_20250910", "name": "web_fetch", "max_uses": 5}]
}`

// TestGroundedRequestSurvivesChatRoundTrip is the regression this feature
// exists for: decoding and re-encoding the request above must leave the
// grounding intact. Before, the tool became a loss entry and the search
// switch an unknown field, so the model answered ungrounded and nothing said
// so.
func TestGroundedRequestSurvivesChatRoundTrip(t *testing.T) {
	req, err := openaichat.NewFrontend().DecodeRequest([]byte(groundedRequest))
	if err != nil {
		t.Fatalf("DecodeRequest() error: %v", err)
	}

	if len(req.ServerTools) != 1 {
		t.Fatalf("ServerTools = %+v, want one entry", req.ServerTools)
	}
	if req.ServerTools[0].Type != "web_fetch_20250910" || req.ServerTools[0].Name != "web_fetch" {
		t.Fatalf("ServerTools[0] = %+v", req.ServerTools[0])
	}
	if req.WebSearch == nil || req.WebSearch.ContextSize != "medium" {
		t.Fatalf("WebSearch = %+v, want context size medium", req.WebSearch)
	}
	// A provider-run tool must not appear in Tools, which callers walk to
	// build the set of calls they have to answer themselves.
	if len(req.Tools) != 0 {
		t.Fatalf("Tools = %+v, want none", req.Tools)
	}
	if fields := req.Loss.Fields(); len(fields) != 0 {
		t.Fatalf("Loss = %v, want nothing lost", fields)
	}

	out, err := openaichat.NewBackend(openaichat.BackendOptions{}).EncodeRequest(req)
	if err != nil {
		t.Fatalf("EncodeRequest() error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal encoded request: %v", err)
	}
	wantTools := []any{map[string]any{
		"type": "web_fetch_20250910", "name": "web_fetch", "max_uses": float64(5),
	}}
	if !reflect.DeepEqual(got["tools"], wantTools) {
		t.Fatalf("tools = %#v, want %#v", got["tools"], wantTools)
	}
	wantSearch := map[string]any{"search_context_size": "medium"}
	if !reflect.DeepEqual(got["web_search_options"], wantSearch) {
		t.Fatalf("web_search_options = %#v, want %#v", got["web_search_options"], wantSearch)
	}
}

// TestGroundedRequestSurvivesLuxRoundTrip keeps the gateway's own dialect in
// step. A field the lux codec cannot carry is one every service behind the
// gateway loses.
func TestGroundedRequestSurvivesLuxRoundTrip(t *testing.T) {
	req, err := openaichat.NewFrontend().DecodeRequest([]byte(groundedRequest))
	if err != nil {
		t.Fatalf("DecodeRequest() error: %v", err)
	}

	wire, err := lux.NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatalf("lux EncodeRequest() error: %v", err)
	}
	back, err := lux.NewFrontend().DecodeRequest(wire)
	if err != nil {
		t.Fatalf("lux DecodeRequest() error: %v", err)
	}

	if !reflect.DeepEqual(back.ServerTools, req.ServerTools) {
		t.Fatalf("ServerTools = %+v, want %+v", back.ServerTools, req.ServerTools)
	}
	if !reflect.DeepEqual(back.WebSearch, req.WebSearch) {
		t.Fatalf("WebSearch = %+v, want %+v", back.WebSearch, req.WebSearch)
	}
}

// TestAnthropicServerToolRoundTrip covers the dialect where these tools are
// native. The options must reach the provider unchanged: max_uses is what
// stops a fetch tool from running away.
func TestAnthropicServerToolRoundTrip(t *testing.T) {
	in := `{
		"model": "claude-sonnet-4-5",
		"max_tokens": 1024,
		"messages": [{"role": "user", "content": "x"}],
		"tools": [
			{"type": "web_search_20250305", "name": "web_search", "max_uses": 3, "allowed_domains": ["go.dev"]},
			{"name": "local", "input_schema": {"type": "object"}}
		]
	}`
	req, err := anthropic.NewFrontend().DecodeRequest([]byte(in))
	if err != nil {
		t.Fatalf("DecodeRequest() error: %v", err)
	}
	if len(req.Tools) != 1 || req.Tools[0].Name != "local" {
		t.Fatalf("Tools = %+v, want only the caller-run tool", req.Tools)
	}
	if len(req.ServerTools) != 1 || req.ServerTools[0].Type != "web_search_20250305" {
		t.Fatalf("ServerTools = %+v", req.ServerTools)
	}

	out, err := anthropic.NewBackend(anthropic.BackendOptions{}).EncodeRequest(req)
	if err != nil {
		t.Fatalf("EncodeRequest() error: %v", err)
	}
	var got struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Tools) != 2 {
		t.Fatalf("tools = %v, want both back", got.Tools)
	}
	want := map[string]any{
		"type": "web_search_20250305", "name": "web_search",
		"max_uses": float64(3), "allowed_domains": []any{"go.dev"},
	}
	if !reflect.DeepEqual(got.Tools[1], want) {
		t.Fatalf("server tool = %#v, want %#v", got.Tools[1], want)
	}
}

// TestAnthropicReportsWebSearchSwitch pins the honest degrade: the Messages
// API has no request-level search switch, so asking for one there is a loss,
// not a silent ungrounded answer.
func TestAnthropicReportsWebSearchSwitch(t *testing.T) {
	req := &ir.Request{
		Model:     "claude-sonnet-4-5",
		Messages:  []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}},
		WebSearch: &ir.WebSearch{ContextSize: "high"},
	}
	if _, err := anthropic.NewBackend(anthropic.BackendOptions{}).EncodeRequest(req); err != nil {
		t.Fatalf("EncodeRequest() error: %v", err)
	}
	if !hasLoss(req, ir.LossWebSearch) {
		t.Fatalf("Loss = %v, want %q", req.Loss.Fields(), ir.LossWebSearch)
	}
}

// TestResponsesReportsBothLost covers the dialect whose server tools are a
// different vocabulary. Forwarding one blind would ask for a tool the
// provider does not have, so both are reported instead of guessed at.
func TestResponsesReportsBothLost(t *testing.T) {
	req := &ir.Request{
		Model:       "gpt-5",
		Messages:    []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "x"}}}},
		ServerTools: []ir.ServerTool{{Type: "web_fetch_20250910", Name: "web_fetch"}},
		WebSearch:   &ir.WebSearch{ContextSize: "medium"},
	}
	if _, err := openairesp.NewBackend().EncodeRequest(req); err != nil {
		t.Fatalf("EncodeRequest() error: %v", err)
	}
	for _, want := range []ir.LossField{ir.LossServerToolOf("web_fetch_20250910"), ir.LossWebSearch} {
		if !hasLoss(req, want) {
			t.Fatalf("Loss = %v, want %q", req.Loss.Fields(), want)
		}
	}
}

// TestWebSearchUserLocationSurvives keeps the provider-shaped location object
// intact: the dialects that accept it do not agree on its fields, so it is
// carried unread.
func TestWebSearchUserLocationSurvives(t *testing.T) {
	in := `{
		"model": "m",
		"messages": [{"role": "user", "content": "x"}],
		"web_search_options": {"search_context_size": "high", "user_location": {"type": "approximate", "country": "DE"}}
	}`
	req, err := openaichat.NewFrontend().DecodeRequest([]byte(in))
	if err != nil {
		t.Fatalf("DecodeRequest() error: %v", err)
	}
	out, err := openaichat.NewBackend(openaichat.BackendOptions{}).EncodeRequest(req)
	if err != nil {
		t.Fatalf("EncodeRequest() error: %v", err)
	}
	var got struct {
		WebSearchOptions map[string]any `json:"web_search_options"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]any{
		"search_context_size": "high",
		"user_location":       map[string]any{"type": "approximate", "country": "DE"},
	}
	if !reflect.DeepEqual(got.WebSearchOptions, want) {
		t.Fatalf("web_search_options = %#v, want %#v", got.WebSearchOptions, want)
	}
}

func hasLoss(req *ir.Request, want ir.LossField) bool {
	return slices.Contains(req.Loss.Fields(), want)
}
