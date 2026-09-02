// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package servertool encodes and decodes provider-executed tool entries.
//
// Anthropic Messages and OpenAI Chat Completions both carry these as objects
// in the same tools array as ordinary function tools, distinguished only by
// their type string. The shape is identical in both, so the translation lives
// here once instead of twice.
//
// Nothing here interprets a tool. Server tools are versioned per provider and
// grow options faster than a neutral representation can track them, so the
// options travel as an opaque object and only type and name are read.
package servertool

import (
	"encoding/json"
	"fmt"

	"latere.ai/x/pkg/llmdialect/ir"
)

// Encode renders t as the wire object a provider expects: type and name
// alongside whatever Config carried.
//
// Type and name come from the struct fields, never from Config, so a value
// that round-tripped through Decode cannot rename or retype the tool on the
// way back out.
func Encode(t ir.ServerTool) (map[string]any, error) {
	out := map[string]any{}
	if len(t.Config) > 0 {
		if err := json.Unmarshal(t.Config, &out); err != nil {
			return nil, fmt.Errorf("server tool %q config: %w", t.Type, err)
		}
	}
	out["type"] = t.Type
	if t.Name != "" {
		out["name"] = t.Name
	} else {
		delete(out, "name")
	}
	return out, nil
}

// Decode splits a wire tool object into a ServerTool: type and name are lifted
// out and everything else is kept, unread, as Config.
//
// Config is nil when nothing else remains, so a tool that takes no options
// encodes back to exactly the two fields it arrived with rather than an empty
// object.
func Decode(raw json.RawMessage) (ir.ServerTool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return ir.ServerTool{}, fmt.Errorf("server tool: %w", err)
	}

	var t ir.ServerTool
	if v, ok := fields["type"]; ok {
		if err := json.Unmarshal(v, &t.Type); err != nil {
			return ir.ServerTool{}, fmt.Errorf("server tool type: %w", err)
		}
		delete(fields, "type")
	}
	if v, ok := fields["name"]; ok {
		if err := json.Unmarshal(v, &t.Name); err != nil {
			return ir.ServerTool{}, fmt.Errorf("server tool name: %w", err)
		}
		delete(fields, "name")
	}
	if len(fields) > 0 {
		cfg, err := json.Marshal(fields)
		if err != nil {
			return ir.ServerTool{}, fmt.Errorf("server tool %q config: %w", t.Type, err)
		}
		t.Config = cfg
	}
	return t, nil
}
