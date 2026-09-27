// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"strings"
	"testing"
	"time"
)

// TestModelDefaults: every field but Name has the default the wire
// writes for a model without that datum, and a set field is written.
func TestModelDefaults(t *testing.T) {
	bare := Model{Name: "m"}
	if got := string(ModelEntry(WireOpenAI, bare)); got != `{"id":"m","object":"model","created":0,"owned_by":"owner"}`+"\n" {
		t.Errorf("openai defaults %s", got)
	}
	if got := string(ModelEntry(WireAnthropic, bare)); got != `{"type":"model","id":"m","display_name":"m","created_at":"1970-01-01T00:00:00Z"}`+"\n" {
		t.Errorf("anthropic defaults %s", got)
	}
	if got := string(ModelEntry(WireGoogle, bare)); got != `{"name":"models/m","displayName":"m","supportedGenerationMethods":["generateContent","countTokens"]}`+"\n" {
		t.Errorf("google defaults %s", got)
	}
	full := Model{Name: "m", DisplayName: "Model M", OwnedBy: "acme", Created: time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600)), Methods: []string{"generateContent"}}
	if got := string(ModelEntry(WireLux, full)); got != `{"id":"m","object":"model","created":1767319445,"owned_by":"acme"}`+"\n" {
		t.Errorf("openai set %s", got)
	}
	if got := string(ModelEntry(WireAnthropic, full)); got != `{"type":"model","id":"m","display_name":"Model M","created_at":"2026-01-02T02:04:05Z"}`+"\n" {
		t.Errorf("anthropic set %s", got)
	}
	if got := string(ModelEntry(WireGoogle, full)); got != `{"name":"models/m","displayName":"Model M","supportedGenerationMethods":["generateContent"]}`+"\n" {
		t.Errorf("google set %s", got)
	}
	// An explicitly empty method list is written as empty, not defaulted.
	if got := string(ModelEntry(WireGoogle, Model{Name: "m", Methods: []string{}})); got != `{"name":"models/m","displayName":"m","supportedGenerationMethods":[]}`+"\n" {
		t.Errorf("google empty methods %s", got)
	}
	// Lists in the order given, with the anthropic ids from the ends.
	if got := string(ModelList(WireAnthropic, []Model{{Name: "b"}, {Name: "a"}})); got != `{"data":[{"type":"model","id":"b","display_name":"b","created_at":"1970-01-01T00:00:00Z"},{"type":"model","id":"a","display_name":"a","created_at":"1970-01-01T00:00:00Z"}],"has_more":false,"first_id":"b","last_id":"a"}`+"\n" {
		t.Errorf("anthropic order %s", got)
	}
	if got := string(ModelList(WireGoogle, nil)); got != `{"models":[]}`+"\n" {
		t.Errorf("empty google list %s", got)
	}
	if got := string(ModelList(WireOpenAI, nil)); got != `{"object":"list","data":[]}`+"\n" {
		t.Errorf("empty openai list %s", got)
	}
}

// TestModelFigures: each wire writes the figures after the members its
// clients read, in the members Model documents for it, with every price
// per 1,000,000 tokens and per written; a figure left zero, and a price
// left empty, has no member; the Google shape has no modalities or
// prices; a list carries each entry as the entry renders it.
func TestModelFigures(t *testing.T) {
	m := Model{Name: "m", ContextWindow: 400000, MaxOutputTokens: 128000, InputModalities: []string{"text", "image"},
		Pricing: &ModelPricing{Currency: "USD", Input: "1.25", Output: "10", CachedInput: "0.125", CacheWrite: "1.25"}}
	const snake = `"pricing":{"currency":"USD","per":1000000,"input":"1.25","output":"10","cached_input":"0.125","cache_write":"1.25"}`
	want := map[Wire]string{
		WireOpenAI: `{"id":"m","object":"model","created":0,"owned_by":"owner",` +
			`"context_window":400000,"max_output_tokens":128000,"input_modalities":["text","image"],` + snake + `}`,
		WireAnthropic: `{"type":"model","id":"m","display_name":"m","created_at":"1970-01-01T00:00:00Z",` +
			`"max_input_tokens":400000,"max_tokens":128000,"input_modalities":["text","image"],` + snake + `}`,
		WireGoogle: `{"name":"models/m","displayName":"m","supportedGenerationMethods":["generateContent","countTokens"],` +
			`"inputTokenLimit":400000,"outputTokenLimit":128000}`,
		WireLux: `{"id":"m","object":"model","created":0,"owned_by":"owner",` +
			`"contextWindow":400000,"maxOutputTokens":128000,"modalities":{"input":["text","image"]},` +
			`"pricing":{"currency":"USD","per":1000000,"input":"1.25","output":"10","cachedInput":"0.125","cacheWrite":"1.25"}}`,
	}
	for w, entry := range want {
		if got := string(ModelEntry(w, m)); got != entry+"\n" {
			t.Errorf("%s entry:\n got %s\nwant %s", w, got, entry)
		}
		if got := string(ModelList(w, []Model{m})); !strings.Contains(got, entry) {
			t.Errorf("%s list does not carry the entry: %s", w, got)
		}
	}
	partial := Model{Name: "m", ContextWindow: 8192, Pricing: &ModelPricing{Input: "1", Output: "2"}}
	for w, entry := range map[Wire]string{
		WireOpenAI: `{"id":"m","object":"model","created":0,"owned_by":"owner","context_window":8192,"pricing":{"per":1000000,"input":"1","output":"2"}}`,
		WireLux:    `{"id":"m","object":"model","created":0,"owned_by":"owner","contextWindow":8192,"pricing":{"per":1000000,"input":"1","output":"2"}}`,
		WireGoogle: `{"name":"models/m","displayName":"m","supportedGenerationMethods":["generateContent","countTokens"],"inputTokenLimit":8192}`,
	} {
		if got := string(ModelEntry(w, partial)); got != entry+"\n" {
			t.Errorf("%s partial:\n got %s\nwant %s", w, got, entry)
		}
	}
}

// TestMarshalPanicsOnABug: a value that cannot marshal is a bug in this
// package, not a shape any wire writes, and marshal says so.
func TestMarshalPanicsOnABug(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "does not marshal") {
			t.Errorf("recovered %v", r)
		}
	}()
	marshal(make(chan int))
}
