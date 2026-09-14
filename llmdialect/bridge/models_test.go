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
