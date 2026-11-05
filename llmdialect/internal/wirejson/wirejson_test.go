// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package wirejson

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"
)

func TestOutWritesNilAsNullAndSortsKeys(t *testing.T) {
	type payload struct {
		Tools []string       `json:"tools"`
		Meta  map[string]int `json:"meta"`
		Any   map[string]any `json:"any"`
	}
	got, err := json.Marshal(payload{Any: map[string]any{"b": 1, "a": 2}}, Out)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"tools":null,"meta":null,"any":{"a":2,"b":1}}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestOutKeepsForeignRawValues(t *testing.T) {
	raw := jsontext.Value("{\"a\":1,\"a\":2,\"s\":\"x\xffy\"}")
	got, err := json.Marshal(struct {
		Raw jsontext.Value `json:"raw"`
	}{raw}, Out)
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\"raw\":{\"a\":1,\"a\":2,\"s\":\"x�y\"}}"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestInAcceptsDuplicateNamesInvalidUTF8AndMixedCase(t *testing.T) {
	var v struct {
		Name string `json:"name"`
		Text string `json:"text"`
		Free string
	}
	in := "{\"name\":\"first\",\"NAME\":\"second\",\"text\":\"a\xffb\",\"free\":\"ok\"}"
	if err := json.Unmarshal([]byte(in), &v, In); err != nil {
		t.Fatal(err)
	}
	if v.Name != "second" || v.Text != "a�b" || v.Free != "ok" {
		t.Errorf("got %+v", v)
	}
	if err := json.Unmarshal([]byte(in), &v); err == nil {
		t.Error("the strict defaults accepted duplicate names")
	}
}
