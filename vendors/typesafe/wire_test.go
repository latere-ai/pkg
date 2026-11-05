// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package typesafe

import (
	"encoding/json/v2"
	"testing"
)

func TestChoiceWritesANilCriteriaAsNull(t *testing.T) {
	got, err := json.Marshal(Choice{})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"type":"choice","criteria":null}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestScoreWritesANilCriteriaAsNull(t *testing.T) {
	got, err := json.Marshal(Score{})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"type":"score","criteria":null}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestEncodeRequestSortsKeysAndWritesNullForNil(t *testing.T) {
	body, err := encodeRequest(&Request{
		State: map[string]any{"b": 1, "a": []string(nil)},
		Questions: map[string]Question{
			"q2": Choice{Criteria: map[string]any{"y": nil, "x": "d"}},
			"q1": Noul{Instructions: "?"},
		},
	}, "jev-latest")
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"state":{"a":null,"b":1},"model":"jev-latest","questions":{"q1":{"type":"noul","instructions":"?"},"q2":{"type":"choice","criteria":{"x":"d","y":null}}}}`
	if string(body) != want {
		t.Errorf("got  %s\nwant %s", body, want)
	}
}

func TestResponseDecodingAcceptsDuplicateNamesAndMixedCase(t *testing.T) {
	var r Response
	in := `{"MODEL":"m","model":"m2","answers":{"q":{"type":"noul","noul":0.25,"noul":0.5}}}`
	if err := json.Unmarshal([]byte(in), &r, foreignJSON); err != nil {
		t.Fatal(err)
	}
	a, err := r.Answers.Noul("q")
	if err != nil || r.Model != "m2" || a.Noul != 0.5 {
		t.Errorf("got %+v %+v %v", r, a, err)
	}
}
