// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openaichat

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// TestLogProbsRequestRoundTrip: the flag a caller sends reaches the
// upstream body. Before the IR carried it, `logprobs` was an unknown
// top-level field and landed in the loss report instead.
func TestLogProbsRequestRoundTrip(t *testing.T) {
	req := decodeFront(t, `{"model":"m","messages":[{"role":"user","content":"x"}],
		"logprobs":true,"top_logprobs":3}`)
	if !req.LogProbs || req.TopLogProbs != 3 {
		t.Fatalf("decoded %v/%d, want true/3", req.LogProbs, req.TopLogProbs)
	}
	for _, f := range req.Loss.Strings() {
		if f == "logprobs" || f == "top_logprobs" {
			t.Fatalf("a served field is reported as a loss: %v", req.Loss.Strings())
		}
	}
	raw, err := NewBackend(BackendOptions{}).EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["logprobs"] != true || body["top_logprobs"] != float64(3) {
		t.Fatalf("upstream body lost the request: %s", raw)
	}
}

// TestTopLogProbsAloneAsksForBoth mirrors what every OpenAI client
// means by the count: alternatives to a number the response omits is
// not an answer.
func TestTopLogProbsAloneAsksForBoth(t *testing.T) {
	req := decodeFront(t, `{"model":"m","messages":[{"role":"user","content":"x"}],"top_logprobs":2}`)
	if !req.LogProbs || req.TopLogProbs != 2 {
		t.Fatalf("decoded %v/%d, want true/2", req.LogProbs, req.TopLogProbs)
	}
}

// TestLogProbsWithoutCountOmitsTopLogProbs keeps the upstream body
// legal: top_logprobs:0 is a request for zero alternatives, which is
// not the same as omitting the member, but sending it without
// logprobs:true is a 400.
func TestLogProbsWithoutCountOmitsTopLogProbs(t *testing.T) {
	raw, err := NewBackend(BackendOptions{}).EncodeRequest(&ir.Request{Model: "m", LogProbs: true})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["logprobs"] != true {
		t.Fatalf("logprobs missing: %s", raw)
	}
	if _, ok := body["top_logprobs"]; ok {
		t.Fatalf("top_logprobs sent without a count: %s", raw)
	}
	// And a count with no flag never travels alone.
	raw, err = NewBackend(BackendOptions{}).EncodeRequest(&ir.Request{Model: "m", TopLogProbs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "top_logprobs") {
		t.Fatalf("top_logprobs travelled without logprobs: %s", raw)
	}
}

func TestDecodeRequestRejectsNegativeTopLogProbs(t *testing.T) {
	_, err := NewFrontend().DecodeRequest([]byte(
		`{"model":"m","messages":[{"role":"user","content":"x"}],"top_logprobs":-1}`))
	if err == nil || !strings.Contains(err.Error(), "count of alternatives") {
		t.Fatalf("err = %v", err)
	}
}

// sampleLogProbs is one masked token and one drawn token with an
// alternative, which is every case the encoder has to get right.
func sampleLogProbs() []ir.TokenLogProb {
	return []ir.TokenLogProb{{
		Token: "hel", Bytes: []byte("hel"), LogProb: ir.LogProb(-0.25),
		Top: []ir.TokenLogProb{
			{Token: "hel", Bytes: []byte("hel"), LogProb: ir.LogProb(-0.25)},
			{Token: "hey", Bytes: []byte("hey"), LogProb: ir.LogProb(math.Inf(-1))},
		},
	}, {
		Token: "lo", Bytes: []byte("lo"), LogProb: ir.LogProb(math.Inf(-1)),
	}}
}

// TestEncodeResponseServesLogProbs is the whole-body half of the shape,
// including the two things JSON cannot express on its own: -Inf, which
// encoding/json refuses outright, and a byte array, which it would
// render as base64.
func TestEncodeResponseServesLogProbs(t *testing.T) {
	raw, err := NewFrontend().EncodeResponse(&ir.Response{
		ID: "r1", Model: "m",
		Blocks:   []ir.Block{{Type: ir.BlockText, Text: "hello"}},
		LogProbs: sampleLogProbs(),
	})
	if err != nil {
		t.Fatalf("a masked token must not fail the encode: %v", err)
	}
	var body struct {
		Choices []struct {
			LogProbs *struct {
				Content []struct {
					Token   string   `json:"token"`
					LogProb *float64 `json:"logprob"`
					Bytes   []int    `json:"bytes"`
					Top     []struct {
						Token string          `json:"token"`
						Top   json.RawMessage `json:"top_logprobs"`
					} `json:"top_logprobs"`
				} `json:"content"`
				Refusal json.RawMessage `json:"refusal"`
			} `json:"logprobs"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	lp := body.Choices[0].LogProbs
	if lp == nil || len(lp.Content) != 2 {
		t.Fatalf("logprobs missing: %s", raw)
	}
	if lp.Content[0].LogProb == nil || *lp.Content[0].LogProb != -0.25 {
		t.Fatalf("drawn token wrong: %s", raw)
	}
	if !reflect.DeepEqual(lp.Content[0].Bytes, []int{104, 101, 108}) {
		t.Fatalf("bytes are not the integer array this dialect declares: %s", raw)
	}
	// A token the policy masked could not have been drawn; null is what
	// that means, and a floor value is a number a consumer averages.
	if lp.Content[1].LogProb != nil {
		t.Fatalf("masked token did not encode as null: %s", raw)
	}
	if len(lp.Content[0].Top) != 2 {
		t.Fatalf("alternatives wrong: %s", raw)
	}
	if lp.Content[0].Top[0].Top != nil {
		t.Fatalf("an alternative carries alternatives of its own: %s", raw)
	}
	if string(lp.Refusal) != "null" {
		t.Fatalf("refusal member wrong: %s", raw)
	}
}

// TestEncodeResponseLogProbsNullWhenNotAsked pins the member a caller
// reads to tell "not asked" from "asked and empty".
func TestEncodeResponseLogProbsNullWhenNotAsked(t *testing.T) {
	raw, err := NewFrontend().EncodeResponse(&ir.Response{ID: "r1", Model: "m",
		Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Choices []map[string]json.RawMessage `json:"choices"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if got, ok := body.Choices[0]["logprobs"]; !ok || string(got) != "null" {
		t.Fatalf("logprobs member = %s, present = %v", got, ok)
	}
}

// TestBackendDecodeResponseLogProbs is the upstream half: what an
// OpenAI-compatible runtime answers has to come back into the IR, null
// included.
func TestBackendDecodeResponseLogProbs(t *testing.T) {
	body := `{"id":"r1","model":"m","choices":[{"message":{"content":"hel"},"finish_reason":"stop",
		"logprobs":{"content":[
			{"token":"hel","logprob":-0.25,"bytes":[104,101,108],
			 "top_logprobs":[{"token":"hey","logprob":-2.5,"bytes":[104,101,121]}]},
			{"token":"lo","logprob":null,"bytes":null,"top_logprobs":[]}
		],"refusal":null}}]}`
	resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.LogProbs) != 2 {
		t.Fatalf("logprobs = %+v", resp.LogProbs)
	}
	first := resp.LogProbs[0]
	if first.Token != "hel" || first.LogProb != ir.LogProb(-0.25) || string(first.Bytes) != "hel" {
		t.Fatalf("first token wrong: %+v", first)
	}
	if len(first.Top) != 1 || first.Top[0].Token != "hey" {
		t.Fatalf("alternatives wrong: %+v", first.Top)
	}
	if !math.IsInf(float64(resp.LogProbs[1].LogProb), -1) {
		t.Fatalf("null did not decode to -Inf: %v", resp.LogProbs[1].LogProb)
	}
	if resp.LogProbs[1].Bytes != nil {
		t.Fatalf("null bytes decoded to %v", resp.LogProbs[1].Bytes)
	}
}

// TestBackendDecodeResponseRejectsNonByteValues: a value outside a byte
// is not a UTF-8 byte, and truncating it would reconstruct wrong text.
func TestBackendDecodeResponseRejectsNonByteValues(t *testing.T) {
	body := `{"id":"r1","model":"m","choices":[{"message":{"content":"x"},"finish_reason":"stop",
		"logprobs":{"content":[{"token":"x","logprob":-1,"bytes":[999],"top_logprobs":[]}]}}]}`
	resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.LogProbs[0].Bytes != nil {
		t.Fatalf("bytes = %v, want nil", resp.LogProbs[0].Bytes)
	}
}

// TestStreamLogProbsSurviveTranslation is the streaming half end to
// end: an upstream chunk carrying logprobs, decoded to IR and
// re-encoded, still carries them, and a masked token is still null.
func TestStreamLogProbsSurviveTranslation(t *testing.T) {
	upstream := "data: " + `{"id":"c1","model":"m","choices":[{"index":0,"delta":{"content":"hel"},` +
		`"logprobs":{"content":[{"token":"hel","logprob":-0.25,"bytes":[104,101,108],` +
		`"top_logprobs":[{"token":"hey","logprob":-2.5,"bytes":[104,101,121]}]}]}}]}` + "\n\n" +
		"data: " + `{"id":"c1","model":"m","choices":[{"index":0,"delta":{"content":"lo"},` +
		`"logprobs":{"content":[{"token":"lo","logprob":null,"bytes":null,"top_logprobs":[]}]}}]}` + "\n\n" +
		"data: [DONE]\n\n"

	dec := NewBackend(BackendOptions{}).NewEventDecoder(strings.NewReader(upstream))
	var deltas []ir.Event
	for {
		ev, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if ev.Type == ir.EventTextDelta {
			deltas = append(deltas, ev)
		}
	}
	if len(deltas) != 2 {
		t.Fatalf("got %d text deltas", len(deltas))
	}
	if len(deltas[0].LogProbs) != 1 || deltas[0].LogProbs[0].Token != "hel" {
		t.Fatalf("first delta lost its tokens: %+v", deltas[0].LogProbs)
	}
	if !math.IsInf(float64(deltas[1].LogProbs[0].LogProb), -1) {
		t.Fatalf("masked token decoded to %v", deltas[1].LogProbs[0].LogProb)
	}

	var out strings.Builder
	enc := NewFrontend().NewEventEncoder(&out)
	for _, ev := range deltas {
		if err := enc.Encode(ev); err != nil {
			t.Fatalf("re-encoding a masked token must not fail: %v", err)
		}
	}
	got := out.String()
	if !strings.Contains(got, `"bytes":[104,101,108]`) {
		t.Fatalf("re-encoded stream lost the bytes: %s", got)
	}
	if !strings.Contains(got, `"logprob":null`) {
		t.Fatalf("re-encoded stream lost the masked token: %s", got)
	}
}

// TestStreamChunksAlwaysCarryTheLogProbsMember: the dialect writes
// `logprobs: null` on every chunk of a request that did not ask.
func TestStreamChunksAlwaysCarryTheLogProbsMember(t *testing.T) {
	var out strings.Builder
	enc := NewFrontend().NewEventEncoder(&out)
	for _, ev := range []ir.Event{
		{Type: ir.EventMessageStart, ID: "c1", Model: "m"},
		{Type: ir.EventBlockStart, Block: &ir.Block{Type: ir.BlockText}},
		{Type: ir.EventTextDelta, Delta: "hi"},
	} {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(out.String(), `"logprobs":null`); n != 2 {
		t.Fatalf("logprobs member on %d chunks, want 2: %s", n, out.String())
	}
}
