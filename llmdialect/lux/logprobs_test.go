// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package lux

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

func sampleLogProbs() []ir.TokenLogProb {
	return []ir.TokenLogProb{{
		Token: "he", Bytes: []byte("he"), LogProb: ir.LogProb(-0.25),
		Top: []ir.TokenLogProb{{Token: "hi", Bytes: []byte("hi"), LogProb: ir.LogProb(-2.5)}},
	}, {
		Token: "y", Bytes: []byte("y"), LogProb: ir.LogProb(math.Inf(-1)),
	}}
}

// TestLogProbsRoundTripLossless is the property this dialect exists to
// have: the lux wire is the IR, so what goes in comes back unchanged,
// masked token included.
func TestLogProbsRoundTripLossless(t *testing.T) {
	in := &ir.Request{
		Model:       "m",
		Messages:    []ir.Message{{Role: ir.RoleUser, Blocks: []ir.Block{{Type: ir.BlockText, Text: "hi"}}}},
		LogProbs:    true,
		TopLogProbs: 3,
	}
	body, err := NewBackend().EncodeRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	back, err := NewFrontend().DecodeRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !back.LogProbs || back.TopLogProbs != 3 {
		t.Fatalf("request round trip lost the ask: %v/%d", back.LogProbs, back.TopLogProbs)
	}
	if len(back.Loss.Strings()) != 0 {
		t.Fatalf("a lux-fronted request reported loss: %v", back.Loss.Strings())
	}

	resp := &ir.Response{ID: "r1", Model: "m", StopReason: ir.StopEndTurn,
		Blocks: []ir.Block{{Type: ir.BlockText, Text: "hey"}}, LogProbs: sampleLogProbs()}
	raw, err := NewFrontend().EncodeResponse(resp)
	if err != nil {
		t.Fatalf("a masked token must not fail the encode: %v", err)
	}
	if !strings.Contains(string(raw), `"logprob":null`) {
		t.Fatalf("masked token did not encode as null: %s", raw)
	}
	// Bytes travel as the base64 string Go gives a []byte.
	if !strings.Contains(string(raw), `"bytes":"aGU="`) {
		t.Fatalf("bytes are not base64: %s", raw)
	}
	got, err := NewBackend().DecodeResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.LogProbs, resp.LogProbs) {
		t.Fatalf("round trip changed the tokens:\n got %+v\nwant %+v", got.LogProbs, resp.LogProbs)
	}
}

// TestEventLogProbsRoundTrip carries the streaming half through the
// same wire.
func TestEventLogProbsRoundTrip(t *testing.T) {
	in := ir.Event{Type: ir.EventTextDelta, Index: 0, Delta: "hey", LogProbs: sampleLogProbs()}
	wire, err := EventFromIR(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("a masked token must not fail the encode: %v", err)
	}
	var back Event
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	out, err := eventToIR(back)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.LogProbs, in.LogProbs) {
		t.Fatalf("round trip changed the tokens:\n got %+v\nwant %+v", out.LogProbs, in.LogProbs)
	}
}

// TestLogProbsAreCopiedNotAliased: the wire struct and the IR must
// never share backing memory, or a mutation on one side reaches the
// other.
func TestLogProbsAreCopiedNotAliased(t *testing.T) {
	in := sampleLogProbs()
	wire := logProbsFromIR(in)
	wire[0].Bytes[0] = 'X'
	wire[0].Top[0].Token = "changed"
	if in[0].Bytes[0] != 'h' || in[0].Top[0].Token != "hi" {
		t.Fatalf("the wire struct aliases the IR: %+v", in[0])
	}
	back := logProbsToIR(wire)
	back[0].Bytes[0] = 'Z'
	if wire[0].Bytes[0] != 'X' {
		t.Fatalf("the IR aliases the wire struct: %+v", wire[0])
	}
}

func TestDecodeRequestRejectsNegativeTopLogProbs(t *testing.T) {
	_, err := NewFrontend().DecodeRequest([]byte(
		`{"model":"m","messages":[{"role":"user","blocks":[{"type":"text","text":"x"}]}],"top_logprobs":-1}`))
	if err == nil || !strings.Contains(err.Error(), "count of alternatives") {
		t.Fatalf("err = %v", err)
	}
}
