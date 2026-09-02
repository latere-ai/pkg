// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openairesp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// TestLogProbsRequestRoundTrip: this dialect asks with two members, not
// one. include is what makes a response carry logprobs at all and
// top_logprobs only sizes the alternatives, so both have to survive.
func TestLogProbsRequestRoundTrip(t *testing.T) {
	req := decode(t, `{"model":"m","input":"hi","top_logprobs":3,
		"include":["message.output_text.logprobs"]}`)
	if !req.LogProbs || req.TopLogProbs != 3 {
		t.Fatalf("decoded %v/%d, want true/3", req.LogProbs, req.TopLogProbs)
	}
	if slices.Contains(req.Loss.Strings(), "include") {
		t.Fatalf("a served include entry is reported as a loss: %v", req.Loss.Strings())
	}
	raw, err := NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Include     []string `json:"include"`
		TopLogProbs int      `json:"top_logprobs"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(body.Include, []string{includeLogProbs}) || body.TopLogProbs != 3 {
		t.Fatalf("upstream body lost the request: %s", raw)
	}
}

// TestIncludeKeepsReportingWhatItCannotServe: the one entry this layer
// answers comes off the loss report, the rest stay on it.
func TestIncludeKeepsReportingWhatItCannotServe(t *testing.T) {
	req := decode(t, `{"model":"m","input":"hi",
		"include":["message.output_text.logprobs","reasoning.encrypted_content"]}`)
	if !req.LogProbs {
		t.Fatal("logprobs include was not honoured")
	}
	if !slices.Contains(req.Loss.Strings(), "include") {
		t.Fatalf("an unservable include entry vanished: %v", req.Loss.Strings())
	}
	// A malformed include is still a loss rather than an error.
	req = decode(t, `{"model":"m","input":"hi","include":"logprobs"}`)
	if !slices.Contains(req.Loss.Strings(), "include") {
		t.Fatalf("malformed include vanished: %v", req.Loss.Strings())
	}
}

// TestTopLogProbsAloneAsksForNothing is this dialect's own rule, and
// the difference from Chat Completions: the count without include
// reports nothing upstream, so it must not fabricate a request here.
func TestTopLogProbsAloneAsksForNothing(t *testing.T) {
	req := decode(t, `{"model":"m","input":"hi","top_logprobs":2}`)
	if req.LogProbs {
		t.Fatal("the count alone asked for logprobs")
	}
	raw, err := NewBackend().EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "top_logprobs") {
		t.Fatalf("a count that asks for nothing travelled upstream: %s", raw)
	}
}

func TestDecodeRequestRejectsNegativeTopLogProbs(t *testing.T) {
	_, err := NewFrontend().DecodeRequest([]byte(`{"model":"m","input":"hi","top_logprobs":-1}`))
	if err == nil || !strings.Contains(err.Error(), "count of alternatives") {
		t.Fatalf("err = %v", err)
	}
}

func sampleLogProbs() []ir.TokenLogProb {
	return []ir.TokenLogProb{{
		Token: "he", Bytes: []byte("he"), LogProb: ir.LogProb(-0.25),
		Top: []ir.TokenLogProb{{Token: "hi", Bytes: []byte("hi"), LogProb: ir.LogProb(-2.5)}},
	}, {
		Token: "y", Bytes: []byte("y"), LogProb: ir.LogProb(math.Inf(-1)),
	}}
}

// TestEncodeResponseServesLogProbs is the whole-body shape: the tokens
// hang off the output_text content part, with bytes, and a masked token
// is null rather than a failed encode.
func TestEncodeResponseServesLogProbs(t *testing.T) {
	raw, err := NewFrontend().EncodeResponse(&ir.Response{
		ID: "r1", Model: "m",
		Blocks:   []ir.Block{{Type: ir.BlockText, Text: "hey"}},
		LogProbs: sampleLogProbs(),
	})
	if err != nil {
		t.Fatalf("a masked token must not fail the encode: %v", err)
	}
	parts := outputTextParts(t, raw)
	if len(parts) != 1 || len(parts[0].LogProbs) != 2 {
		t.Fatalf("logprobs missing: %s", raw)
	}
	first := parts[0].LogProbs[0]
	if first.LogProb == nil || *first.LogProb != -0.25 {
		t.Fatalf("drawn token wrong: %s", raw)
	}
	if !reflect.DeepEqual(first.Bytes, []int{104, 101}) {
		t.Fatalf("bytes are not the integer array the content part declares: %s", raw)
	}
	if len(first.Top) != 1 || first.Top[0].Token != "hi" {
		t.Fatalf("alternatives wrong: %s", raw)
	}
	if parts[0].LogProbs[1].LogProb != nil {
		t.Fatalf("masked token did not encode as null: %s", raw)
	}
}

// TestEncodeResponseLogProbsEmptyWhenNotAsked: the member is required
// on this dialect's content part, so it is an empty array and not an
// absent key.
func TestEncodeResponseLogProbsEmptyWhenNotAsked(t *testing.T) {
	raw, err := NewFrontend().EncodeResponse(&ir.Response{ID: "r1", Model: "m",
		Blocks: []ir.Block{{Type: ir.BlockText, Text: "hey"}}})
	if err != nil {
		t.Fatal(err)
	}
	parts := outputTextParts(t, raw)
	if len(parts) != 1 || parts[0].LogProbs == nil || len(parts[0].LogProbs) != 0 {
		t.Fatalf("logprobs member = %v: %s", parts[0].LogProbs, raw)
	}
}

type wirePart struct {
	Type     string `json:"type"`
	LogProbs []struct {
		Token   string   `json:"token"`
		LogProb *float64 `json:"logprob"`
		Bytes   []int    `json:"bytes"`
		Top     []struct {
			Token string `json:"token"`
			Bytes []int  `json:"bytes"`
		} `json:"top_logprobs"`
	} `json:"logprobs"`
}

func outputTextParts(t *testing.T, raw []byte) []wirePart {
	t.Helper()
	var body struct {
		Output []struct {
			Type    string     `json:"type"`
			Content []wirePart `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	var out []wirePart
	for _, item := range body.Output {
		for _, p := range item.Content {
			if p.Type == "output_text" {
				out = append(out, p)
			}
		}
	}
	return out
}

// TestBackendDecodeResponseLogProbs is the upstream half.
func TestBackendDecodeResponseLogProbs(t *testing.T) {
	body := `{"id":"resp_1","model":"m","status":"completed","output":[
		{"type":"message","role":"assistant","content":[
			{"type":"output_text","text":"hey","logprobs":[
				{"token":"he","logprob":-0.25,"bytes":[104,101],
				 "top_logprobs":[{"token":"hi","logprob":-2.5,"bytes":[104,105]}]},
				{"token":"y","logprob":null,"bytes":[999]}
			]}]}]}`
	resp, err := NewBackend().DecodeResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.LogProbs) != 2 {
		t.Fatalf("logprobs = %+v", resp.LogProbs)
	}
	if resp.LogProbs[0].Token != "he" || string(resp.LogProbs[0].Bytes) != "he" {
		t.Fatalf("first token wrong: %+v", resp.LogProbs[0])
	}
	if len(resp.LogProbs[0].Top) != 1 || resp.LogProbs[0].Top[0].Token != "hi" {
		t.Fatalf("alternatives wrong: %+v", resp.LogProbs[0].Top)
	}
	if !math.IsInf(float64(resp.LogProbs[1].LogProb), -1) {
		t.Fatalf("null did not decode to -Inf: %v", resp.LogProbs[1].LogProb)
	}
	// 999 is not a UTF-8 byte, and a truncated one reconstructs wrong
	// text.
	if resp.LogProbs[1].Bytes != nil {
		t.Fatalf("out-of-range bytes decoded to %v", resp.LogProbs[1].Bytes)
	}
}

// TestStreamLogProbsSurviveTranslation pins the streaming shape, which
// differs from the whole-body one: the events carry no bytes member,
// and the .done event repeats the whole sequence the deltas reported.
func TestStreamLogProbsSurviveTranslation(t *testing.T) {
	upstream := "event: response.created\n" +
		`data: {"type":"response.created","response":{"id":"resp_1","model":"m"}}` + "\n\n" +
		"event: response.output_item.added\n" +
		`data: {"type":"response.output_item.added","item":{"type":"message"}}` + "\n\n" +
		"event: response.output_text.delta\n" +
		`data: {"type":"response.output_text.delta","delta":"he","logprobs":[` +
		`{"token":"he","logprob":-0.25,"top_logprobs":[{"token":"hi","logprob":-2.5}]}]}` + "\n\n" +
		"event: response.output_text.delta\n" +
		`data: {"type":"response.output_text.delta","delta":"y","logprobs":[{"token":"y","logprob":null}]}` + "\n\n" +
		"event: response.output_item.done\n" +
		`data: {"type":"response.output_item.done"}` + "\n\n" +
		"event: response.completed\n" +
		`data: {"type":"response.completed","response":{"id":"resp_1","status":"completed"}}` + "\n\n"

	dec := NewBackend().NewEventDecoder(strings.NewReader(upstream))
	var events []ir.Event
	for {
		ev, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	var deltas []ir.Event
	for _, ev := range events {
		if ev.Type == ir.EventTextDelta {
			deltas = append(deltas, ev)
		}
	}
	if len(deltas) != 2 || len(deltas[0].LogProbs) != 1 || deltas[0].LogProbs[0].Token != "he" {
		t.Fatalf("deltas lost their tokens: %+v", deltas)
	}
	if deltas[0].LogProbs[0].Bytes != nil {
		t.Fatalf("the streaming shape has no bytes member, got %v", deltas[0].LogProbs[0].Bytes)
	}
	if !math.IsInf(float64(deltas[1].LogProbs[0].LogProb), -1) {
		t.Fatalf("masked token decoded to %v", deltas[1].LogProbs[0].LogProb)
	}

	var buf bytes.Buffer
	enc := NewFrontend().NewEventEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatalf("re-encoding a masked token must not fail: %v", err)
		}
	}
	got := buf.String()
	if !strings.Contains(got, `"token":"he"`) || !strings.Contains(got, `"logprob":null`) {
		t.Fatalf("re-encoded stream lost the tokens: %s", got)
	}
	// The delta events carry no bytes member; the content part inside
	// the .done items does, which is the dialect's own asymmetry.
	if delta := frameData(t, got, "response.output_text.delta"); strings.Contains(delta, `"bytes"`) {
		t.Fatalf("a streaming event carries bytes: %s", delta)
	}
	// response.output_text.done repeats the whole sequence, so both
	// tokens appear in the frame that finalizes the text.
	done := frameData(t, got, "response.output_text.done")
	var doneEv struct {
		LogProbs []struct {
			Token string `json:"token"`
		} `json:"logprobs"`
	}
	if err := json.Unmarshal([]byte(done), &doneEv); err != nil {
		t.Fatal(err)
	}
	if len(doneEv.LogProbs) != 2 {
		t.Fatalf("done frame carries %d tokens, want 2: %s", len(doneEv.LogProbs), done)
	}
}

func frameData(t *testing.T, raw, name string) string {
	t.Helper()
	for _, ev := range readFrames(t, raw) {
		if ev.Name == name {
			return string(ev.Data)
		}
	}
	t.Fatalf("no %s frame in %s", name, raw)
	return ""
}
