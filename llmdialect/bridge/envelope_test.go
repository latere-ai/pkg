// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// The wires and the file each one's goldens are named for: the copied
// goldens keep the names they had.
var wireFiles = map[Wire]string{WireOpenAI: "openai", WireAnthropic: "anthropic", WireGoogle: "gemini", WireLux: "lux"}

// The failure every envelope golden renders: a code, its sentence, a
// developer detail, a request id, the status, and the domain.
var goldenFailure = Failure{
	Code: "model_not_found", Message: "There is no model of that name.", Detail: `no Model named "x"`,
	RequestID: "req_01TEST", Status: 404, Domain: "lux",
}

// TestGoldenShapes: Envelope, ErrorFrame, ModelList, ModelEntry, and
// CountBody render the golden bytes for every wire.
func TestGoldenShapes(t *testing.T) {
	names := []string{"alias", "claude", "claude-3", "dual", "gemini", "gemini-only", "gpt", "gpt-4.1", "luxm", "multi", "never", "priced", "reasoner"}
	var models []Model
	for _, n := range names {
		models = append(models, Model{Name: n, OwnedBy: "lux"})
	}
	frameFailure := Failure{Code: "upstream_error", Message: "The provider returned an error.", Detail: "cut", RequestID: "req_1", Status: 502, Domain: "lux"}
	for w, file := range wireFiles {
		if got, want := Envelope(w, goldenFailure), fixture(t, "envelopes/"+file+".golden.json"); !bytes.Equal(got, want) {
			t.Errorf("%s envelope:\n got %s\nwant %s", w, got, want)
		}
		if got, want := ModelList(w, models), fixture(t, "models/"+file+".golden.json"); !bytes.Equal(got, want) {
			t.Errorf("%s list:\n got %s\nwant %s", w, got, want)
		}
		if got, want := ModelEntry(w, Model{Name: "gpt", OwnedBy: "lux"}), fixture(t, "entries/"+file+".golden.json"); !bytes.Equal(got, want) {
			t.Errorf("%s entry:\n got %s\nwant %s", w, got, want)
		}
		frame := ErrorFrame(w, frameFailure)
		if w == WireGoogle {
			if frame != nil {
				t.Errorf("google frame %q", frame)
			}
		} else if want := fixture(t, "frames/"+file+".golden.sse"); !bytes.Equal(frame, want) {
			t.Errorf("%s frame:\n got %q\nwant %q", w, frame, want)
		}
	}
	if got, want := Envelope(WireLux, Failure{Code: "not_found", Message: "There is no such object.", RequestID: "req_01TEST"}), fixture(t, "envelopes/lux-nodetail.golden.json"); !bytes.Equal(got, want) {
		t.Errorf("lux envelope without a detail:\n got %s\nwant %s", got, want)
	}
	if got, want := ModelList(WireAnthropic, nil), fixture(t, "models/anthropic-empty.golden.json"); !bytes.Equal(got, want) {
		t.Errorf("empty anthropic list:\n got %s\nwant %s", got, want)
	}
	for _, w := range []Wire{WireAnthropic, WireLux} {
		if got, want := CountBody(w, 123), fixture(t, "counts/"+wireFiles[w]+".golden.json"); !bytes.Equal(got, want) {
			t.Errorf("%s count:\n got %s\nwant %s", w, got, want)
		}
	}
	if got := CountBody(WireGoogle, 123); string(got) != "{\"totalTokens\":123}\n" {
		t.Errorf("google count %s", got)
	}
	if CountBody(WireOpenAI, 1) != nil || CountBody("", 1) != nil {
		t.Error("a count body for a wire with no count route")
	}
	// The developer detail is in the lux body and nowhere else.
	for _, w := range []Wire{WireOpenAI, WireAnthropic, WireGoogle} {
		if bytes.Contains(Envelope(w, goldenFailure), []byte(goldenFailure.Detail)) {
			t.Errorf("%s envelope carries the developer detail", w)
		}
	}
	if Envelope("", goldenFailure) != nil || ErrorFrame("", goldenFailure) != nil || ModelList("", models) != nil || ModelEntry("", models[0]) != nil {
		t.Error("a shape for a wire that is none")
	}
}

// TestEnvelopeDetails: the lux shape merges Details under the named
// members, omits details when there are none, and falls back to code
// and message when a detail value cannot be marshaled; the Google shape
// omits an empty domain.
func TestEnvelopeDetails(t *testing.T) {
	got := Envelope(WireLux, Failure{Code: "c", Message: "M.", RequestID: "r", Detail: "d", Details: map[string]any{"retry_after": 2, "request_id": "overridden"}})
	if string(got) != `{"error":{"code":"c","message":"M.","details":{"detail":"d","request_id":"r","retry_after":2}}}`+"\n" {
		t.Errorf("merged details %s", got)
	}
	if got := Envelope(WireLux, Failure{Code: "c", Message: "M."}); string(got) != `{"error":{"code":"c","message":"M."}}`+"\n" {
		t.Errorf("no details %s", got)
	}
	if got := Envelope(WireLux, Failure{Code: "c", Message: "M.", Details: map[string]any{"ch": make(chan int)}}); string(got) != `{"error":{"code":"c","message":"M."}}`+"\n" {
		t.Errorf("unmarshalable detail %s", got)
	}
	if got := Envelope(WireGoogle, Failure{Code: "c", Message: "M.", Status: 429}); strings.Contains(string(got), "domain") || !strings.Contains(string(got), `"status":"RESOURCE_EXHAUSTED"`) {
		t.Errorf("google without a domain %s", got)
	}
}

// TestEnvelopeRoundTrip: ParseEnvelope reads back what Envelope wrote
// on every wire, and reports false for a body of another shape or none.
func TestEnvelopeRoundTrip(t *testing.T) {
	f := Failure{Code: "rate_limited", Message: "Too many requests; wait and retry.", Detail: "bucket empty", RequestID: "req_9", Status: 429, Domain: "lux", Details: map[string]any{"retry_after": "2"}}
	for w := range wireFiles {
		got, ok := ParseEnvelope(w, Envelope(w, f))
		if !ok || got.Code != f.Code || got.Message != f.Message {
			t.Errorf("%s: %+v %v", w, got, ok)
		}
		switch w {
		case WireAnthropic:
			if got.RequestID != f.RequestID {
				t.Errorf("anthropic request id %q", got.RequestID)
			}
		case WireLux:
			if got.RequestID != f.RequestID || got.Detail != f.Detail || got.Details["retry_after"] != "2" || len(got.Details) != 1 {
				t.Errorf("lux %+v", got)
			}
		case WireGoogle:
			if got.Status != f.Status || got.Domain != f.Domain {
				t.Errorf("google %+v", got)
			}
		}
	}
	// A lux body with no details, and one whose details are only the two
	// named members, leave Details nil.
	if got, ok := ParseEnvelope(WireLux, Envelope(WireLux, Failure{Code: "c", RequestID: "r"})); !ok || got.Details != nil || got.RequestID != "r" {
		t.Errorf("lux named-only details %+v %v", got, ok)
	}
	// The OpenAI shape reads type when code is null, as the API writes
	// some errors.
	if got, ok := ParseEnvelope(WireOpenAI, []byte(`{"error":{"message":"m","type":"invalid_request_error","code":null,"param":null}}`)); !ok || got.Code != "invalid_request_error" {
		t.Errorf("openai null code %+v %v", got, ok)
	}
	// Another shape, or no shape at all, is false.
	cases := []struct {
		w    Wire
		body string
	}{
		{WireOpenAI, string(Envelope(WireGoogle, f))},
		{WireOpenAI, `{"error":{"code":"x"}}`},
		{WireOpenAI, `{"error":{"message":"m","code":5}}`},
		{WireAnthropic, string(Envelope(WireOpenAI, f))},
		{WireAnthropic, `{"type":"error"}`},
		{WireGoogle, string(Envelope(WireOpenAI, f))},
		{WireGoogle, `{"error":{"message":"m"}}`},
		{WireLux, string(Envelope(WireGoogle, f))},
		{WireLux, `{"error":{"message":"m"}}`},
		{WireLux, `{"error":{"code":"c","details":"not an object"}}`},
		{WireOpenAI, `not json`},
		{WireAnthropic, `[]`},
		{WireGoogle, `null`},
		{WireLux, `{}`},
		{"", string(Envelope(WireLux, f))},
	}
	for _, c := range cases {
		if got, ok := ParseEnvelope(c.w, []byte(c.body)); ok {
			t.Errorf("%s accepted %s as %+v", c.w, c.body, got)
		}
	}
}

func TestGoogleStatusNames(t *testing.T) {
	cases := map[int]string{
		400: "INVALID_ARGUMENT", 401: "UNAUTHENTICATED", 403: "PERMISSION_DENIED", 404: "NOT_FOUND",
		413: "INVALID_ARGUMENT", 429: "RESOURCE_EXHAUSTED", 502: "UNAVAILABLE", 503: "UNAVAILABLE",
		504: "DEADLINE_EXCEEDED", 500: "INTERNAL", 0: "INTERNAL",
	}
	for status, want := range cases {
		if got := GoogleStatus(status); got != want {
			t.Errorf("GoogleStatus(%d) = %s, want %s", status, got, want)
		}
	}
}

func FuzzParseEnvelope(f *testing.F) {
	for w := range wireFiles {
		f.Add(string(w), Envelope(w, goldenFailure))
	}
	f.Add("openai", []byte(`{"error":{"message":"m","code":null}}`))
	f.Add("lux", []byte(`{"error":{"code":"c","details":{"request_id":1}}}`))
	f.Fuzz(func(t *testing.T, wire string, body []byte) {
		got, ok := ParseEnvelope(Wire(wire), body)
		if !ok && (got.Code != "" || got.Message != "" || got.Detail != "" || got.RequestID != "" || got.Status != 0 || got.Domain != "" || got.Details != nil) {
			t.Fatalf("a failure with ok false: %+v", got)
		}
		if ok && !json.Valid(body) {
			t.Fatal("ok on invalid JSON")
		}
	})
}

func FuzzEnvelopeRoundTrip(f *testing.F) {
	f.Add("model_not_found", "There is no model of that name.", "req_1", "detail", 404, "lux")
	f.Add("", "", "", "", 0, "")
	f.Add("c\"quote", "m\nnewline", "r<>&", "d\\", 999, "d")
	f.Fuzz(func(t *testing.T, code, message, requestID, detail string, status int, domain string) {
		for _, s := range []string{code, message, requestID, detail, domain} {
			if !utf8.ValidString(s) {
				t.Skip("JSON replaces invalid UTF-8")
			}
		}
		in := Failure{Code: code, Message: message, RequestID: requestID, Detail: detail, Status: status, Domain: domain}
		for w := range wireFiles {
			body := Envelope(w, in)
			if !json.Valid(body) {
				t.Fatalf("%s: invalid JSON %s", w, body)
			}
			got, ok := ParseEnvelope(w, body)
			if !ok || got.Code != in.Code || got.Message != in.Message {
				t.Fatalf("%s: %+v %v from %s", w, got, ok, body)
			}
			if (w == WireAnthropic || w == WireLux) && got.RequestID != in.RequestID {
				t.Fatalf("%s: request id %q", w, got.RequestID)
			}
			if w == WireLux && got.Detail != in.Detail {
				t.Fatalf("lux: detail %q", got.Detail)
			}
			if w == WireGoogle && (got.Status != in.Status || got.Domain != in.Domain) {
				t.Fatalf("google: %+v", got)
			}
			if frame := ErrorFrame(w, in); w != WireGoogle && !bytes.HasSuffix(frame, []byte("\n\n")) {
				t.Fatalf("%s: frame %q", w, frame)
			}
		}
	})
}
