// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"errors"
	"testing"

	"latere.ai/x/pkg/llmdialect"
	"latere.ai/x/pkg/llmdialect/ir"
)

// TestCountTokens: the estimate over the decoded request for every wire
// with a frontend, always estimated; DecodeRequest for a body the
// frontend refuses, Unsupported for WireGoogle.
func TestCountTokens(t *testing.T) {
	cases := []struct {
		w    Wire
		body string
	}{
		{WireOpenAI, string(fixture(t, "fixtures/openai-chat.request.json"))},
		{WireAnthropic, string(fixture(t, "fixtures/anthropic-messages.request.json"))},
		{WireLux, string(fixture(t, "fixtures/lux.request.json"))},
	}
	for _, c := range cases {
		n, estimated, err := CountTokens(c.w, []byte(c.body))
		if err != nil || !estimated || n <= 0 {
			t.Errorf("%s: %d %v %v", c.w, n, estimated, err)
		}
		_, _, err = CountTokens(c.w, []byte(`{"model":"gpt"}`))
		var e *Error
		if !errors.As(err, &e) || e.Code != DecodeRequest || e.Scope == llmdialect.ScopeNone {
			t.Errorf("%s undecodable: %v", c.w, err)
		}
	}
	// A longer prompt estimates more.
	short, _, _ := CountTokens(WireAnthropic, []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`))
	long, _, _ := CountTokens(WireAnthropic, []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"hello there, this is a much longer prompt with many more words in it"}]}`))
	if long <= short {
		t.Errorf("estimates %d and %d are not ordered by length", short, long)
	}
	for _, w := range []Wire{WireGoogle, ""} {
		_, estimated, err := CountTokens(w, []byte(`{}`))
		var e *Error
		if !errors.As(err, &e) || e.Code != Unsupported || estimated {
			t.Errorf("%q: %v", w, err)
		}
	}
}

// TestCountTokensFor counts a body by its own dialect: a Responses body
// that CountTokens's Chat codec refuses is counted through the Responses
// codec, and a dialect with no codec is Unsupported.
func TestCountTokensFor(t *testing.T) {
	body := []byte(`{"model":"m","input":"hello there"}`)
	if _, _, err := CountTokens(WireOpenAI, body); err == nil {
		t.Fatal("the wire's Chat codec read a Responses body")
	}
	n, estimated, err := CountTokensFor(ir.DialectOpenAIResponses, body)
	if err != nil || n <= 0 || !estimated {
		t.Fatalf("Responses: %d %v %v", n, estimated, err)
	}
	chat := fixture(t, "fixtures/openai-chat.request.json")
	if n, _, err := CountTokensFor(ir.DialectOpenAIChat, chat); err != nil || n <= 0 {
		t.Fatalf("Chat: %d %v", n, err)
	}
	if wn, _, err := CountTokens(WireOpenAI, chat); err != nil || wn != n {
		t.Fatalf("CountTokens and CountTokensFor disagree on a Chat body: %d %d %v", wn, n, err)
	}
	var e *Error
	if _, _, err := CountTokensFor(ir.Dialect("nope"), chat); !errors.As(err, &e) || e.Code != Unsupported {
		t.Fatalf("an unknown dialect: %v", err)
	}
	if _, _, err := CountTokensFor(ir.DialectOpenAIChat, []byte(`{"model":"gpt"}`)); !errors.As(err, &e) || e.Code != DecodeRequest {
		t.Fatalf("a body the codec refuses: %v", err)
	}
}

func FuzzCountTokens(f *testing.F) {
	f.Add("anthropic", []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`))
	f.Add("openai", []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	f.Add("lux", []byte(`{"model":"m","messages":[{"role":"user","blocks":[{"type":"text","text":"hi"}]}]}`))
	f.Add("google", []byte(`{}`))
	f.Fuzz(func(t *testing.T, wire string, body []byte) {
		n, estimated, err := CountTokens(Wire(wire), body)
		if err != nil {
			checkError(t, err)
			if n != 0 || estimated {
				t.Fatalf("a count beside an error: %d %v", n, estimated)
			}
			return
		}
		if n < 0 || !estimated {
			t.Fatalf("a success with %d %v", n, estimated)
		}
	})
}
