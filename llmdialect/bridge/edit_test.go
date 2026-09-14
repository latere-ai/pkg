// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestProbe(t *testing.T) {
	cases := []struct {
		body   string
		want   Call
		wantOK bool
	}{
		{`{"model":"m","stream":true,"max_tokens":10}`, Call{Model: "m", HasModel: true, Stream: true, MaxTokens: 10}, true},
		{`{"model":"m","max_completion_tokens":20}`, Call{Model: "m", HasModel: true, MaxTokens: 20}, true},
		{`{"model":"m","max_output_tokens":30}`, Call{Model: "m", HasModel: true, MaxTokens: 30}, true},
		{`{"generationConfig":{"maxOutputTokens":40}}`, Call{MaxTokens: 40}, true},
		{`{"max_tokens":0,"generationConfig":{"maxOutputTokens":0}}`, Call{}, true},
		{`{"model":5,"stream":"yes","max_tokens":"x"}`, Call{}, true},
		{`{"model":""}`, Call{}, true},
		{`{}`, Call{}, true},
		{`[]`, Call{}, false},
		{`"s"`, Call{}, false},
		{`null`, Call{}, false},
		{`{"model":`, Call{}, false},
		{``, Call{}, false},
	}
	for _, c := range cases {
		got, err := Probe([]byte(c.body))
		if (err == nil) != c.wantOK {
			t.Errorf("%s: err %v, want ok %v", c.body, err, c.wantOK)
			continue
		}
		if got != c.want {
			t.Errorf("%s: %+v, want %+v", c.body, got, c.want)
		}
	}
}

func TestSetModel(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"model":"a","x":1}`, `{"model":"up","x":1}`},
		{`{ "x" : [1,{"model":"nested"}], "model" : "a" }`, `{ "x" : [1,{"model":"nested"}], "model" : "up" }`},
		{`{"type":"message_start","message":{"id":"i","model":"a"}}`, `{"type":"message_start","message":{"id":"i","model":"up"}}`},
		{`{"x":"a\"model\":\"b\"","model":"a"}`, `{"x":"a\"model\":\"b\"","model":"up"}`},
		{`{"model":1}`, `{"model":1}`},
		{`{"x":1}`, `{"x":1}`},
		{`{"message":"s"}`, `{"message":"s"}`},
		{`[1]`, `[1]`},
		{`{"model":"a"`, `{"model":"up"`}, // the member is found before the missing brace
		{`{"model" "a"}`, `{"model" "a"}`},
		{`{bad:1}`, `{bad:1}`},
		{`{"a":"unterminated}`, `{"a":"unterminated}`},
		{`{"a":[1,2}`, `{"a":[1,2}`},
		{`{"a":}`, `{"a":}`},
		{`{"a":1,}`, `{"a":1,}`},
		{`{"a":1,"b":true,"c":null,"model":"a"}`, `{"a":1,"b":true,"c":null,"model":"up"}`},
		{`{"aA":1,"model":"a"}`, `{"aA":1,"model":"up"}`},
		{`{"\uZZ":1,"model":"a"}`, `{"\uZZ":1,"model":"a"}`}, // a key that is not a JSON string
	}
	for _, c := range cases {
		if got := string(SetModel([]byte(c.in), "up")); got != c.want {
			t.Errorf("SetModel(%s) = %s, want %s", c.in, got, c.want)
		}
	}
	// A name is written as json.Marshal writes a string: valid JSON for
	// any name, with the HTML-sensitive characters escaped.
	if got := string(SetModel([]byte(`{"model":"a"}`), "x<y>&\"z\n")); got != `{"model":"x\u003cy\u003e\u0026\"z\n"}` || !json.Valid([]byte(got)) {
		t.Errorf("quoting %s", got)
	}
}

func TestSetModelInFrame(t *testing.T) {
	frame := "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"up\"}}\r\n: comment\ndata:{\"model\":\"up\"}\n\n"
	want := "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"name\"}}\r\n: comment\ndata: {\"model\":\"name\"}\n\n"
	if got := string(SetModelInFrame([]byte(frame), "name")); got != want {
		t.Errorf("SetModelInFrame\n got %q\nwant %q", got, want)
	}
	if got := string(SetModelInFrame([]byte("data: [DONE]\n\n"), "name")); got != "data: [DONE]\n\n" {
		t.Errorf("[DONE] %q", got)
	}
	if got := string(SetModelInFrame([]byte("data: {\"model\":\"a\"}"), "n")); got != "data: {\"model\":\"n\"}" {
		t.Errorf("no line ending %q", got)
	}
	if got := SetModelInFrame(nil, "n"); len(got) != 0 {
		t.Errorf("empty frame %q", got)
	}
}

func TestSetIncludeUsage(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"model":"m","stream":true}`, `{"stream_options":{"include_usage":true},"model":"m","stream":true}`},
		{`{}`, `{"stream_options":{"include_usage":true}}`},
		{`{ }`, `{"stream_options":{"include_usage":true} }`},
		{`{"stream_options":{}}`, `{"stream_options":{"include_usage":true}}`},
		{`{"stream_options":{"include_usage":false}}`, `{"stream_options":{"include_usage":true}}`},
		{`{"stream_options":{"other":1}}`, `{"stream_options":{"include_usage":true,"other":1}}`},
		{`{"stream_options":{"include_usage":true}}`, `{"stream_options":{"include_usage":true}}`},
		{`{"stream_options":null}`, `{"stream_options":{"include_usage":true}}`},
		{`[1]`, `[1]`},
		{`{"stream_options":{"a":}}`, `{"stream_options":{"a":}}`},
	}
	for _, c := range cases {
		got := string(SetIncludeUsage([]byte(c.in)))
		if got != c.want {
			t.Errorf("SetIncludeUsage(%s) = %s, want %s", c.in, got, c.want)
		}
		if json.Valid([]byte(c.in)) && !json.Valid([]byte(got)) {
			t.Errorf("SetIncludeUsage(%s) = %s is not valid JSON", c.in, got)
		}
	}
}

func TestRemoveMember(t *testing.T) {
	cases := []struct{ in, key, want string }{
		{`{"a":1,"max_tokens":5,"b":2}`, "max_tokens", `{"a":1,"b":2}`},
		{`{"max_tokens":5,"b":2}`, "max_tokens", `{"b":2}`},
		{`{"a":1,"max_tokens":5}`, "max_tokens", `{"a":1}`},
		{`{"a":1, "max_tokens" : {"x":[1]} }`, "max_tokens", `{"a":1 }`},
		{`{"max_tokens":5}`, "max_tokens", `{}`},
		{`{"a":1}`, "max_tokens", `{"a":1}`},
		{`[1]`, "max_tokens", `[1]`},
		{`{"a\"b":1,"c":2}`, `a"b`, `{"c":2}`}, // a key with an escaped quote
		{`{"c":2,"a\"b":{"a\"b":1}}`, `a"b`, `{"c":2}`},
	}
	for _, c := range cases {
		got := string(RemoveMember([]byte(c.in), c.key))
		if got != c.want {
			t.Errorf("RemoveMember(%s, %s) = %s, want %s", c.in, c.key, got, c.want)
		}
		if !json.Valid([]byte(got)) {
			t.Errorf("RemoveMember(%s) = %s is not valid JSON", c.in, got)
		}
	}
}

// keys of a JSON object body, for the fuzz invariants.
func keys(body []byte) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	return m
}

func FuzzProbe(f *testing.F) {
	f.Add([]byte(`{"model":"m","stream":true,"max_tokens":10}`))
	f.Add([]byte(`{"generationConfig":{"maxOutputTokens":40}}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		c, err := Probe(body)
		if err != nil {
			if c != (Call{}) {
				t.Fatalf("a call beside an error: %+v", c)
			}
			return
		}
		if c.HasModel != (c.Model != "") || c.MaxTokens < 0 {
			t.Fatalf("ill-formed call %+v", c)
		}
	})
}

func FuzzSetModel(f *testing.F) {
	f.Add([]byte(`{"model":"a","x":1}`), "up")
	f.Add([]byte(`{"type":"message_start","message":{"id":"i","model":"a"}}`), "up")
	f.Add([]byte(`{"a":"unterminated}`), "n")
	f.Fuzz(func(t *testing.T, body []byte, name string) {
		out := SetModel(body, name)
		if json.Valid(body) && !json.Valid(out) {
			t.Fatalf("valid in, invalid out: %s -> %s", body, out)
		}
		if again := SetModel(out, name); !bytes.Equal(again, out) {
			t.Fatalf("not idempotent: %s -> %s -> %s", body, out, again)
		}
		in, res := keys(body), keys(out)
		if in == nil {
			if !bytes.Equal(out, body) && !bytes.Contains(body, []byte("model")) {
				t.Fatalf("an unreadable body without the member changed: %s -> %s", body, out)
			}
			return
		}
		for k, v := range in {
			if k == "model" || k == "message" {
				continue
			}
			if !bytes.Equal(res[k], v) {
				t.Fatalf("member %q changed: %s -> %s", k, v, res[k])
			}
		}
	})
}

func FuzzSetModelInFrame(f *testing.F) {
	f.Add([]byte("event: x\r\ndata: {\"model\":\"a\"}\r\n\n"), "n")
	f.Add([]byte("data:{\"model\":\"a\"}\ndata: [DONE]\n\n"), "n")
	f.Fuzz(func(t *testing.T, frame []byte, name string) {
		out := SetModelInFrame(frame, name)
		if again := SetModelInFrame(out, name); !bytes.Equal(again, out) {
			t.Fatalf("not idempotent: %q -> %q -> %q", frame, out, again)
		}
		inLines, outLines := bytes.SplitAfter(frame, []byte("\n")), bytes.SplitAfter(out, []byte("\n"))
		if len(inLines) != len(outLines) {
			t.Fatalf("line count %d -> %d: %q -> %q", len(inLines), len(outLines), frame, out)
		}
		for i, line := range inLines {
			if !bytes.HasPrefix(bytes.TrimRight(line, "\r\n"), []byte("data:")) && !bytes.Equal(outLines[i], line) {
				t.Fatalf("a line that is no data line changed: %q -> %q", line, outLines[i])
			}
		}
	})
}

func FuzzSetIncludeUsage(f *testing.F) {
	f.Add([]byte(`{"model":"m","stream":true}`))
	f.Add([]byte(`{"stream_options":{"other":1}}`))
	f.Add([]byte(`{"stream_options":null}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		out := SetIncludeUsage(body)
		if json.Valid(body) && !json.Valid(out) {
			t.Fatalf("valid in, invalid out: %s -> %s", body, out)
		}
		if again := SetIncludeUsage(out); !bytes.Equal(again, out) {
			t.Fatalf("not idempotent: %s -> %s -> %s", body, out, again)
		}
		in, res := keys(body), keys(out)
		if in == nil {
			return
		}
		var so struct {
			IncludeUsage bool `json:"include_usage"`
		}
		if json.Unmarshal(res["stream_options"], &so) != nil || !so.IncludeUsage {
			t.Fatalf("include_usage is not true: %s", out)
		}
		for k, v := range in {
			if k != "stream_options" && !bytes.Equal(res[k], v) {
				t.Fatalf("member %q changed: %s -> %s", k, v, res[k])
			}
		}
	})
}

func FuzzRemoveMember(f *testing.F) {
	f.Add([]byte(`{"a":1,"max_tokens":5,"b":2}`), "max_tokens")
	f.Add([]byte(`{"a":1, "max_tokens" : {"x":[1]} }`), "max_tokens")
	f.Add([]byte(`{"a\"b":1,"c":2}`), `a"b`)
	f.Fuzz(func(t *testing.T, body []byte, key string) {
		out := RemoveMember(body, key)
		if json.Valid(body) && !json.Valid(out) {
			t.Fatalf("valid in, invalid out: %s -> %s", body, out)
		}
		in, res := keys(body), keys(out)
		if in == nil {
			return
		}
		for k, v := range in {
			if k != key && !bytes.Equal(res[k], v) {
				t.Fatalf("member %q changed: %s -> %s", k, v, res[k])
			}
		}
		if _, still := res[key]; still && strings.Count(string(body), quote(key)) < 2 {
			t.Fatalf("the member is still there: %s -> %s", body, out)
		}
	})
}
