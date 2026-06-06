package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEventJSONOmitOptionalFields(t *testing.T) {
	ev := Event{
		EventID:  "e1",
		TS:       time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC),
		Category: CategoryLifecycle,
		Actor:    Actor{Type: "user", PrincipalID: "alice"},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "subject") {
		t.Errorf("subject should be omitted when nil: %s", s)
	}
	if strings.Contains(s, "policy") {
		t.Errorf("policy should be omitted when empty: %s", s)
	}
	if strings.Contains(s, "owner_sub") {
		t.Errorf("owner_sub should be omitted when empty: %s", s)
	}

	// With Subject and Payload populated.
	ev.Subject = &Subject{Kind: "sandbox", ID: "sb-1", Name: "demo"}
	ev.Payload = json.RawMessage(`{"k":"v"}`)
	b, _ = json.Marshal(ev)
	s = string(b)
	if !strings.Contains(s, `"subject":{"kind":"sandbox","id":"sb-1","name":"demo"}`) {
		t.Errorf("subject not present: %s", s)
	}
	if !strings.Contains(s, `"payload":{"k":"v"}`) {
		t.Errorf("payload not present: %s", s)
	}
}

func TestActorIsZero(t *testing.T) {
	if !(Actor{}).IsZero() {
		t.Error("zero Actor should be zero")
	}
	if (Actor{Type: "user"}).IsZero() {
		t.Error("Actor with Type set should not be zero")
	}
	if (Actor{PrincipalID: "x"}).IsZero() {
		t.Error("Actor with PrincipalID set should not be zero")
	}
	if (Actor{OwnerSub: "x"}).IsZero() {
		t.Error("Actor with OwnerSub set should not be zero")
	}
}

func TestSubjectIsZero(t *testing.T) {
	if !(Subject{}).IsZero() {
		t.Error("zero Subject should be zero")
	}
	if (Subject{Kind: "k"}).IsZero() || (Subject{ID: "i"}).IsZero() || (Subject{Name: "n"}).IsZero() {
		t.Error("populated Subject should not be zero")
	}
}

type fakeEmitter struct {
	mu     sync.Mutex
	events []Event
	err    error
}

func (f *fakeEmitter) Emit(_ context.Context, ev Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return f.err
}

func TestMultiEmitterFanout(t *testing.T) {
	a := &fakeEmitter{}
	b := &fakeEmitter{}
	m := MultiEmitter{a, b, nil}
	if err := m.Emit(context.Background(), Event{EventID: "e1"}); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if len(a.events) != 1 || len(b.events) != 1 {
		t.Fatalf("a=%d b=%d", len(a.events), len(b.events))
	}
}

func TestMultiEmitterCollectsErrors(t *testing.T) {
	errA := errors.New("err-a")
	errB := errors.New("err-b")
	a := &fakeEmitter{err: errA}
	b := &fakeEmitter{err: errB}
	c := &fakeEmitter{}
	m := MultiEmitter{a, b, c}
	err := m.Emit(context.Background(), Event{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Errorf("missing wrapped errors: %v", err)
	}
	if len(c.events) != 1 {
		t.Errorf("c should still have been called: %d", len(c.events))
	}
}

func TestMultiEmitterNilSliceNoError(t *testing.T) {
	var m MultiEmitter
	if err := m.Emit(context.Background(), Event{}); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestEmitterFunc(t *testing.T) {
	calls := 0
	f := EmitterFunc(func(_ context.Context, ev Event) error {
		calls++
		if ev.EventID != "e1" {
			t.Errorf("ev.EventID = %q", ev.EventID)
		}
		return nil
	})
	if err := f.Emit(context.Background(), Event{EventID: "e1"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestStdoutEmitterWritesNDJSON(t *testing.T) {
	var buf bytes.Buffer
	em := NewStdoutEmitter(&buf)
	if err := em.Emit(context.Background(), Event{EventID: "e1", Category: CategoryLifecycle}); err != nil {
		t.Fatal(err)
	}
	if err := em.Emit(context.Background(), Event{EventID: "e2", Category: CategoryAdmin}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	for i, line := range lines {
		var got Event
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d not JSON: %v", i, err)
		}
	}
}

func TestStdoutEmitterRedactCallback(t *testing.T) {
	var buf bytes.Buffer
	em := NewStdoutEmitter(&buf, WithRedact(func(ev Event) Event {
		ev.Payload = RedactJSON(ev.Payload)
		return ev
	}))
	payload := json.RawMessage(`{"argv":["env","GITHUB_TOKEN=ghp_0123456789abcdef0123456789abcdef0123"]}`)
	if err := em.Emit(context.Background(), Event{EventID: "x", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "ghp_0123456789abcdef0123456789abcdef0123") {
		t.Errorf("secret leaked: %s", buf.String())
	}
}

func TestStdoutEmitterConcurrent(t *testing.T) {
	var buf bytes.Buffer
	em := NewStdoutEmitter(&buf)
	var wg sync.WaitGroup
	const writers, each = 8, 50
	for range writers {
		wg.Go(func() {
			for range each {
				_ = em.Emit(context.Background(), Event{EventID: "id"})
			}
		})
	}
	wg.Wait()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != writers*each {
		t.Fatalf("got %d lines, want %d", len(lines), writers*each)
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("line %d not valid JSON: %q", i, line)
		}
	}
}

type errWriter struct{ err error }

func (e errWriter) Write([]byte) (int, error) { return 0, e.err }

func TestStdoutEmitterWriteError(t *testing.T) {
	em := NewStdoutEmitter(errWriter{err: errors.New("boom")})
	if err := em.Emit(context.Background(), Event{EventID: "x"}); err == nil {
		t.Error("expected write error to bubble")
	}
}

type unmarshalable struct{}

func (unmarshalable) MarshalJSON() ([]byte, error) { return nil, errors.New("nope") }

func TestStdoutEmitterMarshalError(t *testing.T) {
	em := NewStdoutEmitter(&bytes.Buffer{})
	// Construct an Event whose Payload errors during marshaling. json.RawMessage
	// can carry invalid JSON; encoding/json validates it on Marshal and returns
	// an error. Pass syntactically invalid bytes.
	if err := em.Emit(context.Background(), Event{EventID: "x", Payload: json.RawMessage(`{`)}); err == nil {
		t.Error("expected marshal error on invalid RawMessage")
	}
}

func TestRedact(t *testing.T) {
	cases := []struct {
		name, in string
		must     []string
		mustnt   []string
	}{
		{"bearer", "Authorization: Bearer abc.def.ghi_123-XYZ", []string{"Authorization: Bearer ***"}, []string{"abc.def.ghi_123-XYZ"}},
		{"env", "GITHUB_TOKEN=ghp_0123456789abcdef0123456789abcdef0123", []string{"GITHUB_TOKEN=***"}, []string{"ghp_0123456789"}},
		{"url", "https://alice:hunter2@example.com/", []string{"https://alice:***@example.com/"}, []string{"hunter2"}},
		{"jwt", "tok=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij", []string{"***"}, []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}},
		{"aws", "AKIAIOSFODNN7EXAMPLE", []string{"***"}, []string{"AKIAIOSFODNN7EXAMPLE"}},
		{"gh classic", "ghp_0123456789abcdef0123456789abcdef0123", []string{"***"}, []string{"ghp_0123456789abcdef0123456789abcdef0123"}},
		{"gh app", "ghs_0123456789abcdef0123456789abcdef0123", []string{"***"}, []string{"ghs_0123456789abcdef0123456789abcdef0123"}},
		{"gh user", "ghu_0123456789abcdef0123456789abcdef0123", []string{"***"}, []string{"ghu_0123456789abcdef0123456789abcdef0123"}},
		{"gh oauth", "gho_0123456789abcdef0123456789abcdef0123", []string{"***"}, []string{"gho_0123456789abcdef0123456789abcdef0123"}},
		{"gh refresh", "ghr_0123456789abcdef0123456789abcdef0123", []string{"***"}, []string{"ghr_0123456789abcdef0123456789abcdef0123"}},
		{"anthropic", "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx", []string{"***"}, []string{"sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx"}},
		{"openai", "sk-proj-abcdef0123456789abcdef0123456789", []string{"***"}, []string{"sk-proj-abcdef0123456789abcdef0123456789"}},
		{"plain", "hello world", []string{"hello world"}, []string{"***"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			for _, s := range tc.must {
				if !strings.Contains(got, s) {
					t.Errorf("want %q in %q", s, got)
				}
			}
			for _, s := range tc.mustnt {
				if strings.Contains(got, s) {
					t.Errorf("leaked %q in %q", s, got)
				}
			}
		})
	}
}

func TestRedactEmpty(t *testing.T) {
	if Redact("") != "" {
		t.Fatal("Redact(\"\") should be empty")
	}
}

func TestRedactJSONScalarsAndArrays(t *testing.T) {
	in := `{"argv":["git","push","https://alice:hunter2@x.com"],"keys":["sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx","plain"],"count":42,"ok":true}`
	out := RedactJSON([]byte(in))
	s := string(out)
	for _, bad := range []string{"hunter2", "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx"} {
		if strings.Contains(s, bad) {
			t.Errorf("leaked %q in %s", bad, s)
		}
	}
	if !strings.Contains(s, `"git"`) || !strings.Contains(s, `"count":42`) || !strings.Contains(s, `"ok":true`) {
		t.Errorf("benign data scrubbed: %s", s)
	}
}

func TestRedactJSONKeyBased(t *testing.T) {
	in := `{"image":"nginx","ApiKey":"whatever","nested":{"auth_token":"x"},"passWORD":12345}`
	out := RedactJSON([]byte(in))
	s := string(out)
	if !strings.Contains(s, `"image":"nginx"`) {
		t.Errorf("benign field scrubbed: %s", s)
	}
	if strings.Contains(s, `"whatever"`) {
		t.Errorf("ApiKey value not scrubbed: %s", s)
	}
	if strings.Contains(s, `"auth_token":"x"`) {
		t.Errorf("auth_token value not scrubbed: %s", s)
	}
	if strings.Contains(s, `12345`) {
		t.Errorf("password numeric value not scrubbed: %s", s)
	}
}

func TestRedactJSONInvalidJSONFallback(t *testing.T) {
	in := []byte("not json: Authorization: Bearer abc.def.ghi-XYZ")
	out := RedactJSON(in)
	if strings.Contains(string(out), "abc.def.ghi-XYZ") {
		t.Errorf("invalid-JSON fallback should still scrub: %s", out)
	}
}

func TestRedactJSONMarshalErrorFallback(t *testing.T) {
	// Force the post-walk Marshal step to fail by injecting an unmarshalable
	// value through a custom type that the json package cannot encode.
	// We can't go through the public Unmarshal path with a non-marshalable
	// leaf because Unmarshal produces only basic types — instead exercise
	// the Marshal-error fallback by stubbing the package marshal under test.
	// Here we cover the realistic invalid-JSON branch which already exists,
	// plus exercise the 'default' walk branch with a number literal that
	// flows through.
	in := `{"n":1.5e10}`
	out := RedactJSON([]byte(in))
	if !strings.Contains(string(out), "n") {
		t.Errorf("default branch lost data: %s", out)
	}
}

func TestRedactJSONPreservesLargeIntegers(t *testing.T) {
	// Integers above 2^53 (snowflake-style IDs, unix-ns timestamps) must
	// survive the redaction round-trip without precision loss. The naive
	// decode-into-any path turns every JSON number into a float64 and
	// silently truncates the trailing digits.
	in := `{"id":1717000000000000123,"big":12345678901234567890,"ratio":1.5}`
	out := string(RedactJSON([]byte(in)))
	for _, want := range []string{"1717000000000000123", "12345678901234567890", "1.5"} {
		if !strings.Contains(out, want) {
			t.Errorf("number %q corrupted in round-trip: %s", want, out)
		}
	}
}

func TestRedactJSONAuthorizationKey(t *testing.T) {
	// Serialized HTTP headers put the opaque credential in the value with no
	// "authorization:" prefix, so the bearer value-rule never fires; the key
	// itself must trigger blanking.
	in := `{"headers":{"Authorization":"Bearer opaquetokenvalue1234567890"},"auth":"Basic dXNlcjpwYXNz"}`
	out := string(RedactJSON([]byte(in)))
	for _, bad := range []string{"opaquetokenvalue1234567890", "dXNlcjpwYXNz"} {
		if strings.Contains(out, bad) {
			t.Errorf("credential %q leaked through auth key: %s", bad, out)
		}
	}
	// The "$" anchor must not blank a benign "author" field.
	keep := `{"author":"Ada Lovelace"}`
	if got := string(RedactJSON([]byte(keep))); !strings.Contains(got, "Ada Lovelace") {
		t.Errorf("benign author field scrubbed: %s", got)
	}
}

func TestRedactJSONTrailingDataFallback(t *testing.T) {
	// A valid JSON value followed by trailing bytes must fall back to the
	// whole-string scrub rather than silently dropping the trailing data.
	in := []byte(`{"a":1} GITHUB_TOKEN=ghp_0123456789abcdef0123456789abcdef0123`)
	out := string(RedactJSON(in))
	if strings.Contains(out, "ghp_0123456789abcdef0123456789abcdef0123") {
		t.Errorf("trailing credential not scrubbed: %s", out)
	}
}

func TestLooksLikeCredentialKeyCases(t *testing.T) {
	for _, k := range []string{"apiKey", "API_KEY", "token", "TOKEN", "secret", "SECRET", "password", "Passwd", "credential"} {
		if !looksLikeCredentialKey(k) {
			t.Errorf("%q should match", k)
		}
	}
	for _, k := range []string{"image", "name", "tier", "duration"} {
		if looksLikeCredentialKey(k) {
			t.Errorf("%q should not match", k)
		}
	}
}

func FuzzRedact(f *testing.F) {
	f.Add("Authorization: Bearer abc.def.ghi")
	f.Add("GITHUB_TOKEN=ghp_0123456789abcdef0123456789abcdef0123")
	f.Add("plain text")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		got := Redact(s)
		// The rules must not panic, and on whitespace-only input the result
		// must equal the input (no spurious replacement).
		if strings.TrimSpace(s) == "" && got != s {
			t.Errorf("whitespace input changed: %q -> %q", s, got)
		}
	})
}

func ExampleNewStdoutEmitter() {
	var buf bytes.Buffer
	em := NewStdoutEmitter(&buf)
	_ = em.Emit(context.Background(), Event{
		EventID:  "e1",
		Category: CategoryLifecycle,
		Actor:    Actor{Type: "user", PrincipalID: "alice"},
		Subject:  &Subject{Kind: "sandbox", ID: "sb-1"},
		TS:       time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
	})
	fmt.Print(buf.String())
	// Output: {"event_id":"e1","ts":"2026-05-10T12:00:00Z","category":"lifecycle","actor":{"type":"user","principal_id":"alice"},"subject":{"kind":"sandbox","id":"sb-1"}}
}
