// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeBody_Success(t *testing.T) {
	body := `{"name":"alice","age":30}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	type payload struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	v, ok := DecodeBody[payload](w, r)
	if !ok {
		t.Fatalf("DecodeBody returned false; response: %s", w.Body.String())
	}
	if v.Name != "alice" || v.Age != 30 {
		t.Fatalf("unexpected value: %+v", v)
	}
}

func TestDecodeBody_InvalidJSON(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	v, ok := DecodeBody[map[string]any](w, r)
	if ok {
		t.Fatal("expected DecodeBody to fail on invalid JSON")
	}
	if v != nil {
		t.Fatal("expected nil on failure")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid JSON") {
		t.Fatalf("expected error message containing 'invalid JSON', got: %s", w.Body.String())
	}
}

func TestDecodeBody_UnknownFields(t *testing.T) {
	body := `{"name":"alice","extra":"field"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	type payload struct {
		Name string `json:"name"`
	}
	_, ok := DecodeBody[payload](w, r)
	if ok {
		t.Fatal("expected DecodeBody to reject unknown fields")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDecodeBody_TrailingContent(t *testing.T) {
	body := `{"name":"alice"}{"name":"bob"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	type payload struct {
		Name string `json:"name"`
	}
	_, ok := DecodeBody[payload](w, r)
	if ok {
		t.Fatal("expected DecodeBody to reject trailing content")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDecodeBody_ScalarTrailingContent(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`true false`))
	w := httptest.NewRecorder()

	_, ok := DecodeBody[bool](w, r)
	if ok {
		t.Fatal("expected DecodeBody to reject trailing scalar content")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDecodeBody_MaxBytesError(t *testing.T) {
	// Build a valid JSON body that exceeds the limit so that the JSON
	// decoder surfaces the MaxBytesError rather than a syntax error.
	bigBody := `{"field":"` + strings.Repeat("a", 1024) + `"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(bigBody))
	r.Body = http.MaxBytesReader(w, r.Body, 10)

	v, ok := DecodeBody[map[string]any](w, r)
	if ok {
		t.Fatal("expected DecodeBody to fail on oversized body")
	}
	if v != nil {
		t.Fatal("expected nil on failure")
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
	// The response should be JSON from Write.
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected JSON response, got: %s", w.Body.String())
	}
	if resp["error"] != "request body too large" {
		t.Fatalf("unexpected error: %s", resp["error"])
	}
}

func TestDecodeOptionalBody_EmptyBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
	w := httptest.NewRecorder()

	type payload struct {
		Name string `json:"name"`
	}
	v, ok := DecodeOptionalBody[payload](w, r)
	if !ok {
		t.Fatalf("DecodeOptionalBody returned false on empty body")
	}
	if v.Name != "" {
		t.Fatalf("expected zero-value, got: %+v", v)
	}
}

func TestDecodeOptionalBody_NilBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Body = nil
	w := httptest.NewRecorder()

	type payload struct {
		Name string
	}
	v, ok := DecodeOptionalBody[payload](w, r)
	if !ok {
		t.Fatal("DecodeOptionalBody returned false on nil body")
	}
	if v == nil {
		t.Fatal("expected non-nil zero-value pointer")
	}
}

func TestDecodeOptionalBody_NilRequest(t *testing.T) {
	w := httptest.NewRecorder()
	type payload struct {
		Name string
	}
	v, ok := DecodeOptionalBody[payload](w, nil)
	if !ok {
		t.Fatal("DecodeOptionalBody returned false on nil request")
	}
	if v == nil {
		t.Fatal("expected non-nil zero-value pointer")
	}
}

func TestDecodeOptionalBody_WithContent(t *testing.T) {
	body := `{"name":"bob"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	type payload struct {
		Name string `json:"name"`
	}
	v, ok := DecodeOptionalBody[payload](w, r)
	if !ok {
		t.Fatalf("DecodeOptionalBody returned false; response: %s", w.Body.String())
	}
	if v.Name != "bob" {
		t.Fatalf("expected bob, got: %s", v.Name)
	}
}

func TestDecodeOptionalBody_InvalidJSON(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	v, ok := DecodeOptionalBody[map[string]any](w, r)
	if ok {
		t.Fatal("expected DecodeOptionalBody to fail on invalid JSON")
	}
	if v != nil {
		t.Fatal("expected nil on failure")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestWrite_Success(t *testing.T) {
	w := httptest.NewRecorder()
	Write(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %s", ct)
	}
	var v map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if v["key"] != "value" {
		t.Fatalf("expected value, got %s", v["key"])
	}
}

func TestWrite_CustomStatus(t *testing.T) {
	for _, code := range []int{http.StatusCreated, http.StatusAccepted, http.StatusNotFound} {
		w := httptest.NewRecorder()
		Write(w, code, map[string]string{})
		if w.Code != code {
			t.Errorf("expected %d, got %d", code, w.Code)
		}
	}
}

func TestWrite_SlicePayload(t *testing.T) {
	w := httptest.NewRecorder()
	Write(w, http.StatusOK, []string{"a", "b", "c"})

	var v []string
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if len(v) != 3 || v[0] != "a" {
		t.Fatalf("unexpected: %v", v)
	}
}

func TestDecodeOptionalBody_MaxBytesError(t *testing.T) {
	bigBody := `{"name":"` + strings.Repeat("a", 1024) + `"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(bigBody))
	r.Body = http.MaxBytesReader(w, r.Body, 10)

	type payload struct {
		Name string `json:"name"`
	}
	v, ok := DecodeOptionalBody[payload](w, r)
	if ok {
		t.Fatal("expected DecodeOptionalBody to fail on oversized body")
	}
	if v != nil {
		t.Fatal("expected nil on failure")
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestDecodeOptionalBody_TrailingContent(t *testing.T) {
	body := `{"name":"alice"}{"name":"bob"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	type payload struct {
		Name string `json:"name"`
	}
	_, ok := DecodeOptionalBody[payload](w, r)
	if ok {
		t.Fatal("expected DecodeOptionalBody to reject trailing content")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDecodeOptionalBody_ScalarTrailingContent(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`1 2`))
	w := httptest.NewRecorder()

	_, ok := DecodeOptionalBody[int](w, r)
	if ok {
		t.Fatal("expected DecodeOptionalBody to reject trailing scalar content")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDecodeOptionalBody_UnknownFields(t *testing.T) {
	body := `{"name":"alice","extra":"field"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	type payload struct {
		Name string `json:"name"`
	}
	_, ok := DecodeOptionalBody[payload](w, r)
	if ok {
		t.Fatal("expected DecodeOptionalBody to reject unknown fields")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// A value that cannot be marshalled must not reach the client as the status the
// caller asked for. Committing the status before encoding used to answer
// "200 OK" with an empty body, which a client cannot distinguish from a
// legitimately empty success.
func TestWrite_EncodingErrorDoesNotCommitTheRequestedStatus(t *testing.T) {
	w := httptest.NewRecorder()

	Write(w, http.StatusOK, make(chan int)) // channels are unmarshallable

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if body := w.Body.String(); strings.TrimSpace(body) == "" {
		t.Fatal("body is empty; a failed encode must say something, not answer silently")
	}
}

// The same rule applies at any status: a caller asking for 201 with a value
// that cannot marshal must not get 201.
func TestWrite_EncodingErrorAtNonDefaultStatus(t *testing.T) {
	w := httptest.NewRecorder()

	Write(w, http.StatusCreated, map[string]any{"bad": make(chan int)})

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

// Values that do marshal must produce byte-identical output to what
// json.Encoder.Encode wrote, trailing newline included. Callers and their
// clients compare bodies.
func TestWrite_WireBytesMatchEncoder(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	}
	cases := []any{
		payload{"alice", 1},
		[]int{1, 2, 3},
		map[string]string{"k": "v"},
		"bare string",
		nil,
	}
	for _, v := range cases {
		var want bytes.Buffer
		if err := json.NewEncoder(&want).Encode(v); err != nil {
			t.Fatalf("reference encode of %#v: %v", v, err)
		}
		w := httptest.NewRecorder()
		Write(w, http.StatusOK, v)
		if got := w.Body.String(); got != want.String() {
			t.Errorf("Write(%#v) body = %q, want %q", v, got, want.String())
		}
	}
}

func TestPathUUID_Valid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/x/00000000-0000-0000-0000-000000000001", nil)
	r.SetPathValue("id", "00000000-0000-0000-0000-000000000001")
	w := httptest.NewRecorder()

	id, ok := PathUUID(w, r, "id")
	if !ok {
		t.Fatalf("expected ok=true, got %d body=%s", w.Code, w.Body.String())
	}
	if id.String() != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("id = %s, want all-zeros-1", id)
	}
}

func TestPathUUID_Missing(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	if _, ok := PathUUID(w, r, "id"); ok {
		t.Fatal("expected ok=false for missing path value")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "missing id") {
		t.Errorf("body = %s, want 'missing id'", w.Body.String())
	}
}

func TestPathUUID_Malformed(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/x/notauuid", nil)
	r.SetPathValue("id", "notauuid")
	w := httptest.NewRecorder()
	if _, ok := PathUUID(w, r, "id"); ok {
		t.Fatal("expected ok=false for malformed uuid")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid id") {
		t.Errorf("body = %s, want 'invalid id'", w.Body.String())
	}
}

// The trailing-content probe in finishDecode reads past the first value, so a
// body whose first value fits under the MaxBytesReader limit but whose trailer
// does not trips the limit on the second Decode rather than the first. That
// path answers 413, not 400.
func TestDecodeBody_TrailingContentExceedsMaxBytes(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"a":1}{"b":2}`))
	w := httptest.NewRecorder()
	r.Body = http.MaxBytesReader(w, r.Body, 8)

	v, ok := DecodeBody[map[string]any](w, r)
	if ok {
		t.Fatal("expected DecodeBody to fail when the trailer exceeds the limit")
	}
	if v != nil {
		t.Fatal("expected nil on failure")
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

// A malformed trailer is a decode error rather than a well-formed extra value,
// so finishDecode reports the syntax error instead of the generic
// "unexpected trailing content" message.
func TestDecodeBody_MalformedTrailingContent(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"a":1}}`))
	w := httptest.NewRecorder()

	v, ok := DecodeBody[map[string]any](w, r)
	if ok {
		t.Fatal("expected DecodeBody to fail on a malformed trailer")
	}
	if v != nil {
		t.Fatal("expected nil on failure")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if !strings.Contains(w.Body.String(), "invalid JSON:") {
		t.Fatalf("body = %q, want a decode error", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "unexpected trailing content") {
		t.Fatalf("body = %q, want the syntax error rather than the trailing-content message", w.Body.String())
	}
}

// failingWriter accepts headers but rejects the body write, standing in for a
// client that disconnects between the status line and the payload.
type failingWriter struct {
	http.ResponseWriter
	err error
}

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

// A body write that fails after the status is committed cannot be reported to
// the client -- the status line is already gone. It must be logged rather than
// panicking or being dropped silently.
func TestWrite_BodyWriteErrorIsSurvivable(t *testing.T) {
	rec := httptest.NewRecorder()
	w := failingWriter{ResponseWriter: rec, err: errors.New("client went away")}

	Write(w, http.StatusOK, map[string]string{"k": "v"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want nothing to have reached the recorder", rec.Body.String())
	}
}
