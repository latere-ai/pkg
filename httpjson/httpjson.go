// Package httpjson provides helpers for decoding JSON request bodies and
// writing JSON responses in HTTP handlers.
package httpjson

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

// DecodeBody decodes the JSON request body into a new T. It rejects unknown
// fields and trailing tokens after the first JSON object, writing a 400
// response on any error. Returns (*T, true) on success or (nil, false) on error.
func DecodeBody[T any](w http.ResponseWriter, r *http.Request) (*T, bool) {
	v := new(T)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			Write(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
			return nil, false
		}
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	if !finishDecode(w, dec) {
		return nil, false
	}
	return v, true
}

// DecodeOptionalBody decodes the JSON request body into a new T when a body is
// present. An absent or empty body is silently accepted and returns a zero-value
// T pointer. When a body is present the same strict rules apply as
// DecodeBody: unknown fields and trailing tokens are rejected with a 400.
func DecodeOptionalBody[T any](w http.ResponseWriter, r *http.Request) (*T, bool) {
	if r == nil || r.Body == nil {
		return new(T), true
	}
	v := new(T)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return new(T), true // empty body — treat as no body provided
		}
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			Write(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
			return nil, false
		}
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	if !finishDecode(w, dec) {
		return nil, false
	}
	return v, true
}

func finishDecode(w http.ResponseWriter, dec *json.Decoder) bool {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return true
	}
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		Write(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return false
	}
	if err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	http.Error(w, "invalid JSON: unexpected trailing content", http.StatusBadRequest)
	return false
}

// Write serialises v as JSON and writes it with the given HTTP status code.
//
// v is marshalled in full before any byte of the response is committed, so a
// value that cannot be encoded answers 500 rather than the requested status
// followed by a truncated body. Committing the status first is the tempting
// shape -- it streams, and it needs no buffer -- but it makes the one failure
// that matters invisible: the client reads a success status and an empty or
// half-written body, and has no way to tell that apart from a legitimately
// empty result.
//
// The 500 is plain text. This package has no opinion on what an error body
// should look like, and every service that uses it has its own envelope; a
// caller that cares should marshal-check the value itself rather than inherit
// a shape from here.
//
// The encoded body keeps the trailing newline that [json.Encoder.Encode]
// writes, so the bytes on the wire are unchanged for values that marshal.
func Write[T any](w http.ResponseWriter, status int, v T) {
	body, err := json.Marshal(v)
	if err != nil {
		slog.Error("write json", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	body = append(body, '\n')

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		slog.Error("write json", "error", err)
	}
}

// PathUUID parses a UUID from the named path segment, writing a 400
// response on failure. Returns (parsed, true) on success or
// (uuid.Nil, false) on missing/malformed input. name is the path
// parameter name (e.g. "id" for routes like "/api/tasks/{id}/...").
func PathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	raw := r.PathValue(name)
	if raw == "" {
		http.Error(w, "missing "+name, http.StatusBadRequest)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		http.Error(w, "invalid "+name+": "+err.Error(), http.StatusBadRequest)
		return uuid.Nil, false
	}
	return id, true
}
