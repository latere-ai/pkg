// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpjson

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteErrorRendersTheEnvelope(t *testing.T) {
	w := httptest.NewRecorder()
	WriteError(w, http.StatusConflict, Error{Code: "repo_exists", Message: "A repository with this id exists."})
	if w.Code != http.StatusConflict || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if got := w.Body.String(); got != `{"error":{"code":"repo_exists","message":"A repository with this id exists."}}`+"\n" {
		t.Fatalf("body = %s", got)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.Error.Code != "repo_exists" || env.Error.Details != nil {
		t.Fatalf("decoded %+v, %v", env, err)
	}
}

func TestWriteErrorCarriesDetailsOnlyWhenPresent(t *testing.T) {
	w := httptest.NewRecorder()
	WriteError(w, http.StatusServiceUnavailable, Error{
		Code: "storage_unavailable", Message: "Files are unavailable right now.",
		Details: map[string]any{"op": "s3 HeadObject", "attempt": 3},
	})
	var env ErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Details["op"] != "s3 HeadObject" || env.Error.Details["attempt"] != float64(3) {
		t.Fatalf("details = %v", env.Error.Details)
	}
}
