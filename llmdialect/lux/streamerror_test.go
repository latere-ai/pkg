// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package lux_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect/bridge"
	"latere.ai/x/pkg/llmdialect/lux"
)

// TestStreamReaderReadsTheGatewaysErrorFrame decodes the frame the
// gateway writes when a stream fails after its first byte, built by the
// same bridge.ErrorFrame call, so the reader cannot drift from the
// writer. It lives outside package lux because bridge imports lux.
func TestStreamReaderReadsTheGatewaysErrorFrame(t *testing.T) {
	frame := bridge.ErrorFrame(bridge.WireLux, bridge.Failure{
		Code:      "upstream_error",
		Message:   "The model's provider failed.",
		Detail:    "anthropic: 529 overloaded",
		RequestID: "req_01ABC",
	})
	_, err := lux.NewStreamReader(bytes.NewReader(frame)).Next()
	var se *lux.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("want StreamError, got %v", err)
	}
	want := lux.StreamError{Code: "upstream_error", Message: "The model's provider failed.", Detail: "anthropic: 529 overloaded", RequestID: "req_01ABC"}
	if *se != want {
		t.Fatalf("got %+v, want %+v", *se, want)
	}
	for _, part := range []string{"upstream_error", "The model's provider failed.", "anthropic: 529 overloaded", "req_01ABC"} {
		if !strings.Contains(se.Error(), part) {
			t.Errorf("Error() = %q, missing %q", se.Error(), part)
		}
	}
}
