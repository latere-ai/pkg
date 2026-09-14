// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"strconv"

	"latere.ai/x/pkg/llmdialect"
	"latere.ai/x/pkg/llmdialect/anthropic"
	"latere.ai/x/pkg/llmdialect/lux"
	"latere.ai/x/pkg/llmdialect/openaichat"
	"latere.ai/x/pkg/llmdialect/tokencount"
)

// frontendForWire is the caller-side codec that reads a wire's request
// body: Chat Completions for WireOpenAI, whose count has no route of
// its own; nil for WireGoogle, which has no codec.
func frontendForWire(w Wire) llmdialect.Frontend {
	switch w {
	case WireOpenAI:
		return openaichat.NewFrontend()
	case WireAnthropic:
		return anthropic.NewFrontend()
	case WireLux:
		return lux.NewFrontend()
	}
	return nil
}

// CountTokens emulates a count for a wire whose upstream cannot answer
// one: body is decoded with the wire's frontend and estimated with
// tokencount.Estimate. estimated is true whenever the answer came from
// the estimator, which is always today; the return exists so a wire
// that gains an exact count can say so. A body the frontend cannot read
// is DecodeRequest; a wire with no frontend, which is WireGoogle, is
// Unsupported.
func CountTokens(w Wire, body []byte) (n int64, estimated bool, err error) {
	fe := frontendForWire(w)
	if fe == nil {
		return 0, false, &Error{Code: Unsupported, Detail: "no frontend codec for wire " + quote(string(w))}
	}
	req, err := fe.DecodeRequest(body)
	if err != nil {
		return 0, false, wrap(DecodeRequest, err)
	}
	return tokencount.Estimate(req), true, nil
}

// CountBody renders the count answer in the wire's shape, one trailing
// newline: {"input_tokens":n} for WireAnthropic and WireLux,
// {"totalTokens":n} for WireGoogle. WireOpenAI has no count route and
// renders nil.
func CountBody(w Wire, n int64) []byte {
	switch w {
	case WireAnthropic, WireLux:
		return []byte(`{"input_tokens":` + strconv.FormatInt(n, 10) + "}\n")
	case WireGoogle:
		return []byte(`{"totalTokens":` + strconv.FormatInt(n, 10) + "}\n")
	}
	return nil
}
