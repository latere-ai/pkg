// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package openaichat

import (
	"reflect"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// TestDecodeUsageCacheWrites: OpenRouter reports the tokens a request
// wrote to the provider's cache in cache_write_tokens and counts them
// in prompt_tokens; they are cache writes, billed at their own rate,
// and not fresh input.
func TestDecodeUsageCacheWrites(t *testing.T) {
	usage := `{"prompt_tokens":26799,"completion_tokens":8,"prompt_tokens_details":{"cached_tokens":0,"cache_write_tokens":26797}}`
	want := ir.Usage{InputTokens: 2, OutputTokens: 8, CacheReadInputTokens: i64(0), CacheWriteInputTokens: i64(26797)}
	resp, err := NewBackend(BackendOptions{}).DecodeResponse([]byte(`{"id":"x","choices":[{"message":{"content":"y"}}],"usage":` + usage + `}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.Usage, want) {
		t.Fatalf("buffered usage = %+v want %+v", resp.Usage, want)
	}
	events := drain(t, chunk(`{"id":"x","choices":[],"usage":`+usage+`}`)+chunk(`[DONE]`))
	if got := events[1].Usage; got == nil || !reflect.DeepEqual(*got, want) {
		t.Fatalf("stream usage = %+v want %+v", got, want)
	}
}

// TestFrontendUsageCountsCacheWrites: a translated answer's cache
// writes are part of prompt_tokens and reported beside the reads, so a
// caller of this dialect sees the whole prompt and what it cost to
// cache.
func TestFrontendUsageCountsCacheWrites(t *testing.T) {
	got := encodeFrontUsage(ir.Usage{InputTokens: 2, OutputTokens: 8, CacheReadInputTokens: i64(100), CacheWriteInputTokens: i64(30)})
	want := map[string]any{
		"prompt_tokens": int64(132), "completion_tokens": int64(8), "total_tokens": int64(140),
		"prompt_tokens_details":     map[string]any{"cached_tokens": int64(100), "cache_write_tokens": int64(30)},
		"completion_tokens_details": map[string]any{"reasoning_tokens": int64(0)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("usage:\n got %v\nwant %v", got, want)
	}
}
