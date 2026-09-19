// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"encoding/json"
	"testing"
)

func TestFingerprintPreservesIntegerPrecision(t *testing.T) {
	a, err := requestFingerprint([]byte(`{"claims":{"number":9007199254740992},"request":{"id":"a"}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := requestFingerprint([]byte(`{"claims":{"number":9007199254740993},"request":{"id":"a"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("integer claims rounded into the same cache key")
	}
	for _, bad := range []string{`{`, `[]`, `null`, `{"request":"bad"}`, `{}`} {
		if _, err := requestFingerprint([]byte(bad)); err == nil {
			t.Fatalf("invalid envelope %s accepted", bad)
		}
	}
}
func FuzzRequestFingerprint(f *testing.F) {
	f.Add([]byte(`{"claims":{"large":9007199254740993},"request":{"id":"a","ip":"192.0.2.1"}}`))
	f.Add([]byte(`not-json`))
	f.Fuzz(func(t *testing.T, body []byte) {
		first, err := requestFingerprint(body)
		if err != nil {
			return
		}
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatal(err)
		}
		var caller map[string]json.RawMessage
		if err := json.Unmarshal(envelope["request"], &caller); err != nil {
			t.Fatal(err)
		}
		if caller == nil {
			caller = map[string]json.RawMessage{}
		}
		caller["id"] = json.RawMessage(`"different-correlation"`)
		envelope["request"], _ = json.Marshal(caller)
		again, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		second, err := requestFingerprint(again)
		if err != nil {
			t.Fatal(err)
		}
		// A null caller becomes an empty object when it acquires an ID; production
		// Caller is always an object. Compare only original object-valued callers.
		var original map[string]json.RawMessage
		_ = json.Unmarshal(body, &original)
		if string(original["request"]) != "null" && first != second {
			t.Fatalf("correlation changed fingerprint for %s", body)
		}
	})
}
