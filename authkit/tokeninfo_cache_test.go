package authkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// countingTokenInfo serves /tokeninfo verdicts keyed by bearer token and
// counts hits, so tests can assert what the cache absorbed.
func countingTokenInfo(t *testing.T, verdicts map[string]int) (*TokenInfoClient, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		tok := r.Header.Get("Authorization")
		status, ok := verdicts[tok]
		if !ok {
			status = http.StatusUnauthorized
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"sub":"agent-1","principal_type":"agent","grantor_id":"owner-9"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return NewTokenInfoClient(srv.URL), &hits
}

func TestCachedTokenInfoReusesPositiveVerdict(t *testing.T) {
	client, hits := countingTokenInfo(t, map[string]int{"Bearer good": http.StatusOK})
	c := NewCachedTokenInfo(client, time.Minute)

	for i := 0; i < 3; i++ {
		ti, err := c.Lookup(context.Background(), "good")
		if err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
		if ti.Delegator() != "owner-9" {
			t.Fatalf("delegator = %q", ti.Delegator())
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1 (cache must absorb repeats)", got)
	}
}

func TestCachedTokenInfoExpiry(t *testing.T) {
	client, hits := countingTokenInfo(t, map[string]int{"Bearer good": http.StatusOK})
	c := NewCachedTokenInfo(client, 30*time.Second)
	base := time.Now()
	c.now = func() time.Time { return base }

	if _, err := c.Lookup(context.Background(), "good"); err != nil {
		t.Fatal(err)
	}
	// Within TTL: cached.
	c.now = func() time.Time { return base.Add(29 * time.Second) }
	if _, err := c.Lookup(context.Background(), "good"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d before expiry, want 1", hits.Load())
	}
	// Past TTL: revalidates online.
	c.now = func() time.Time { return base.Add(31 * time.Second) }
	if _, err := c.Lookup(context.Background(), "good"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d after expiry, want 2", hits.Load())
	}
}

func TestCachedTokenInfoNeverCachesNegatives(t *testing.T) {
	client, hits := countingTokenInfo(t, map[string]int{}) // everything 401s
	c := NewCachedTokenInfo(client, time.Minute)

	for i := 0; i < 3; i++ {
		if _, err := c.Lookup(context.Background(), "revoked"); err == nil {
			t.Fatalf("lookup %d: expected error", i)
		}
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("upstream hits = %d, want 3 (negatives must not cache)", got)
	}
}

func TestCachedTokenInfoBounded(t *testing.T) {
	verdicts := map[string]int{}
	for _, tok := range []string{"a", "b", "c"} {
		verdicts["Bearer "+tok] = http.StatusOK
	}
	client, _ := countingTokenInfo(t, verdicts)
	c := NewCachedTokenInfo(client, time.Minute)
	c.MaxEntries = 2

	for _, tok := range []string{"a", "b", "c"} {
		if _, err := c.Lookup(context.Background(), tok); err != nil {
			t.Fatalf("lookup %s: %v", tok, err)
		}
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > 2 {
		t.Fatalf("cache grew to %d entries, bound is 2", n)
	}
}

func TestTokenInfoDelegatorFallback(t *testing.T) {
	// grantor_id wins; act is the fallback; neither → empty.
	act := &struct {
		Sub string `json:"sub"`
	}{Sub: "owner-act"}
	cases := []struct {
		ti   TokenInfo
		want string
	}{
		{TokenInfo{GrantorID: "owner-flat", Act: act}, "owner-flat"},
		{TokenInfo{Act: act}, "owner-act"},
		{TokenInfo{}, ""},
	}
	for i, tc := range cases {
		if got := tc.ti.Delegator(); got != tc.want {
			t.Errorf("case %d: Delegator() = %q, want %q", i, got, tc.want)
		}
	}
}
