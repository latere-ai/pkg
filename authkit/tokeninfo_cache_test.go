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
			_, _ = w.Write([]byte(`{"sub":"svc-1","principal_type":"service","org_id":"org-9"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return NewTokenInfoClient(srv.URL), &hits
}

// richTokenInfo serves a verdict carrying every field shape the cache must
// copy rather than share: scalars plus both slices.
func richTokenInfo(t *testing.T, verdicts map[string]int) (*TokenInfoClient, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		status, ok := verdicts[r.Header.Get("Authorization")]
		if !ok {
			status = http.StatusUnauthorized
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"sub":"svc-1","principal_type":"service","org_id":"org-9",` +
				`"scopes":["read","write"],"roles":["member"]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return NewTokenInfoClient(srv.URL), &hits
}

func TestCloneTokenInfoNil(t *testing.T) {
	if got := cloneTokenInfo(nil); got != nil {
		t.Fatalf("cloneTokenInfo(nil) = %#v, want nil", got)
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

// TestCachedTokenInfoSharedPointerPoisoning pins that a caller mutating the
// *TokenInfo it received cannot poison the cached verdict served to the next
// caller. Both the value stored and the value returned must be copies.
func TestCachedTokenInfoSharedPointerPoisoning(t *testing.T) {
	client, hits := richTokenInfo(t, map[string]int{"Bearer good": http.StatusOK})
	c := NewCachedTokenInfo(client, time.Minute)

	first, err := c.Lookup(context.Background(), "good")
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	// A caller mutates its own copy — scalar and slice elements alike.
	first.OrgID = "attacker-owned"
	first.Scopes[0] = "admin"
	first.Roles[0] = "admin"

	second, err := c.Lookup(context.Background(), "good")
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1 (must be a cache hit, not a refetch)", got)
	}
	if second.OrgID != "org-9" {
		t.Fatalf("cached verdict poisoned: org_id = %q, want org-9", second.OrgID)
	}
	if second.Scopes[0] != "read" {
		t.Fatalf("cached scopes poisoned: scopes[0] = %q, want read", second.Scopes[0])
	}
	if second.Roles[0] != "member" {
		t.Fatalf("cached roles poisoned: roles[0] = %q, want member", second.Roles[0])
	}
}

func TestCachedTokenInfoReusesPositiveVerdict(t *testing.T) {
	client, hits := countingTokenInfo(t, map[string]int{"Bearer good": http.StatusOK})
	c := NewCachedTokenInfo(client, time.Minute)

	for i := 0; i < 3; i++ {
		ti, err := c.Lookup(context.Background(), "good")
		if err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
		if ti.Sub != "svc-1" {
			t.Fatalf("sub = %q, want svc-1", ti.Sub)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1 (cache must absorb repeats)", got)
	}
}
