// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSubjectIsIssuerQualified(t *testing.T) {
	if got := Subject("https://auth.example.com/", "u1"); got != "https://auth.example.com|u1" {
		t.Fatalf("rendered %q", got)
	}
	if Subject("https://auth.example.com", "") != "" {
		t.Fatal("an empty sub is the anonymous subject")
	}
	// Two issuers agreeing on a sub are two subjects.
	if Subject("https://a", "u1") == Subject("https://b", "u1") {
		t.Fatal("two issuers rendered one subject")
	}
	iss, sub, ok := SplitSubject("https://auth.example.com|u1")
	if !ok || iss != "https://auth.example.com" || sub != "u1" {
		t.Fatalf("split: %q %q %v", iss, sub, ok)
	}
	// A sub that carries a pipe splits on the last one, since an issuer
	// URL never carries one.
	iss, sub, ok = SplitSubject("https://a|x|y")
	if !ok || iss != "https://a|x" || sub != "y" {
		t.Fatalf("split on the last pipe: %q %q", iss, sub)
	}
	for _, bare := range []string{"", "u1"} {
		if _, _, ok := SplitSubject(bare); ok {
			t.Fatalf("%q split", bare)
		}
	}
}

func FuzzSplitSubject(f *testing.F) {
	f.Add("https://a|b")
	f.Add("")
	f.Add("|")
	f.Fuzz(func(t *testing.T, s string) {
		iss, sub, ok := SplitSubject(s)
		if ok && Subject(iss, sub) != s && sub != "" {
			// Rendering trims a trailing slash of the issuer, so a subject
			// whose issuer half ends in one does not round-trip; every
			// other one does.
			if iss[len(iss)-1] != '/' {
				t.Fatalf("%q split to %q %q and rendered differently", s, iss, sub)
			}
		}
	})
}

func TestResourceIsOneFlatObject(t *testing.T) {
	r := NewResource("Repository", "r1", map[string]any{"owner": "acme", "slug": "app", "kind": "ignored", "id": "ignored"})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(b, &flat); err != nil {
		t.Fatal(err)
	}
	if flat["kind"] != "Repository" || flat["id"] != "r1" || flat["owner"] != "acme" || flat["slug"] != "app" || len(flat) != 4 {
		t.Fatalf("flat object: %v", flat)
	}
	var back Resource
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Kind != "Repository" || back.ID != "r1" || back.String("owner") != "acme" || back.String("missing") != "" {
		t.Fatalf("round trip: %+v", back)
	}
	// A create carries no id.
	b, _ = json.Marshal(NewResource("Repository", "", nil))
	if string(b) != `{"kind":"Repository"}` {
		t.Fatalf("create: %s", b)
	}
	var page Resource
	if err := json.Unmarshal([]byte(`{"kind":"Repository","limit":50,"cursor":"c"}`), &page); err != nil {
		t.Fatal(err)
	}
	if page.Int("limit") != 50 || page.Int("cursor") != 0 || page.String("cursor") != "c" {
		t.Fatalf("page fields: %+v", page)
	}
	if (Resource{Fields: map[string]any{"n": 3}}).Int("n") != 3 {
		t.Fatal("an int field reads as itself")
	}
	if err := json.Unmarshal([]byte(`[]`), &page); err == nil {
		t.Fatal("an array is not a resource")
	}
}

func FuzzResourceUnmarshal(f *testing.F) {
	f.Add(`{"kind":"Repository","id":"r1","owner":"a"}`)
	f.Add(`{}`)
	f.Add(`{"kind":1,"id":2}`)
	f.Fuzz(func(t *testing.T, s string) {
		var r Resource
		if err := json.Unmarshal([]byte(s), &r); err != nil {
			return
		}
		if _, err := json.Marshal(r); err != nil {
			t.Fatalf("%q decoded and did not encode: %v", s, err)
		}
	})
}

func TestParseDecisionAppliesTheDefaults(t *testing.T) {
	d, err := ParseDecision([]byte(`{"allow":true}`))
	if err != nil || !d.Allow || d.TTL != DefaultTTL || d.Limits != nil || d.Filter != nil {
		t.Fatalf("defaults: %+v %v", d, err)
	}
	d, err = ParseDecision([]byte(`{"allow":true,"ttl":9000,"limits":{"replicas":3},"filter":{"owners":["a"],"labels":{"k":"v"}}}`))
	if err != nil || d.TTL != MaxTTL || d.Filter == nil || d.Filter.Owners[0] != "a" || d.Filter.Labels["k"] != "v" {
		t.Fatalf("capped ttl and filter: %+v %v", d, err)
	}
	var limits struct {
		Replicas int `json:"replicas"`
	}
	if err := d.DecodeLimits(&limits); err != nil || limits.Replicas != 3 {
		t.Fatalf("limits: %+v %v", limits, err)
	}
	d, err = ParseDecision([]byte(`{"allow":false,"reason":"no","ttl":-1,"limits":null}`))
	if err != nil || d.Allow || d.Reason != "no" || d.TTL != DefaultTTL || d.Limits != nil {
		t.Fatalf("deny: %+v %v", d, err)
	}
	if err := d.DecodeLimits(&limits); err != nil {
		t.Fatal("no limits is not an error")
	}
	if _, err := ParseDecision([]byte(`{"reason":"no verdict"}`)); err == nil {
		t.Fatal("a body with no allow field is no answer")
	}
	if _, err := ParseDecision([]byte(`{`)); err == nil {
		t.Fatal("a body that does not parse is no answer")
	}
}

// fakeAuthorizer answers a fixed decision or error.
type fakeAuthorizer struct {
	d   Decision
	err error
	got Request
}

func (f *fakeAuthorizer) Authorize(_ context.Context, req Request) (Decision, error) {
	f.got = req
	return f.d, f.err
}

func TestCheckSendsTheProbeAndReadsAnAllowAsAFault(t *testing.T) {
	ctx := context.Background()
	f := &fakeAuthorizer{d: Decision{Reason: "probe"}}
	if err := Check(ctx, f, "repo.read", "Repository"); err != nil {
		t.Fatalf("a deny is the right answer: %v", err)
	}
	if f.got.Subject != "" || f.got.Resource.ID != ProbeID || f.got.Resource.Kind != "Repository" || f.got.Action != "repo.read" {
		t.Fatalf("probe: %+v", f.got)
	}
	f.d = Decision{Allow: true}
	if err := Check(ctx, f, "repo.read", "Repository"); !errors.Is(err, ErrProbeAllowed) {
		t.Fatalf("an allow: %v", err)
	}
	f.err = &Unavailable{URL: "u", Status: 500}
	if err := Check(ctx, f, "repo.read", "Repository"); err == nil || err.Error() != "authz: authorizer answered 500" {
		t.Fatalf("an outage: %v", err)
	}
	if (&Unavailable{URL: "u", Err: errors.New("dial")}).Error() != "authz: authorizer unavailable: dial" {
		t.Fatal("the error text")
	}
	if Timeout != 5*time.Second || DefaultTTL != 60*time.Second || MaxTTL != 600*time.Second || DenyTTL != 5*time.Second || CacheEntries != 65536 {
		t.Fatal("the contract's figures changed")
	}
}
