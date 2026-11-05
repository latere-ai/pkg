// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"encoding/json/v2"
	"testing"
)

func TestRequestWireBytes(t *testing.T) {
	req := Request{
		Subject: "https://iss|alice", Issuer: "https://iss", Sub: "alice",
		Claims:   map[string]any{"z": 1, "a": []string(nil), "m": map[string]any{"y": 2, "x": 1}},
		Action:   "repo.read",
		Resource: NewResource("Repository", "r1", map[string]any{"owner": "alice", "labels": map[string]string(nil)}),
		Request:  Caller{ID: "req", IP: "10.0.0.1"},
	}
	got, err := json.Marshal(req, wireJSON)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"subject":"https://iss|alice","issuer":"https://iss","sub":"alice","claims":{"a":null,"m":{"x":1,"y":2},"z":1},"action":"repo.read","resource":{"id":"r1","kind":"Repository","labels":null,"owner":"alice"},"request":{"id":"req","ip":"10.0.0.1","user_agent":""}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestRequestWithNilClaimsWritesAnObject(t *testing.T) {
	got, err := json.Marshal(Request{Action: "a"}, wireJSON)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"subject":"","issuer":"","sub":"","claims":{},"action":"a","resource":{"kind":""},"request":{"id":"","ip":"","user_agent":""}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParseDecisionAcceptsDuplicateNamesAndMixedCase(t *testing.T) {
	d, err := ParseDecision([]byte(`{"allow":false,"ALLOW":true,"Reason":"ok","ttl":5}`))
	if err != nil || !d.Allow || d.Reason != "ok" {
		t.Errorf("got %+v %v", d, err)
	}
}
