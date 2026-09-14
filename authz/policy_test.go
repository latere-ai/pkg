// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"slices"
	"testing"
)

// TestOwnerPolicy is the owner policy's table: every row of the list a
// core builds in when no authorizer is configured.
func TestOwnerPolicy(t *testing.T) {
	const (
		alice = "https://iss|alice"
		bob   = "https://iss|bob"
		root  = "https://iss|root"
	)
	p := Policy{Admins: []string{root}, Create: "repo.admin"}
	owned := Object{Exists: true, Owner: alice}
	none := Object{}
	req := func(subject, action, id string) Request {
		return Request{Subject: subject, Action: action, Resource: Resource{Kind: "Repository", ID: id}}
	}
	for _, tc := range []struct {
		name   string
		req    Request
		obj    Object
		allow  bool
		reason string
	}{
		{"the probe is denied for everybody", req(root, "repo.read", ProbeID), none, false, ReasonProbe},
		{"the probe is denied whatever the case of the id", req(alice, "repo.read", "00000000-0000-0000-0000-000000000001"), owned, false, ReasonProbe},
		{"anonymous is denied", req("", "repo.read", "r1"), owned, false, ReasonAnonymous},
		{"anonymous cannot create", req("", "repo.admin", "r1"), none, false, ReasonAnonymous},
		{"an admin reads everything", req(root, "repo.read", "r1"), owned, true, ""},
		{"an admin administers what does not exist", req(root, "repo.admin", "r1"), none, true, ""},
		{"the owner reads its own", req(alice, "repo.read", "r1"), owned, true, ""},
		{"the owner writes its own", req(alice, "repo.write", "r1"), owned, true, ""},
		{"the owner administers its own", req(alice, "repo.admin", "r1"), owned, true, ""},
		{"a stranger is refused", req(bob, "repo.read", "r1"), owned, false, ReasonNotOwner},
		{"a subject may create under an id it chose", req(bob, "repo.admin", "r2"), none, true, ""},
		{"a subject may create with no id, as a create carries none on the wire", req(bob, "repo.admin", ""), none, true, ""},
		{"anonymous cannot create with no id either", req("", "repo.admin", ""), none, false, ReasonAnonymous},
		{"a read of an unknown id is refused like a stranger's", req(bob, "repo.read", "r2"), none, false, ReasonNotOwner},
		{"an unresolved name under another action is refused", req(bob, "repo.write", ""), none, false, ReasonNotOwner},
		{"a name that resolves to another's object is refused under the create action too", req(bob, "repo.admin", ""), owned, false, ReasonNotOwner},
		{"a list names no id and is refused to a non-admin", req(bob, "repo.list", ""), none, false, ReasonNotOwner},
	} {
		d := p.Decide(tc.req, tc.obj)
		if d.Allow != tc.allow || d.Reason != tc.reason {
			t.Errorf("%s: %+v", tc.name, d)
		}
	}
	// A policy that names no create action allows creation to nobody but
	// an admin, with or without an id.
	for _, id := range []string{"r2", ""} {
		if d := (Policy{}).Decide(req(bob, "repo.admin", id), none); d.Allow {
			t.Fatalf("no create action and a creation with id %q was allowed", id)
		}
	}
}

func TestParseSubjects(t *testing.T) {
	got := ParseSubjects(" https://a|x , ,https://b|y,")
	if !slices.Equal(got, []string{"https://a|x", "https://b|y"}) {
		t.Fatalf("parsed %v", got)
	}
	if ParseSubjects("") != nil {
		t.Fatal("an empty list is nil")
	}
}
