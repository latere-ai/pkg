// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"slices"
	"strings"
)

// The owner policy: what a core decides when no authorizer is configured.
//
// A self-hosted core needs no service to be usable, so the contract names
// one policy every core builds in: an owner acts on its own objects,
// admins act on every object, a subject may create, the probe and the
// anonymous subject are denied. The core looks the object up and hands
// the policy what it found; the policy is a pure function over the
// request and that Object, and it reads no claim.

// Policy is the owner policy's frame.
type Policy struct {
	// Admins are the rendered subjects allowed every action on every
	// object.
	Admins []string
	// Create is the action of the core's vocabulary that creates an
	// object. It is the one action allowed on an object that does not
	// exist, whether the request names an id, the one the caller chose
	// for the new object, or none, as a create on the wire carries none;
	// every other action on an unknown object is refused with the same
	// reason as an object the subject does not own, so a deny does not
	// disclose whether the object exists.
	Create string
}

// Object is what the core found when it looked the resource up.
type Object struct {
	// Exists reports whether the resource's id names an object.
	Exists bool
	// Owner is the rendered subject that created it.
	Owner string
}

// The reasons the owner policy denies with.
const (
	ReasonProbe     = "probe"
	ReasonAnonymous = "anonymous"
	ReasonNotOwner  = "not_owner"
)

// Decide answers one request. The rows, in order:
//
//  1. the probe id is denied for every subject;
//  2. the anonymous subject is denied;
//  3. an admin is allowed everything;
//  4. the owner of an object that exists is allowed;
//  5. the Create action on an object that does not exist is allowed, so a
//     subject may create, with no id, as a create carries none on the
//     wire, or with the id the caller chose for the new object;
//  6. everything else is denied as not_owner: another subject's object,
//     an unknown id or an unresolved name under any other action.
func (p Policy) Decide(req Request, obj Object) Decision {
	switch {
	case strings.EqualFold(req.Resource.ID, ProbeID):
		return Decision{Reason: ReasonProbe}
	case req.Subject == "":
		return Decision{Reason: ReasonAnonymous}
	case slices.Contains(p.Admins, req.Subject):
		return Decision{Allow: true}
	case obj.Exists && obj.Owner == req.Subject:
		return Decision{Allow: true}
	case !obj.Exists && p.Create != "" && req.Action == p.Create:
		return Decision{Allow: true}
	}
	return Decision{Reason: ReasonNotOwner}
}

// ParseSubjects reads a comma-separated list of rendered subjects, the
// form an environment variable carries, trimming each and dropping
// empties.
func ParseSubjects(raw string) []string {
	var out []string
	for s := range strings.SplitSeq(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
