package scopes

// Policy scopes gate write operations against the policy engine
// (currently consumed by the sandbox service for ABAC rule changes).
var (
	PolicyWrite = Scope{Name: "policy:write", Description: "Create and update policy rules.", Category: "Policy"}
)

func policy() []Scope { return []Scope{PolicyWrite} }
