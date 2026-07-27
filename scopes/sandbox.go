package scopes

// Sandbox scopes gate every /v1/sandboxes/* operation in the sandbox
// service. write implies read; admin is reserved for lifecycle ops
// like force-stop and disk resize. attach is held separately from
// exec so the default agent flow (programmatic POST /commands) does
// not implicitly carry interactive-shell privileges.
var (
	SandboxRead   = Scope{Name: "read:sandbox", Description: "List and inspect sandboxes.", Category: "Sandbox"}
	SandboxWrite  = Scope{Name: "write:sandbox", Description: "Create, update, and delete sandboxes.", Category: "Sandbox"}
	SandboxExec   = Scope{Name: "exec:sandbox", Description: "Execute commands inside a sandbox.", Category: "Sandbox"}
	SandboxAttach = Scope{Name: "attach:sandbox", Description: "Open interactive PTY sessions inside a sandbox.", Category: "Sandbox"}
	SandboxAdmin  = Scope{Name: "admin:sandbox", Description: "Lifecycle ops: force-stop, disk resize, evictions.", Category: "Sandbox"}
	SandboxSpawn  = Scope{Name: "sandbox:spawn", Description: "Autonomous sandbox-to-sandbox spawning under a propagated budget.", Category: "Sandbox"}
)

func sandbox() []Scope {
	return []Scope{SandboxRead, SandboxWrite, SandboxExec, SandboxAttach, SandboxAdmin, SandboxSpawn}
}
