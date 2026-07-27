package scopes

// Agent-API scopes gate the topos agent surface: sessions, attach, and the
// RFC 8693 exchange to an agent principal.
var (
	AgentsRead  = Scope{Name: "read:agents", Description: "List and inspect agents and their runs.", Category: "Agents"}
	AgentsWrite = Scope{Name: "write:agents", Description: "Create, update, and delete agents.", Category: "Agents"}
	AgentsRun   = Scope{Name: "run:agents", Description: "Start agent sessions and attach to them.", Category: "Agents"}
	AgentsAdmin = Scope{Name: "admin:agents", Description: "Administer agents across principals.", Category: "Agents"}
)

func agents() []Scope { return []Scope{AgentsRead, AgentsWrite, AgentsRun, AgentsAdmin} }
