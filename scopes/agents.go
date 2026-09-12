// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package scopes

// Agent-API scopes gate the topos agent surface: listing and inspecting
// agents, changing them, starting a session and attaching to it, and
// administering them across principals. They are scopes on a product's API,
// not a principal type: auth mints no agent principal.
var (
	AgentsRead  = Scope{Name: "read:agents", Description: "List and inspect agents and their runs.", Category: "Agents"}
	AgentsWrite = Scope{Name: "write:agents", Description: "Create, update, and delete agents.", Category: "Agents"}
	AgentsRun   = Scope{Name: "run:agents", Description: "Start agent sessions and attach to them.", Category: "Agents"}
	AgentsAdmin = Scope{Name: "admin:agents", Description: "Administer agents across principals.", Category: "Agents"}
)

func agents() []Scope { return []Scope{AgentsRead, AgentsWrite, AgentsRun, AgentsAdmin} }
