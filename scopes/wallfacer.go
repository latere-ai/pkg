// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package scopes

// ProjectsRead is the default scope auth assigns a newly registered agent
// principal (AGENT_DEFAULT_SCOPES). It is advertised here so the admin scope
// picker and OIDC discovery can name it.
var ProjectsRead = Scope{Name: "read:projects", Description: "List and read projects.", Category: "Wallfacer"}

func wallfacer() []Scope { return []Scope{ProjectsRead} }
