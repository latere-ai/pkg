package scopes

// Wallfacer scopes gate the wallfacer agent's project and task APIs.
// They live here (not in wallfacer's own repo) so the auth service
// can advertise them in /admin/scopes without having to import an
// external module.
var (
	ProjectsRead = Scope{Name: "read:projects", Description: "List and read projects.", Category: "Wallfacer"}
	TasksAdmin   = Scope{Name: "admin:tasks", Description: "Manage tasks across projects.", Category: "Wallfacer"}
)

func wallfacer() []Scope { return []Scope{ProjectsRead, TasksAdmin} }
