// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

// AllowedEnvironment lists every variable a stage may inherit from the process
// that launches it. It holds what a shell, a package manager and a program
// need in order to run at all: where executables are, the locale and time
// zone, where scratch files go, who the user is, and which trust store to
// verify TLS against. HOME and TERM are absent because the driver sets them.
//
// It is a table checked by a test rather than a comment: passing a stage the
// whole process environment is how an exported vendor key or cloud secret
// reaches a program that runs with its permission prompts bypassed.
var AllowedEnvironment = []string{
	"PATH",
	"LANG", "LANGUAGE",
	"LC_ALL", "LC_COLLATE", "LC_CTYPE", "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME",
	"TZ",
	"TMPDIR",
	"USER", "LOGNAME",
	"SHELL",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// Environment builds the environment a stage starts from by looking up each
// name in AllowedEnvironment, so there is no way to hand the driver a raw
// process environment. A composition root passes os.LookupEnv. An unset
// variable is absent rather than present and empty. A nil lookup yields nil,
// which the Driver refuses to launch a stage with.
func Environment(lookup func(string) (string, bool)) []string {
	if lookup == nil {
		return nil
	}
	environment := make([]string, 0, len(AllowedEnvironment))
	for _, name := range AllowedEnvironment {
		if value, ok := lookup(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}
