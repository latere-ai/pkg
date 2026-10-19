// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// launchOnlyVariable names a request file that makes this test binary launch
// one stage and exit at once, so a test can watch a stage outlive the
// process that launched it.
const launchOnlyVariable = "HOSTSANDBOX_TEST_LAUNCH"

// launchRequest is what a test asks the launch-only process to start.
type launchRequest struct {
	Home   string    `json:"home"`
	Spec   StageSpec `json:"spec"`
	Local  bool      `json:"local"`
	Handle string    `json:"handle"`
}

// TestMain makes this test binary a program that calls Main, as a consumer's
// is: the driver starts it again as a stage's launcher.
func TestMain(m *testing.M) {
	Main()
	if path, ok := os.LookupEnv(launchOnlyVariable); ok {
		os.Exit(launchOnly(path))
	}
	os.Exit(m.Run())
}

// launchOnly launches the stage the request file names under Seatbelt,
// writes its handle where the request says, and returns.
func launchOnly(path string) int {
	body, err := os.ReadFile(path) //nolint:gosec // the test's own request file
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var request launchRequest
	if err := json.Unmarshal(body, &request); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	localDestinations = request.Local
	driver := New(Config{Isolation: IsolationSeatbelt, Home: request.Home, Lookup: os.LookupEnv})
	handle, err := driver.Launch(context.Background(), request.Spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	encoded, err := json.Marshal(handle)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(request.Handle, encoded, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
