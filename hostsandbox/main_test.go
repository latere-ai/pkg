// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"
)

// launchOnlyVariable names a request file that makes this test binary launch
// one stage and exit at once, so a test can watch a stage outlive the
// process that launched it.
const launchOnlyVariable = "HOSTSANDBOX_TEST_LAUNCH"

// verifyVariable names a certificate chain that makes this test binary,
// running as a stage, verify the chain through the operating system's
// verifier, as a TLS client on macOS does, and exit.
const verifyVariable = "HOSTSANDBOX_TEST_VERIFY"

// verifiedAt is a time inside the captured chain's validity, so the
// verification holds after the leaf expires.
var verifiedAt = time.Date(2026, time.October, 20, 12, 0, 0, 0, time.UTC)

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
	if path, ok := os.LookupEnv(verifyVariable); ok {
		os.Exit(verifyChain(path))
	}
	os.Exit(m.Run())
}

// verifyChain verifies the leaf of the chain in path for example.com
// against the system's roots, with the rest as intermediates, and prints
// the outcome.
func verifyChain(path string) int {
	body, err := os.ReadFile(path) //nolint:gosec // the test's own chain
	if err != nil {
		fmt.Println(err)
		return 1
	}
	var chain []*x509.Certificate
	for block, rest := pem.Decode(body); block != nil; block, rest = pem.Decode(rest) {
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Println(err)
			return 1
		}
		chain = append(chain, certificate)
	}
	if len(chain) == 0 {
		fmt.Println("no certificate in", path)
		return 1
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: "example.com", Intermediates: intermediates, CurrentTime: verifiedAt}); err != nil {
		fmt.Println("not verified:", err)
		return 1
	}
	fmt.Println("verified")
	return 0
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
