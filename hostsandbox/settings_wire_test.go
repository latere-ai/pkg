// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import "testing"

func TestSettingsEncodeWritesNilListsAsNull(t *testing.T) {
	got, err := Settings{}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\n  \"network\": {\n    \"allowedDomains\": null,\n    \"deniedDomains\": null,\n    \"allowLocalBinding\": false,\n    \"allowAllUnixSockets\": false\n  },\n  \"filesystem\": {\n    \"denyRead\": null,\n    \"allowRead\": null,\n    \"allowWrite\": null,\n    \"denyWrite\": null\n  }\n}\n"
	if string(got) != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
