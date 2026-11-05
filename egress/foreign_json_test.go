// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"testing"
	"time"
)

func TestParseTokenResponseAcceptsDuplicateNamesAndMixedCase(t *testing.T) {
	tok, life, err := parseTokenResponse([]byte(`{"access_token":"a","ACCESS_TOKEN":"b","Expires_In":"60"}`))
	if err != nil || tok != "b" || life != time.Minute {
		t.Errorf("got %q %v %v", tok, life, err)
	}
}
