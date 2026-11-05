// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestSaveOmitsAZeroExpiresIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	s := &FileTokenStore{Path: path}
	tok := &oauth2.Token{AccessToken: "a", RefreshToken: "r", Expiry: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	if err := s.Save(tok); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"access_token":"a","refresh_token":"r","expiry":"2026-01-02T03:04:05Z"}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	tok.ExpiresIn = 60
	tok.TokenType = "Bearer"
	if err := s.Save(tok); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	const want2 = `{"access_token":"a","token_type":"Bearer","refresh_token":"r","expiry":"2026-01-02T03:04:05Z","expires_in":60}`
	if string(got) != want2 {
		t.Errorf("got  %s\nwant %s", got, want2)
	}
}
