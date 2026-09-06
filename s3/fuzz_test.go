// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"testing"
)

func FuzzParseListing(f *testing.F) {
	f.Add([]byte(`<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>a</Key><Size>1</Size><ETag>"x"</ETag><LastModified>2026-09-06T00:00:00Z</LastModified></Contents><CommonPrefixes><Prefix>p/</Prefix></CommonPrefixes></ListBucketResult>`))
	f.Add([]byte(`<not xml`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, raw []byte) {
		res, err := parseListing(raw)
		if err != nil && (len(res.Objects) != 0 || len(res.Prefixes) != 0 || res.Truncated) {
			t.Fatalf("error with a partial result: %+v", res)
		}
	})
}

func FuzzParseError(f *testing.F) {
	f.Add(500, []byte(`<Error><Code>InternalError</Code><Message>injected</Message></Error>`))
	f.Add(404, []byte(`<Error><Code>NoSuchKey</Code></Error>`))
	f.Add(400, []byte(`plain text`))
	f.Fuzz(func(t *testing.T, status int, raw []byte) {
		e := parseError(status, raw)
		if e.Status != status {
			t.Fatalf("status %d became %d", status, e.Status)
		}
		if e.Code != "" && e.Body != "" {
			t.Fatalf("both code and body set: %+v", e)
		}
		if e.Error() == "" {
			t.Fatal("empty message")
		}
	})
}
