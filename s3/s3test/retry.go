// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3test

import (
	"time"

	"latere.ai/x/pkg/retry"
)

// fastRetry keeps the default attempt budget and waits a nanosecond
// between attempts, so a test of the retry path finishes at once.
var fastRetry = retry.Policy{MaxAttempts: 3, Base: time.Nanosecond, Max: time.Nanosecond, Jitter: -1}
