package ratelimit

import (
	"context"
	"time"
)

type Result struct {
	Allowed      bool
	FirstBlocked bool
	RetryAfter   time.Duration
}

type Limiter interface {
	Allow(context.Context, string, int, time.Duration) (Result, error)
}
