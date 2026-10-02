package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryLimiterBlocksAfterLimitAndOnlyFlagsFirstBlock(t *testing.T) {
	limiter := NewMemory()
	ctx := context.Background()

	first, err := limiter.Allow(ctx, "site:test", 2, time.Minute)
	if err != nil || !first.Allowed || first.FirstBlocked {
		t.Fatalf("first request = %+v err=%v", first, err)
	}

	second, err := limiter.Allow(ctx, "site:test", 2, time.Minute)
	if err != nil || !second.Allowed || second.FirstBlocked {
		t.Fatalf("second request = %+v err=%v", second, err)
	}

	third, err := limiter.Allow(ctx, "site:test", 2, time.Minute)
	if err != nil || third.Allowed || !third.FirstBlocked {
		t.Fatalf("third request = %+v err=%v", third, err)
	}

	fourth, err := limiter.Allow(ctx, "site:test", 2, time.Minute)
	if err != nil || fourth.Allowed || fourth.FirstBlocked {
		t.Fatalf("fourth request = %+v err=%v", fourth, err)
	}
}
