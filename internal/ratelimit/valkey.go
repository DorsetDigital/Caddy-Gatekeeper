package ratelimit

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type Valkey struct {
	client redis.UniversalClient
	prefix string
}

func NewValkey(client redis.UniversalClient, prefix string) *Valkey {
	if prefix == "" {
		prefix = "gatekeeper:"
	}
	return &Valkey{client: client, prefix: prefix}
}

var allowScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
return {count, ttl}
`)

func (v *Valkey) Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	raw, err := allowScript.Run(ctx, v.client, []string{v.prefix + "rate:" + key}, window.Milliseconds()).Result()
	if err != nil {
		return Result{}, err
	}

	items, ok := raw.([]interface{})
	if !ok || len(items) != 2 {
		return Result{}, errors.New("invalid Valkey rate-limit response")
	}

	count, ok := items[0].(int64)
	if !ok {
		return Result{}, errors.New("invalid Valkey rate-limit count")
	}
	ttl, ok := items[1].(int64)
	if !ok {
		return Result{}, errors.New("invalid Valkey rate-limit TTL")
	}

	if ttl < 0 {
		ttl = 0
	}

	return Result{
		Allowed:      count <= int64(limit),
		FirstBlocked: count == int64(limit+1),
		RetryAfter:   time.Duration(ttl) * time.Millisecond,
	}, nil
}
