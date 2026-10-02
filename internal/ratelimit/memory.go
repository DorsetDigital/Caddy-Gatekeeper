package ratelimit

import (
	"context"
	"sync"
	"time"
)

type memoryBucket struct {
	Count     int
	ExpiresAt time.Time
}

type Memory struct {
	mu      sync.Mutex
	buckets map[string]memoryBucket
}

func NewMemory() *Memory {
	return &Memory{buckets: map[string]memoryBucket{}}
}

func (m *Memory) Allow(_ context.Context, key string, limit int, window time.Duration) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	bucket, ok := m.buckets[key]
	if !ok || !now.Before(bucket.ExpiresAt) {
		bucket = memoryBucket{ExpiresAt: now.Add(window)}
	}

	bucket.Count++
	m.buckets[key] = bucket

	retryAfter := time.Until(bucket.ExpiresAt)
	if retryAfter < 0 {
		retryAfter = 0
	}

	return Result{
		Allowed:      bucket.Count <= limit,
		FirstBlocked: bucket.Count == limit+1,
		RetryAfter:   retryAfter,
	}, nil
}
