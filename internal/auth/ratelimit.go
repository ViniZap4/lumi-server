package auth

import (
	"strings"
	"sync"
	"time"
)

// RateLimiter is a per-process in-memory token bucket. Acceptable per Pillar
// 4 with sticky sessions; horizontal scale beyond a few replicas needs Redis.
type RateLimiter struct {
	capacity     float64
	refillPerSec float64
	idleTTL      time.Duration
	clock        func() time.Time
	buckets      sync.Map
}

type bucket struct {
	mu        sync.Mutex
	tokens    float64
	updatedAt time.Time
}

func NewRateLimiter(capacity int, window, idleTTL time.Duration) *RateLimiter {
	if capacity < 1 {
		capacity = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	if idleTTL <= 0 {
		idleTTL = 10 * time.Minute
	}
	return &RateLimiter{
		capacity:     float64(capacity),
		refillPerSec: float64(capacity) / window.Seconds(),
		idleTTL:      idleTTL,
		clock:        time.Now,
	}
}

// Allow consumes one token. Empty/whitespace keys are always allowed.
func (r *RateLimiter) Allow(key string) bool {
	if r == nil {
		return true
	}
	if strings.TrimSpace(key) == "" {
		return true
	}
	now := r.clock()
	b := r.bucketFor(key, now)

	b.mu.Lock()
	defer b.mu.Unlock()

	elapsed := now.Sub(b.updatedAt).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * r.refillPerSec
		if b.tokens > r.capacity {
			b.tokens = r.capacity
		}
	}
	b.updatedAt = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Reset clears the bucket for key — used after successful auth.
func (r *RateLimiter) Reset(key string) {
	if r == nil || strings.TrimSpace(key) == "" {
		return
	}
	r.buckets.Delete(key)
}

func (r *RateLimiter) bucketFor(key string, now time.Time) *bucket {
	if v, ok := r.buckets.Load(key); ok {
		b := v.(*bucket)
		b.mu.Lock()
		stale := now.Sub(b.updatedAt) > r.idleTTL
		b.mu.Unlock()
		if !stale {
			return b
		}
		r.buckets.Delete(key)
	}
	fresh := &bucket{tokens: r.capacity, updatedAt: now}
	actual, loaded := r.buckets.LoadOrStore(key, fresh)
	if loaded {
		return actual.(*bucket)
	}
	return fresh
}
