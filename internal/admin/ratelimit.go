package admin

import (
	"math"
	"sync"
	"time"
)

// FailureLimiter is the per-IP budget for failed admin authentications: a
// token bucket of Burst failures refilled one per Every. Only failures
// spend it, and a valid token always passes: every panel call leaves from
// the panel's own address, so blocking valid tokens there would let anyone
// with bad tokens lock every administrator out.
type FailureLimiter struct {
	burst   float64
	every   time.Duration
	maxKeys int
	now     func() time.Time

	mu      sync.Mutex
	buckets map[string]*failBucket
}

type failBucket struct {
	tokens float64
	at     time.Time
}

// NewFailureLimiter: burst failures, one more per every, at most maxKeys
// tracked addresses (the fullest buckets are dropped first when full).
func NewFailureLimiter(burst int, every time.Duration, maxKeys int) *FailureLimiter {
	if burst < 1 {
		burst = 1
	}
	if every <= 0 {
		every = 6 * time.Second
	}
	if maxKeys < 1 {
		maxKeys = 10_000
	}
	return &FailureLimiter{
		burst: float64(burst), every: every, maxKeys: maxKeys,
		now: time.Now, buckets: make(map[string]*failBucket),
	}
}

// Allow spends one failure for key. When the budget is exhausted it returns
// false and how long until the next failure is allowed.
func (l *FailureLimiter) Allow(key string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.sweepLocked(now)
		}
		b = &failBucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens < 1 {
		wait := time.Duration(math.Ceil((1 - b.tokens) * float64(l.every)))
		return false, wait
	}
	b.tokens--
	return true, 0
}

func (l *FailureLimiter) refill(b *failBucket, now time.Time) {
	if el := now.Sub(b.at); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+float64(el)/float64(l.every))
		b.at = now
	}
}

// sweepLocked drops refilled buckets; if none are, it drops everything
// (an address flood; the limiter then starts over rather than grow).
func (l *FailureLimiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		l.refill(b, now)
		if b.tokens >= l.burst {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) >= l.maxKeys {
		clear(l.buckets)
	}
}

// Sweep drops buckets that refilled completely; call it periodically.
func (l *FailureLimiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, b := range l.buckets {
		l.refill(b, now)
		if b.tokens >= l.burst {
			delete(l.buckets, k)
		}
	}
}
