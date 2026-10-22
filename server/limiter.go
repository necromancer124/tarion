package main

import (
	"sync"
	"time"
)

// limiter is a set of token buckets, one per key (an IP, a username, ...).
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens added per second
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(every time.Duration, burst int) *limiter {
	return &limiter{rate: 1 / every.Seconds(), burst: float64(burst), buckets: map[string]*bucket{}}
}

// newByteLimiter allows perSecond bytes per key, with one second of burst.
func newByteLimiter(perSecond int) *limiter {
	return &limiter{rate: float64(perSecond), burst: float64(perSecond), buckets: map[string]*bucket{}}
}

// Allow takes one token for key, reporting false when none is left.
func (l *limiter) Allow(key string) bool { return l.AllowN(key, 1) }

// AllowN takes n tokens for key, or none if fewer are left.
func (l *limiter) AllowN(key string, n float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// sweep forgets buckets that have refilled completely, so memory stays
// bounded by recently active keys.
func (l *limiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
