package middlewares

import (
	"context"
	"sync"
	"time"
)

// Store is where a RateLimiter keeps its fixed-window counters. The default is an
// in-process map (memStore); a shared implementation (e.g. Postgres-backed) lets
// several API instances enforce one budget together instead of each granting it
// in full. A Store is addressed by an opaque key the limiter builds; it owns the
// window arithmetic so a distributed backend can do it atomically.
//
// The interface is deliberately small — Allow and Peek are the only operations
// the limiter needs — and is satisfied structurally, so a backend in another
// package (which may not import this one) implements it without a dependency.
type Store interface {
	// Allow spends one unit against key and reports whether it stays within max
	// in the window, and how long until the window resets when it does not.
	Allow(ctx context.Context, key string, max int, window time.Duration) (ok bool, retry time.Duration)
	// Peek reports whether key has already reached max, without spending anything.
	Peek(ctx context.Context, key string, max int, window time.Duration) (blocked bool, retry time.Duration)
}

// window is one key's counter and when it resets.
type window struct {
	count int
	reset time.Time
}

// memStore is the in-process default: a map guarded by a mutex, with an
// opportunistic sweep so it cannot grow without bound under a distributed attack.
// Its behaviour is the limiter's original behaviour, unchanged.
type memStore struct {
	mu     sync.Mutex
	hits   map[string]*window
	lastGC time.Time
}

func newMemStore() *memStore {
	return &memStore{hits: make(map[string]*window), lastGC: time.Now()}
}

func (m *memStore) Allow(_ context.Context, key string, max int, win time.Duration) (bool, time.Duration) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	if now.Sub(m.lastGC) > win {
		for k, w := range m.hits {
			if now.After(w.reset) {
				delete(m.hits, k)
			}
		}
		m.lastGC = now
	}

	w, ok := m.hits[key]
	if !ok || now.After(w.reset) {
		m.hits[key] = &window{count: 1, reset: now.Add(win)}
		return true, 0
	}
	w.count++
	if w.count > max {
		return false, time.Until(w.reset)
	}
	return true, 0
}

func (m *memStore) Peek(_ context.Context, key string, max int, _ time.Duration) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.hits[key]
	if !ok || time.Now().After(w.reset) {
		return false, 0
	}
	if w.count >= max {
		return true, time.Until(w.reset)
	}
	return false, 0
}
