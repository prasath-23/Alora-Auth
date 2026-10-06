package infrastructure

import (
	"context"
	"log/slog"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/services/ratelimits"
)

// RateLimitStore is a shared, Postgres-backed rate-limit counter store. It lets
// several API instances behind a load balancer enforce ONE fixed-window budget
// together, instead of each granting it in full. It satisfies
// middlewares.Store structurally, so the middleware layer depends on no part of
// the database layer.
//
// On a database error it FAILS OPEN — it allows the request — so a database blip
// cannot 429 the whole fleet. During such a blip the limit degrades to what it
// was before this store existed (per-instance), which is a safe floor, never a
// lock-out.
type RateLimitStore struct {
	db  *contexts.DbContext
	log *slog.Logger
}

// NewRateLimitStore builds the store on the application's database context.
func NewRateLimitStore(db *contexts.DbContext, log *slog.Logger) *RateLimitStore {
	return &RateLimitStore{db: db, log: log}
}

// Allow spends one unit against key and reports whether it stays within max in
// the window, and how long until the window resets when it does not.
func (s *RateLimitStore) Allow(ctx context.Context, key string, max int, window time.Duration) (bool, time.Duration) {
	blocked, resetAt, err := ratelimits.NewRateLimitDbService(s.db).Hit(ctx, key, int32(max), int32(window/time.Second))
	if err != nil {
		s.log.Warn("rate-limit store unavailable; allowing", "err", err)
		return true, 0
	}
	if !blocked {
		return true, 0
	}
	return false, time.Until(resetAt)
}

// Peek reports whether key has already reached max, without spending anything.
func (s *RateLimitStore) Peek(ctx context.Context, key string, max int, _ time.Duration) (bool, time.Duration) {
	blocked, resetAt, err := ratelimits.NewRateLimitDbService(s.db).Peek(ctx, key, int32(max))
	if err != nil {
		s.log.Warn("rate-limit store unavailable; not blocking", "err", err)
		return false, 0
	}
	if !blocked {
		return false, 0
	}
	return true, time.Until(resetAt)
}
