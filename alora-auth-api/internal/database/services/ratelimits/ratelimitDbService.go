// Package ratelimits is the table service for tbl_rate_limit_counters: the
// shared, fixed-window rate-limit counters several API instances enforce one
// budget with. Counters are ephemeral and best-effort — a lost row only resets
// one window early.
package ratelimits

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/sqlc"
)

// RateLimitDbService is the surface of tbl_rate_limit_counters.
type RateLimitDbService struct{ q *sqlc.Queries }

// NewRateLimitDbService binds the service to a context: the pool or a transaction.
func NewRateLimitDbService(c contexts.Querier) *RateLimitDbService {
	return &RateLimitDbService{q: c.Queries()}
}

// Hit spends one unit against key's fixed-window counter. It reports whether the
// request is over budget and, when it is, when the window resets.
func (s *RateLimitDbService) Hit(ctx context.Context, key string, max, windowSecs int32) (blocked bool, resetAt time.Time, err error) {
	ts, err := s.q.RateLimitHit(ctx, sqlc.RateLimitHitParams{PKey: key, PMax: max, PWindowsecs: windowSecs})
	if err != nil {
		return false, time.Time{}, err
	}
	// NULL reset time means the hit was within budget.
	if !ts.Valid {
		return false, time.Time{}, nil
	}
	return true, ts.Time, nil
}

// Peek reports whether key has already reached max, without spending a unit, and
// when its window resets if so.
func (s *RateLimitDbService) Peek(ctx context.Context, key string, max int32) (blocked bool, resetAt time.Time, err error) {
	ts, err := s.q.RateLimitPeek(ctx, sqlc.RateLimitPeekParams{PKey: key, PMax: max})
	if err != nil {
		return false, time.Time{}, err
	}
	if !ts.Valid {
		return false, time.Time{}, nil
	}
	return true, ts.Time, nil
}

// Cleanup removes expired counters and returns how many it deleted.
func (s *RateLimitDbService) Cleanup(ctx context.Context) (int32, error) {
	return s.q.CleanupRateLimitCounters(ctx)
}
