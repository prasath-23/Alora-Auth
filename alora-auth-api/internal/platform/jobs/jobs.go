// Package jobs runs the periodic maintenance sweeps that keep expired rows from
// accumulating: revoking timed-out sessions and expiring stale invitations.
package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/alora/auth/internal/platform/database/sqlc"
)

// Batch caps rows touched per tick. Bounded work keeps each sweep's transaction
// short so it never blocks the request path on a lock.
const Batch = 500

type Runner struct {
	q   *sqlc.Queries
	log *slog.Logger
}

func New(q *sqlc.Queries, log *slog.Logger) *Runner { return &Runner{q: q, log: log} }

// Start launches both sweeps and returns immediately. They stop when ctx is
// cancelled, which happens on SIGINT/SIGTERM.
//
// Each runs once EAGERLY at startup: after a deployment or a long outage there
// may already be a backlog, and waiting a full interval would leave expired
// sessions accepted in the meantime.
func (r *Runner) Start(ctx context.Context) {
	go r.loop(ctx, "expire-sessions", time.Hour, r.expireSessions)
	go r.loop(ctx, "expire-invitations", 6*time.Hour, r.expireInvitations)
}

func (r *Runner) loop(ctx context.Context, name string, every time.Duration, fn func(context.Context) error) {
	run := func() {
		// A sweep must never outlive its own interval, or slow ticks would pile up.
		runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		if err := fn(runCtx); err != nil {
			// Logged, never fatal: a failed sweep is retried on the next tick and
			// must not take the server down.
			r.log.Error("background job failed", "job", name, "err", err)
		}
	}
	run()

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.log.Info("background job stopped", "job", name)
			return
		case <-ticker.C:
			run()
		}
	}
}

// expireSessions marks timed-out sessions revoked. Purely a hygiene measure:
// every read path already filters on expires_at, so a late sweep is never a
// security gap.
func (r *Runner) expireSessions(ctx context.Context) error {
	return r.q.ExpireSessions(ctx, Batch)
}

func (r *Runner) expireInvitations(ctx context.Context) error {
	return r.q.ExpireInvitations(ctx, Batch)
}
