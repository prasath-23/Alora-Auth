package infrastructure

import (
	"context"
	"log/slog"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	codecustoms "github.com/alora/auth/internal/database/services/authorizationcodes/customs"
	invitationcustoms "github.com/alora/auth/internal/database/services/invitations/customs"
	"github.com/alora/auth/internal/database/services/loginstates"
	"github.com/alora/auth/internal/database/services/ratelimits"
	sessioncustoms "github.com/alora/auth/internal/database/services/sessions/customs"
)

// SweepBatch caps rows touched per tick. Bounded work keeps each sweep's transaction
// short so it never blocks the request path on a lock.
const SweepBatch = 500

// JobRunner runs the periodic maintenance sweeps that keep expired rows from
// accumulating: revoking timed-out sessions, expiring stale invitations, and
// deleting spent authorization codes and abandoned sign-in states.
type JobRunner struct {
	db  *contexts.DbContext
	log *slog.Logger
}

// NewJobRunner builds the runner on the application's database context.
func NewJobRunner(db *contexts.DbContext, log *slog.Logger) *JobRunner {
	return &JobRunner{db: db, log: log}
}

// Start launches every sweep and returns immediately. They stop when ctx is
// cancelled, which happens on SIGINT/SIGTERM.
//
// Each runs once EAGERLY at startup: after a deployment or a long outage there
// may already be a backlog, and waiting a full interval would leave it in place.
func (r *JobRunner) Start(ctx context.Context) {
	go r.loop(ctx, "expire-sessions", time.Hour, r.expireSessions)
	go r.loop(ctx, "expire-invitations", 6*time.Hour, r.expireInvitations)
	go r.loop(ctx, "cleanup-codes", time.Hour, r.cleanupCodes)
	go r.loop(ctx, "cleanup-login-states", 15*time.Minute, r.cleanupLoginStates)
	go r.loop(ctx, "cleanup-rate-limits", 15*time.Minute, r.cleanupRateLimits)
}

func (r *JobRunner) loop(ctx context.Context, name string, every time.Duration, fn func(context.Context) error) {
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

// expireSessions marks timed-out sessions and capped families revoked. Purely a
// hygiene measure: every read path already checks expiry itself, so a late
// sweep is never a security gap.
func (r *JobRunner) expireSessions(ctx context.Context) error {
	return sessioncustoms.NewSessionDbCustoms(r.db).ExpireStale(ctx, SweepBatch)
}

func (r *JobRunner) expireInvitations(ctx context.Context) error {
	return invitationcustoms.NewInvitationDbCustoms(r.db).ExpireStale(ctx, SweepBatch)
}

func (r *JobRunner) cleanupCodes(ctx context.Context) error {
	_, err := codecustoms.NewAuthorizationCodeDbCustoms(r.db).CleanupExpired(ctx)
	return err
}

func (r *JobRunner) cleanupLoginStates(ctx context.Context) error {
	_, err := loginstates.NewLoginStateDbService(r.db).Cleanup(ctx)
	return err
}

// cleanupRateLimits deletes expired shared rate-limit counters. Harmless when the
// in-memory store is in use: the table is simply empty.
func (r *JobRunner) cleanupRateLimits(ctx context.Context) error {
	_, err := ratelimits.NewRateLimitDbService(r.db).Cleanup(ctx)
	return err
}
