package main

// Invariants that live in the SCHEMA rather than in Go, tested here because a
// unit test cannot see them and a code review will not notice when one is
// loosened. Each of these was a real defect before it was a test.

import (
	"context"
	"os"
	"testing"

	"github.com/alora/auth/internal/platform/database"
	"github.com/jackc/pgx/v5/pgxpool"
)

func schemaPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ALORA_TEST_DB")
	if dsn == "" {
		t.Skip("ALORA_TEST_DB not set; skipping schema invariant tests")
	}
	pool, err := database.New(context.Background(), dsn, database.Options{})
	if err != nil {
		t.Fatalf("database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// The audit trail records WHO did each thing. An ON DELETE SET NULL on the actor
// key silently defeats that: deleting a user makes PostgreSQL rewrite the
// existing audit rows and drop the actor. Revoking UPDATE on tbl_audit_logs does
// not help, because a referential action runs as the referencing table's owner
// and never consults the caller's grants.
func TestAuditActorKeyIsRestrict(t *testing.T) {
	pool := schemaPool(t)
	ctx := context.Background()

	var action string
	err := pool.QueryRow(ctx, `
		SELECT confdeltype::text FROM pg_constraint
		WHERE conname = 'fk_tbl_audit_logs_tbl_users_actor_user_id'`).Scan(&action)
	if err != nil {
		t.Fatalf("read constraint: %v", err)
	}
	if action != "r" {
		t.Fatalf("audit actor FK is %q, want %q (RESTRICT).\n"+
			"With SET NULL (%q) or CASCADE (%q), deleting a user erases them from the "+
			"audit trail. Apply Migrations/0001_audit_actor_restrict.sql.",
			action, "r", "n", "c")
	}
}

// The property the constraint is there to provide, exercised rather than
// asserted: a user who has done something cannot be removed, so the record of
// what they did keeps naming them.
func TestDeletingAnAuditedUserIsRefused(t *testing.T) {
	pool := schemaPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var clientID, userID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO tbl_clients (name, is_active) VALUES ('inv-test', true) RETURNING id`,
	).Scan(&clientID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO tbl_users (client_id, email, account_type, is_active)
		 VALUES ($1, 'inv-test@example.test', 'EMAIL', true) RETURNING id`, clientID,
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO tbl_audit_logs (client_id, actor_user_id, event_type)
		 VALUES ($1, $2, 'INVARIANT_PROBE')`, clientID, userID); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM tbl_users WHERE id = $1`, userID); err == nil {
		t.Fatal("deleted a user that has audit history; the trail can be erased by " +
			"deleting its subject, which is exactly what the trail exists to prevent")
	}
}

// tbl_client_products is provisioning-only, so no routine writes it and the
// application role holds no grant on it. If a procedure ever starts writing it,
// Security/roles.sql has to grant that explicitly -- otherwise it works for the
// owner in development and fails in production, which is the worst ordering.
func TestNoRoutineWritesClientProducts(t *testing.T) {
	pool := schemaPool(t)

	var n int
	err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		  AND (p.proname LIKE 'stp\_%' OR p.proname LIKE 'udf\_%')
		  AND p.prosrc ~* '(insert into|update|delete from)\s+tbl_client_products'`).Scan(&n)
	if err != nil {
		t.Fatalf("scan routines: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d routine(s) write tbl_client_products, which the application role "+
			"cannot access. Grant it in Security/roles.sql or move the write to bootstrap.", n)
	}
}
