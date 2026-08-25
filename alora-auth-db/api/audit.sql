-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: audit trail
--
-- Insert only. There is deliberately no update or delete entry point, so the
-- application has no way to rewrite history even if it tried.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: InsertAuditLog :exec
CALL stp_InsertAuditLog(
    sqlc.arg('client_id'),
    sqlc.narg('actor_user_id'),
    sqlc.arg('event_type'),
    sqlc.narg('event_metadata'),
    sqlc.narg('ip_address'),
    sqlc.narg('user_agent'),
    sqlc.narg('request_id')
);
