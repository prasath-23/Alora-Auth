-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: subscriptions and direct product-role grants
-- ─────────────────────────────────────────────────────────────────────────────

-- name: ActiveSubscriptionId :one
-- Filtered so a NULL (no subscription) yields ZERO ROWS rather than one NULL
-- row: a scalar function always returns a row, and the caller distinguishes
-- "not found" by pgx.ErrNoRows.
SELECT id FROM (SELECT udf_ActiveSubscriptionId($1, $2) AS id) t WHERE id IS NOT NULL;

-- name: ListClientProducts :many
SELECT * FROM udf_ListClientProducts($1);

-- name: GetProductPermission :one
SELECT * FROM udf_GetProductPermission($1, $2, $3);

-- name: UpsertProductPermission :exec
CALL stp_UpsertProductPermission($1, $2, $3, $4, $5);

-- name: DeleteProductPermission :one
SELECT stp_DeleteProductPermission($1, $2, $3);

-- name: UpsertSubscription :one
SELECT * FROM stp_UpsertSubscription(
    sqlc.arg('client_id'),
    sqlc.arg('product_id'),
    sqlc.arg('is_active'),
    sqlc.narg('seat_limit'),
    sqlc.narg('ends_at')
);
