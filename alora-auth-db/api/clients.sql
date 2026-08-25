-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: tenants and the product catalogue
-- ─────────────────────────────────────────────────────────────────────────────

-- name: GetClientById :one
SELECT * FROM udf_GetClientById($1);

-- name: GetClientOAuthGate :one
SELECT * FROM udf_GetClientOAuthGate($1);

-- name: ClientNameById :one
-- Filtered so an unknown tenant yields zero rows (see entitlements.sql).
SELECT name FROM (SELECT udf_ClientNameById($1) AS name) t WHERE name IS NOT NULL;

-- name: CreateClient :one
SELECT * FROM stp_CreateClient(
    sqlc.arg('name'),
    sqlc.narg('domain'),
    sqlc.arg('allowed_idp_providers')::"IdpProvider"[],
    sqlc.arg('require_mfa'),
    sqlc.arg('subscription_status')::"SubscriptionStatus",
    sqlc.narg('max_seats'),
    sqlc.arg('is_active')
);

-- name: UpdateClient :one
SELECT * FROM stp_UpdateClient(
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.arg('require_mfa'),
    sqlc.arg('allowed_idp_providers')::"IdpProvider"[],
    sqlc.narg('domain_verified_at'),
    sqlc.arg('subscription_status')::"SubscriptionStatus",
    sqlc.narg('max_seats'),
    sqlc.arg('is_active')
);

-- name: GetProductById :one
SELECT * FROM udf_GetProductById($1, $2);

-- name: ProductKeyById :one
-- Filtered so an unknown product yields zero rows (see entitlements.sql).
SELECT key FROM (SELECT udf_ProductKeyById($1) AS key) t WHERE key IS NOT NULL;

-- name: ListActiveProducts :many
SELECT * FROM udf_ListActiveProducts();

-- name: CreateProduct :one
SELECT * FROM stp_CreateProduct(
    sqlc.arg('key'),
    sqlc.arg('name'),
    sqlc.narg('description'),
    sqlc.narg('base_url'),
    sqlc.arg('is_active')
);

-- name: UpdateProduct :one
SELECT * FROM stp_UpdateProduct(
    sqlc.arg('product_id'),
    sqlc.arg('name'),
    sqlc.narg('description'),
    sqlc.narg('base_url'),
    sqlc.arg('is_active')
);
