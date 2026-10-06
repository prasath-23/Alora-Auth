-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: tenants and the product catalogue
-- ─────────────────────────────────────────────────────────────────────────────

-- name: GetClientById :one
SELECT * FROM udf_GetClientById($1);

-- name: ClientNameById :one
-- Filtered so an unknown tenant yields zero rows (see entitlements.sql).
SELECT name FROM (SELECT udf_ClientNameById($1) AS name) t WHERE name IS NOT NULL;

-- name: ListCompanies :many
SELECT * FROM udf_ListCompanies();

-- name: CreateClient :one
SELECT * FROM stp_CreateClient(
    sqlc.arg('name'),
    sqlc.narg('domain'),
    sqlc.arg('subscription_status')::"SubscriptionStatus",
    sqlc.narg('max_seats'),
    sqlc.arg('is_active'),
    sqlc.arg('is_platform')
);

-- name: UpdateClient :one
SELECT * FROM stp_UpdateClient(
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.narg('domain_verified_at'),
    sqlc.arg('subscription_status')::"SubscriptionStatus",
    sqlc.narg('max_seats'),
    sqlc.arg('is_active')
);

-- name: SetClientDomain :one
SELECT * FROM stp_SetClientDomain(
    sqlc.arg('client_id'),
    sqlc.narg('domain'),
    sqlc.arg('verified')
);

-- name: GetProductById :one
SELECT * FROM udf_GetProductById($1, $2);

-- name: ProductKeyById :one
-- Filtered so an unknown product yields zero rows (see entitlements.sql).
SELECT key FROM (SELECT udf_ProductKeyById($1) AS key) t WHERE key IS NOT NULL;

-- name: ListActiveProducts :many
SELECT * FROM udf_ListActiveProducts();

-- name: ListProducts :many
SELECT * FROM udf_ListProducts();

-- name: GetProductClient :one
SELECT * FROM udf_GetProductClient($1);

-- name: GetProductClientCredential :one
SELECT * FROM udf_GetProductClientCredential($1);

-- name: ListProductRoles :many
SELECT * FROM udf_ListProductRoles($1);

-- name: ListProductRedirectUris :many
SELECT * FROM udf_ListProductRedirectUris($1);

-- name: IsRedirectUriRegistered :one
SELECT udf_IsRedirectUriRegistered($1, $2);

-- name: CreateProduct :one
SELECT * FROM stp_CreateProduct(
    sqlc.arg('key'),
    sqlc.arg('name'),
    sqlc.narg('description'),
    sqlc.narg('base_url'),
    sqlc.narg('initiate_login_uri'),
    sqlc.arg('is_active'),
    sqlc.arg('accepts_api_clients')
);

-- name: UpdateProduct :one
SELECT * FROM stp_UpdateProduct(
    sqlc.arg('product_id'),
    sqlc.arg('name'),
    sqlc.narg('description'),
    sqlc.narg('base_url'),
    sqlc.narg('initiate_login_uri'),
    sqlc.arg('is_active'),
    sqlc.narg('accepts_api_clients')
);

-- name: SetProductClientSecret :one
SELECT stp_SetProductClientSecret($1, $2);

-- name: SetProductRedirectUris :one
SELECT stp_SetProductRedirectUris(
    sqlc.arg('product_id'),
    sqlc.arg('redirect_uris')::text[]
);

-- name: SetProductRoles :one
SELECT stp_SetProductRoles(
    sqlc.arg('product_id'),
    sqlc.arg('role_names')::text[]
);
