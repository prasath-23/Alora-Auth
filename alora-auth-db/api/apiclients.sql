-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: API clients — applications' identities, where their credential
-- may be used (CLIENT scopes), the products they may get a token for, and their
-- secrets
--
-- Every read and write is tenant-scoped by (id, client_id) inside the routine,
-- so a foreign id finds and changes nothing. Secrets are stored as hashes only,
-- and no read here returns one.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: CreateApiClient :one
SELECT * FROM stp_CreateApiClient(
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.narg('description'),
    sqlc.narg('created_by_user_id'),
    sqlc.narg('created_by_owner_id')
);

-- name: UpdateApiClient :one
SELECT * FROM stp_UpdateApiClient(
    sqlc.arg('api_client_id'),
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.narg('description'),
    sqlc.arg('is_active')
);

-- name: DeleteApiClient :one
SELECT stp_DeleteApiClient(sqlc.arg('api_client_id'), sqlc.arg('client_id'));

-- name: SetApiClientScopes :one
SELECT stp_SetApiClientScopes(
    sqlc.arg('api_client_id'),
    sqlc.arg('client_id'),
    sqlc.arg('scopes')::text[]
);

-- name: SetApiClientProducts :one
SELECT stp_SetApiClientProducts(
    sqlc.arg('api_client_id'),
    sqlc.arg('client_id'),
    sqlc.arg('product_ids')::text[]
);

-- name: CreateApiClientSecret :one
SELECT * FROM stp_CreateApiClientSecret(
    sqlc.arg('api_client_id'),
    sqlc.arg('client_id'),
    sqlc.arg('secret_hash'),
    sqlc.arg('prefix'),
    sqlc.narg('expires_at'),
    sqlc.narg('created_by_user_id'),
    sqlc.narg('created_by_owner_id')
);

-- name: RevokeApiClientSecret :one
SELECT stp_RevokeApiClientSecret(sqlc.arg('secret_id'), sqlc.arg('api_client_id'), sqlc.arg('client_id'));

-- name: ListApiClients :many
SELECT * FROM udf_ListApiClients($1);

-- name: ListAllApiClients :many
SELECT * FROM udf_ListAllApiClients();

-- name: GetApiClient :one
SELECT * FROM udf_GetApiClient(sqlc.arg('api_client_id'), sqlc.arg('client_id'));

-- name: ListApiClientSecrets :many
SELECT * FROM udf_ListApiClientSecrets(sqlc.arg('api_client_id'), sqlc.arg('client_id'));

-- name: ListApiClientProductChoices :many
SELECT * FROM udf_ListApiClientProductChoices($1);

-- name: GetOAuthClientCredentials :many
SELECT * FROM udf_GetOAuthClientCredentials($1);

-- name: GetApiClientGrant :one
SELECT * FROM udf_GetApiClientGrant(sqlc.arg('api_client_id'), sqlc.arg('product_key'));

-- name: IsApiClientSecretLive :one
SELECT udf_IsApiClientSecretLive(sqlc.arg('secret_id'), sqlc.arg('api_client_id'));

-- name: TouchApiClientSecret :exec
CALL stp_TouchApiClientSecret(sqlc.arg('secret_id'), sqlc.arg('api_client_id'));
