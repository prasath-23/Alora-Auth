-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: tenants' own OIDC identity providers
--
-- The client secret enters and leaves only as ciphertext; the key that decrypts
-- it is held by the API, never by the database.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: GetSsoConnection :one
SELECT * FROM udf_GetSsoConnection($1);

-- name: ListSsoConnections :many
SELECT * FROM udf_ListSsoConnections($1);

-- name: CreateSsoConnection :one
SELECT * FROM stp_CreateSsoConnection(
    sqlc.arg('connection_id'),
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.arg('issuer'),
    sqlc.arg('oidc_client_id'),
    sqlc.narg('secret_ciphertext'),
    sqlc.narg('secret_key_id'),
    sqlc.arg('scopes'),
    sqlc.arg('trust_unverified_email'),
    sqlc.arg('is_active')
);

-- name: UpdateSsoConnection :one
SELECT * FROM stp_UpdateSsoConnection(
    sqlc.arg('connection_id'),
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.arg('issuer'),
    sqlc.arg('oidc_client_id'),
    sqlc.narg('secret_ciphertext'),
    sqlc.narg('secret_key_id'),
    sqlc.arg('scopes'),
    sqlc.arg('trust_unverified_email'),
    sqlc.arg('is_active')
);

-- name: SetSsoConnectionDomains :one
SELECT stp_SetSsoConnectionDomains(
    sqlc.arg('connection_id'),
    sqlc.arg('client_id'),
    sqlc.arg('domains')::text[]
);
