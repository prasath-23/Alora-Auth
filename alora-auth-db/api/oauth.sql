-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: OAuth2 authorization codes and federated identities
--
-- The single-use guarantee is enforced inside stp_ClaimAuthorizationCode as one
-- atomic UPDATE, so no caller can reintroduce a check-then-act race.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: CreateAuthorizationCode :one
SELECT * FROM stp_CreateAuthorizationCode(
    sqlc.arg('code'),
    sqlc.arg('product_id'),
    sqlc.arg('user_id'),
    sqlc.arg('redirect_url'),
    sqlc.arg('code_challenge'),
    sqlc.arg('code_challenge_method'),
    sqlc.narg('state'),
    sqlc.arg('expires_at')
);

-- name: ClaimAuthorizationCode :one
SELECT * FROM stp_ClaimAuthorizationCode($1);

-- name: CleanupExpiredAuthCodes :one
SELECT stp_CleanupExpiredAuthCodes();

-- name: GetLinkedIdentity :one
SELECT * FROM udf_GetLinkedIdentity(
    sqlc.arg('provider')::"IdpProvider",
    sqlc.arg('provider_id')
);

-- name: CreateLinkedIdentity :one
SELECT * FROM stp_CreateLinkedIdentity(
    sqlc.arg('user_id'),
    sqlc.arg('provider')::"IdpProvider",
    sqlc.arg('provider_id'),
    sqlc.arg('email_verified')
);

-- name: ClientIdByVerifiedDomain :one
-- Filtered so an unknown domain yields zero rows (see entitlements.sql).
SELECT id FROM (SELECT udf_ClientIdByVerifiedDomain($1) AS id) t WHERE id IS NOT NULL;
