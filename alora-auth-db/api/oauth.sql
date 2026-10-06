-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: authorization codes, federated identities and sign-in states
--
-- The single-use guarantees are enforced inside stp_ClaimAuthorizationCode and
-- stp_TakeLoginState as one atomic statement each, so no caller can reintroduce
-- a check-then-act race.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: CreateAuthorizationCode :one
SELECT * FROM stp_CreateAuthorizationCode(
    sqlc.arg('code_hash'),
    sqlc.arg('product_id'),
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.arg('parent_family_id'),
    sqlc.arg('redirect_uri'),
    sqlc.arg('code_challenge'),
    sqlc.arg('code_challenge_method'),
    sqlc.narg('nonce'),
    sqlc.narg('scope'),
    sqlc.arg('expires_at')
);

-- name: ClaimAuthorizationCode :one
SELECT * FROM stp_ClaimAuthorizationCode($1);

-- name: GetAuthorizationCodeByHash :one
SELECT * FROM udf_GetAuthorizationCodeByHash($1);

-- name: SetCodeIssuedFamily :exec
CALL stp_SetCodeIssuedFamily($1, $2);

-- name: CleanupExpiredAuthCodes :one
SELECT stp_CleanupExpiredAuthCodes();

-- name: ListGoogleLinks :many
SELECT * FROM udf_ListGoogleLinks($1);

-- name: GetLinkedIdentityByConnection :one
SELECT * FROM udf_GetLinkedIdentityByConnection($1, $2);

-- name: CreateLinkedIdentity :one
SELECT * FROM stp_CreateLinkedIdentity(
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.arg('provider')::"IdpProvider",
    sqlc.narg('connection_id'),
    sqlc.arg('provider_id'),
    sqlc.arg('email_verified'),
    sqlc.narg('email_at_link')
);

-- name: DeleteLinkedIdentity :one
SELECT stp_DeleteLinkedIdentity(
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.arg('provider')::"IdpProvider",
    sqlc.narg('connection_id')
);

-- name: ClientIdByVerifiedDomain :one
-- Filtered so an unknown domain yields zero rows (see entitlements.sql).
SELECT id FROM (SELECT udf_ClientIdByVerifiedDomain($1) AS id) t WHERE id IS NOT NULL;

-- name: CreateLoginState :exec
CALL stp_CreateLoginState(
    sqlc.arg('state_hash'),
    sqlc.arg('kind')::"LoginStateKind",
    sqlc.narg('connection_id'),
    sqlc.narg('nonce'),
    sqlc.narg('code_verifier'),
    sqlc.narg('return_to'),
    sqlc.narg('candidate_user_ids')::text[],
    sqlc.narg('auth_method')::"IdpProvider",
    sqlc.arg('expires_at')
);

-- name: GetLoginState :one
SELECT * FROM udf_GetLoginState(
    sqlc.arg('state_hash'),
    sqlc.arg('kind')::"LoginStateKind"
);

-- name: TakeLoginState :one
SELECT * FROM stp_TakeLoginState(
    sqlc.arg('state_hash'),
    sqlc.arg('kind')::"LoginStateKind"
);

-- name: CleanupLoginStates :one
SELECT stp_CleanupLoginStates();
