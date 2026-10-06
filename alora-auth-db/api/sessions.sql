-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: sessions (logins and refresh-token rotation)
--
-- A login is a family (tbl_session_families); each refresh appends a generation
-- (tbl_user_sessions). The rotation sequence is orchestrated by the API inside
-- ONE transaction, but every individual statement is a database object. In
-- particular the lock is taken by udf_GetSessionByRefreshHashForUpdate, so the
-- FOR UPDATE that serialises concurrent rotations lives in the database.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: GetSessionByRefreshHashForUpdate :one
SELECT * FROM udf_GetSessionByRefreshHashForUpdate($1);

-- name: GetSessionById :one
SELECT * FROM udf_GetSessionById($1);

-- name: GetGraceSuccessor :one
SELECT * FROM udf_GetGraceSuccessor($1, $2);

-- name: GetSessionForLogout :one
SELECT * FROM udf_GetSessionForLogout($1);

-- name: GetSessionFamilyGate :one
SELECT * FROM udf_GetSessionFamilyGate($1);

-- name: ListSessionFamilies :many
SELECT * FROM udf_ListSessionFamilies($1);

-- name: CreateCentralFamily :one
SELECT * FROM stp_CreateCentralFamily(
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.arg('auth_method')::"IdpProvider",
    sqlc.narg('auth_connection_id'),
    sqlc.arg('absolute_expires_at'),
    sqlc.arg('session_uuid'),
    sqlc.arg('refresh_token_hash'),
    sqlc.arg('expires_at'),
    sqlc.narg('ip_address'),
    sqlc.narg('device_label'),
    sqlc.narg('user_agent')
);

-- name: CreateProductFamily :one
SELECT * FROM stp_CreateProductFamily(
    sqlc.arg('parent_family_id'),
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.arg('product_id'),
    sqlc.arg('session_uuid'),
    sqlc.arg('refresh_token_hash'),
    sqlc.arg('expires_at'),
    sqlc.narg('ip_address'),
    sqlc.narg('device_label'),
    sqlc.narg('user_agent')
);

-- name: CreateSuccessorSession :one
SELECT * FROM stp_CreateSuccessorSession(
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.arg('session_uuid'),
    sqlc.arg('family_id'),
    sqlc.arg('generation'),
    sqlc.arg('refresh_token_hash'),
    sqlc.narg('prev_token_hash'),
    sqlc.arg('expires_at'),
    sqlc.narg('ip_address'),
    sqlc.narg('device_label'),
    sqlc.narg('user_agent')
);

-- name: MarkSessionReplaced :exec
CALL stp_MarkSessionReplaced($1, $2);

-- name: RevokeSessionFamily :one
SELECT stp_RevokeSessionFamily(
    sqlc.arg('family_id'),
    sqlc.arg('client_id'),
    sqlc.arg('reason')::"SessionRevokedReason"
);

-- name: RevokeAllUserSessions :one
SELECT stp_RevokeAllUserSessions(
    sqlc.arg('user_id'),
    sqlc.arg('reason')::"SessionRevokedReason"
);

-- name: RevokeAllClientSessions :one
SELECT stp_RevokeAllClientSessions(
    sqlc.arg('client_id'),
    sqlc.arg('reason')::"SessionRevokedReason"
);

-- name: RevokeTokenFamily :exec
CALL stp_RevokeTokenFamily($1, $2);

-- name: ExpireSessions :exec
CALL stp_ExpireSessions($1);
