-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: sessions (refresh-token rotation)
--
-- The rotation sequence is orchestrated by the API inside ONE transaction, but
-- every individual statement is a database object. In particular the lock is
-- taken by udf_GetSessionByRefreshHashForUpdate, so the FOR UPDATE that
-- serialises concurrent rotations lives in the database, not in application SQL.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: GetSessionByRefreshHashForUpdate :one
SELECT * FROM udf_GetSessionByRefreshHashForUpdate($1);

-- name: GetSessionById :one
SELECT * FROM udf_GetSessionById($1);

-- name: GetGraceSuccessor :one
SELECT * FROM udf_GetGraceSuccessor($1, $2);

-- name: GetSessionForLogout :one
SELECT * FROM udf_GetSessionForLogout($1);

-- name: GetClientSessionById :one
SELECT * FROM udf_GetClientSessionById($1, $2);

-- name: ListActiveSessions :many
SELECT * FROM udf_ListActiveSessions($1);

-- name: CreateSession :one
SELECT * FROM stp_CreateSession(
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.arg('session_uuid'),
    sqlc.arg('family_id'),
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

-- name: RevokeSession :one
SELECT stp_RevokeSession(
    sqlc.arg('session_id'),
    sqlc.arg('client_id'),
    sqlc.arg('reason')::"SessionRevokedReason"
);

-- name: RevokeAllUserSessions :one
SELECT stp_RevokeAllUserSessions(
    sqlc.arg('user_id'),
    sqlc.arg('reason')::"SessionRevokedReason"
);

-- name: RevokeTokenFamily :exec
CALL stp_RevokeTokenFamily($1, $2);

-- name: ExpireSessions :exec
CALL stp_ExpireSessions($1);
