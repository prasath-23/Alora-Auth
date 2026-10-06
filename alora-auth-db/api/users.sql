-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: users
--
-- Every statement in this folder is a CALL of a procedure or a SELECT from a
-- function. Nothing here reads or writes a table directly, so all query logic —
-- predicates, projections, tenant scoping — lives in the database objects under
-- db/Tables, db/Views and db/Programmability and can be reviewed there in one
-- place.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: GetUserById :one
SELECT * FROM udf_GetUserById($1);

-- name: ListLoginCandidates :many
SELECT * FROM udf_ListLoginCandidates($1);

-- name: ListUserIdentitiesByEmail :many
SELECT * FROM udf_ListUserIdentitiesByEmail($1);

-- name: GetUserIdentityForToken :one
SELECT * FROM udf_GetUserIdentityForToken($1);

-- name: GetUserTenantScoped :one
SELECT * FROM udf_GetUserTenantScoped($1, $2);

-- name: GetOAuthLinkableUser :one
SELECT * FROM udf_GetOAuthLinkableUser($1, $2);

-- name: GetUserForSsoLink :one
SELECT * FROM udf_GetUserForSsoLink($1, $2);

-- name: ListUsers :many
SELECT * FROM udf_ListUsers(
    sqlc.arg('client_id'),
    sqlc.narg('search'),
    sqlc.narg('cursor_created'),
    sqlc.narg('cursor_id'),
    sqlc.arg('take')
);

-- name: ListUserGroups :many
SELECT * FROM udf_ListUserGroups(
    sqlc.arg('client_id'),
    sqlc.arg('user_ids')::text[]
);

-- name: ListUserProductRoles :many
SELECT * FROM udf_ListUserProductRoles($1, $2);

-- name: GetUserLoginPolicy :one
SELECT * FROM udf_GetUserLoginPolicy($1, $2);

-- name: ActiveEmailExists :one
SELECT udf_ActiveEmailExists($1, $2);

-- name: UserCursorPosition :one
-- Filtered so an unresolvable cursor yields zero rows (see entitlements.sql).
SELECT created_at FROM (SELECT udf_UserCursorPosition($1, $2) AS created_at) t
WHERE created_at IS NOT NULL;

-- name: UserIdByEmail :one
-- Filtered so an unknown address yields zero rows (see entitlements.sql).
SELECT id FROM (SELECT udf_UserIdByEmail($1, $2) AS id) t WHERE id IS NOT NULL;

-- name: CreateUser :one
SELECT * FROM stp_CreateUser(
    sqlc.arg('client_id'),
    sqlc.arg('email'),
    sqlc.narg('password_hash'),
    sqlc.arg('account_type')::"AccountType"
);

-- name: SetUserActive :one
SELECT stp_SetUserActive($1, $2, $3);

-- name: SetUserPassword :exec
CALL stp_SetUserPassword(
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.arg('password_hash')
);

-- name: SoftDeleteUser :exec
CALL stp_SoftDeleteUser($1, $2);

-- name: BumpPermissionsVersion :exec
CALL stp_BumpPermissionsVersion($1, $2);

-- name: SetUserLoginPolicy :one
SELECT stp_SetUserLoginPolicy(
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.narg('policy_id')
);

-- name: CreatePlatformOwner :exec
-- Provisioning only: fails under the application role by design.
CALL stp_CreatePlatformOwner($1, $2);
