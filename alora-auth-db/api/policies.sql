-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: login policies and login discovery
--
-- Which policy applies to a user is resolved in vw_UserLoginPolicy (users.sql);
-- these are the Owner's management entry points and the domain-only discovery
-- hint the login page uses.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: ListLoginPolicies :many
SELECT * FROM udf_ListLoginPolicies($1);

-- name: GetLoginPolicy :one
SELECT * FROM udf_GetLoginPolicy($1, $2);

-- name: CreateLoginPolicy :one
SELECT * FROM stp_CreateLoginPolicy(
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.arg('allow_password'),
    sqlc.arg('allow_google'),
    sqlc.narg('sso_connection_id'),
    sqlc.arg('priority')
);

-- name: UpdateLoginPolicy :one
SELECT * FROM stp_UpdateLoginPolicy(
    sqlc.arg('policy_id'),
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.arg('allow_password'),
    sqlc.arg('allow_google'),
    sqlc.narg('sso_connection_id'),
    sqlc.arg('priority')
);

-- name: DeleteLoginPolicy :one
SELECT stp_DeleteLoginPolicy($1, $2);

-- name: SetDefaultLoginPolicy :one
SELECT stp_SetDefaultLoginPolicy($1, $2);

-- name: GetDomainLoginHint :one
SELECT * FROM udf_GetDomainLoginHint($1);
