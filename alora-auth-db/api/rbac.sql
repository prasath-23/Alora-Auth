-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: groups and feature grants
--
-- Tenant ownership for the feature write is enforced inside
-- stp_SetGroupFeatures, which re-derives it through tbl_groups. The API cannot
-- bypass it by passing a foreign group id.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: ListGroups :many
SELECT * FROM udf_ListGroups($1);

-- name: GetGroupDetail :many
SELECT * FROM udf_GetGroupDetail($1, $2);

-- name: GetGroupTenantScoped :one
SELECT * FROM udf_GetGroupTenantScoped($1, $2);

-- name: HasGroupFeature :one
SELECT udf_HasGroupFeature($1, $2, $3);

-- name: CreateGroup :one
SELECT * FROM stp_CreateGroup(
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.narg('description')
);

-- name: UpdateGroup :one
SELECT * FROM stp_UpdateGroup(
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.arg('name'),
    sqlc.narg('description')
);

-- name: DeleteGroup :one
SELECT stp_DeleteGroup($1, $2);

-- name: SetGroupFeatures :one
SELECT stp_SetGroupFeatures(
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.arg('feature_keys')::text[]
);

-- name: AddGroupMember :exec
CALL stp_AddGroupMember(
    sqlc.arg('user_id'),
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.narg('assigned_by')
);

-- name: RemoveGroupMember :one
SELECT stp_RemoveGroupMember($1, $2, $3);
