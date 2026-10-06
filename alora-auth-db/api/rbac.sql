-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: groups, and the App Central scopes groups and people hold
--
-- Tenant ownership for the scope writes is enforced inside stp_SetGroupScopes
-- and stp_SetUserScopes, which look the group or user up by (id, tenant). The
-- API cannot bypass it by passing a foreign id.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: ListGroups :many
SELECT * FROM udf_ListGroups($1);

-- name: GetGroupDetail :many
SELECT * FROM udf_GetGroupDetail($1, $2);

-- name: GetGroupTenantScoped :one
SELECT * FROM udf_GetGroupTenantScoped($1, $2);

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

-- name: SetGroupScopes :one
SELECT stp_SetGroupScopes(
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.arg('scopes')::text[]
);

-- name: SetUserScopes :one
SELECT stp_SetUserScopes(
    sqlc.arg('user_id'),
    sqlc.arg('client_id'),
    sqlc.arg('scopes')::text[],
    sqlc.narg('granted_by_user_id'),
    sqlc.narg('granted_by_owner_id')
);

-- name: ListUserScopes :many
SELECT * FROM udf_ListUserScopes(
    sqlc.arg('client_id'),
    sqlc.arg('user_id')
);

-- name: ListScopes :many
SELECT * FROM udf_ListScopes();

-- name: AddGroupMember :exec
CALL stp_AddGroupMember(
    sqlc.arg('user_id'),
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.narg('assigned_by')
);

-- name: RemoveGroupMember :one
SELECT stp_RemoveGroupMember($1, $2, $3);

-- name: GetSystemGroupId :one
-- Filtered so a missing system group yields zero rows (see entitlements.sql).
SELECT id FROM (SELECT udf_GetSystemGroupId($1, $2) AS id) t WHERE id IS NOT NULL;

-- name: SetGroupProductGrants :one
SELECT stp_SetGroupProductGrants(
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.arg('product_ids')::text[],
    sqlc.arg('role_names')::text[],
    sqlc.narg('granted_by')
);

-- name: ListGroupManagers :many
SELECT * FROM udf_ListGroupManagers(
    sqlc.arg('group_id'),
    sqlc.arg('client_id')
);

-- name: ListManagedGroups :many
SELECT * FROM udf_ListManagedGroups(
    sqlc.arg('user_id'),
    sqlc.arg('client_id')
);

-- name: IsGroupManager :one
SELECT udf_IsGroupManager(
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.arg('user_id')
);

-- name: ListScopeReach :many
-- Rule 2's measure of a person: the distinct scopes they hold or can hand out
-- as a group's manager. Never used to grant anything.
SELECT DISTINCT v.scope FROM udf_ListScopeReach(
    sqlc.arg('client_id'),
    sqlc.arg('user_id')
) v
ORDER BY v.scope;

-- name: AddGroupManager :one
SELECT stp_AddGroupManager(
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.arg('user_id'),
    sqlc.narg('by_user_id'),
    sqlc.narg('by_owner_id')
);

-- name: RemoveGroupManager :one
SELECT stp_RemoveGroupManager(
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.arg('user_id')
);

-- name: ManagerAddGroupMember :one
SELECT stp_ManagerAddGroupMember(
    sqlc.arg('manager_id'),
    sqlc.arg('user_id'),
    sqlc.arg('group_id'),
    sqlc.arg('client_id')
);

-- name: ManagerRemoveGroupMember :one
SELECT stp_ManagerRemoveGroupMember(
    sqlc.arg('manager_id'),
    sqlc.arg('user_id'),
    sqlc.arg('group_id'),
    sqlc.arg('client_id')
);

-- name: SetGroupLoginPolicy :one
SELECT stp_SetGroupLoginPolicy(
    sqlc.arg('group_id'),
    sqlc.arg('client_id'),
    sqlc.narg('policy_id')
);
