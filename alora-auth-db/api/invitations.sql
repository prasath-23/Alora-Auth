-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: invitations
--
-- The redeemable-invitation predicates (pending, unexpired, active tenant) live
-- in vw_PendingInvitation, so every lookup below inherits them and no caller can
-- accidentally honour a dead invitation.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: GetPendingInviteByEmail :one
SELECT * FROM udf_GetPendingInviteByEmail($1, $2);

-- name: GetPendingInvitation :one
SELECT * FROM udf_GetPendingInvitation($1);

-- name: ListInvitations :many
SELECT * FROM udf_ListInvitations($1);

-- name: ListInvitationGroups :many
SELECT * FROM udf_ListInvitationGroups($1);

-- name: GetInvitationLoginPolicy :one
SELECT * FROM udf_GetInvitationLoginPolicy($1, $2);

-- name: CreateInvitation :one
SELECT * FROM stp_CreateInvitation(
    sqlc.arg('email'),
    sqlc.arg('client_id'),
    sqlc.narg('invited_by_user_id'),
    sqlc.narg('invited_by_owner_id'),
    sqlc.arg('token_hash'),
    sqlc.arg('expires_at')
);

-- name: CreateInvitationGroup :exec
CALL stp_CreateInvitationGroup($1, $2, $3);

-- name: RevokeInvitation :one
SELECT stp_RevokeInvitation(
    sqlc.arg('invitation_id'),
    sqlc.arg('client_id'),
    sqlc.narg('revoked_by_user_id')
);

-- name: ClaimInvitation :one
SELECT * FROM stp_ClaimInvitation(
    sqlc.arg('token_hash'),
    sqlc.narg('accepted_by_user_id')
);

-- name: SetInvitationAcceptedBy :exec
CALL stp_SetInvitationAcceptedBy($1, $2);

-- name: ExpireInvitations :exec
CALL stp_ExpireInvitations($1);
