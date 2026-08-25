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

-- name: ListInvitationProducts :many
SELECT * FROM udf_ListInvitationProducts($1);

-- name: CreateInvitation :one
SELECT * FROM stp_CreateInvitation($1, $2, $3, $4, $5);

-- name: CreateInvitationProduct :exec
CALL stp_CreateInvitationProduct($1, $2, $3);

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
