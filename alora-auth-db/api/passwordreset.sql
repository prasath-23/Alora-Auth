-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: password reset
--
-- vw_ValidResetToken carries the unused and unexpired predicates and surfaces the
-- owner's state, so the caller cannot honour a spent link or revive a disabled
-- account.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: GetValidResetToken :one
SELECT * FROM udf_GetValidResetToken($1);

-- name: CreateResetToken :one
SELECT * FROM stp_CreateResetToken($1, $2, $3, $4, $5);

-- name: DeleteUnusedResetTokens :exec
CALL stp_DeleteUnusedResetTokens($1);

-- name: MarkResetTokenUsed :exec
CALL stp_MarkResetTokenUsed($1);
