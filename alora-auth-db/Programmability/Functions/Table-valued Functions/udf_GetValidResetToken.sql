/****** Object: Table-valued Function [udf_GetValidResetToken] ******/
-- A redeemable password-reset token with its owner's state. The unused and
-- unexpired predicates come from vw_ValidResetToken; the owner's flags let the
-- caller refuse to revive a disabled account.
--
-- FOR UPDATE OF t is ESSENTIAL and is why this function reads the base tables
-- rather than simply selecting from the view: it locks the token row for the
-- caller's transaction, so two concurrent redemptions of the same (possibly
-- stolen) token serialise. The second waits, re-evaluates `used_at IS NULL`
-- under the lock, and finds nothing — which is what makes single-use real. A
-- lock-free read would let an attacker racing the legitimate user set the
-- password to a value of their choosing.
--
-- VOLATILE because a STABLE function may not take row locks.
--
-- The result type stays SETOF vw_ValidResetToken so the row shape is declared in
-- exactly one place.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetValidResetToken(p_tokenHash TEXT)
RETURNS SETOF vw_ValidResetToken
LANGUAGE sql
VOLATILE
AS $$
    SELECT t.id,
           t.user_id,
           t.client_id,
           t.token_hash,
           u.email,
           u.is_active,
           u.deleted_at
    FROM   tbl_password_reset_tokens t
    JOIN   tbl_users u ON u.id = t.user_id
    WHERE  t.token_hash  = p_tokenHash
      AND  t.used_at    IS NULL
      AND  t.expires_at  > now()
    FOR    UPDATE OF t;
$$;
