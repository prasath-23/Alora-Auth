/****** Object: Stored Procedure [stp_ClaimAuthorizationCode] ******/
-- Redeems a code in ONE atomic statement. The used_at IS NULL and expiry
-- guards are part of the UPDATE, so two concurrent redemptions cannot both
-- succeed -- the second updates zero rows. A SELECT-then-UPDATE here would
-- be a double-spend, which is the classic authorization-code attack.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_ClaimAuthorizationCode(p_codeHash TEXT)
RETURNS SETOF tbl_authorization_codes
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_authorization_codes
    SET    used_at = now()
    WHERE  code_hash  = p_codeHash
      AND  used_at   IS NULL
      AND  expires_at > now()
    RETURNING *;
$$;
