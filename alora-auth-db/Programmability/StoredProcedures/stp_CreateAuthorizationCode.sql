/****** Object: Stored Procedure [stp_CreateAuthorizationCode] ******/
-- Issues a single-use authorization code. redirect_url and code_challenge
-- are stored WITH the code so both are re-verified at redemption and cannot
-- be swapped between the two legs of the flow.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateAuthorizationCode(p_code TEXT, p_productId TEXT, p_userId TEXT, p_redirectUrl TEXT, p_codeChallenge TEXT, p_codeChallengeMethod TEXT, p_state TEXT, p_expiresAt TIMESTAMPTZ)
RETURNS SETOF tbl_authorization_codes
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_authorization_codes (code, product_id, user_id, redirect_url,
                                         code_challenge, code_challenge_method,
                                         state, expires_at)
    VALUES (p_code, p_productId, p_userId, p_redirectUrl,
            p_codeChallenge, p_codeChallengeMethod, p_state, p_expiresAt)
    RETURNING *;
$$;
