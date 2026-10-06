/****** Object: Stored Procedure [stp_CreateAuthorizationCode] ******/
-- Issues a single-use authorization code, stored as its hash. The redirect
-- URI, PKCE challenge, nonce and the central login it was issued under are
-- stored WITH the code, so all are re-verified at redemption and cannot be
-- swapped between the two legs of the flow.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateAuthorizationCode(p_codeHash TEXT, p_productId TEXT, p_userId TEXT, p_clientId TEXT, p_parentFamilyId TEXT, p_redirectUri TEXT, p_codeChallenge TEXT, p_codeChallengeMethod TEXT, p_nonce TEXT, p_scope TEXT, p_expiresAt TIMESTAMPTZ)
RETURNS SETOF tbl_authorization_codes
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_authorization_codes (code_hash, product_id, user_id, client_id, parent_family_id,
                                         redirect_uri, code_challenge, code_challenge_method,
                                         nonce, scope, expires_at)
    VALUES (p_codeHash, p_productId, p_userId, p_clientId, p_parentFamilyId,
            p_redirectUri, p_codeChallenge, p_codeChallengeMethod,
            p_nonce, p_scope, p_expiresAt)
    RETURNING *;
$$;
