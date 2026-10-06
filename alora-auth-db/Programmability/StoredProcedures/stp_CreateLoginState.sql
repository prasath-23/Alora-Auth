/****** Object: Stored Procedure [stp_CreateLoginState] ******/
-- Stores the server side of a sign-in in progress under the hash of a value
-- only the browser's cookie carries.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_CreateLoginState(p_stateHash TEXT, p_kind "LoginStateKind", p_connectionId TEXT, p_nonce TEXT, p_codeVerifier TEXT, p_returnTo TEXT, p_candidateUserIds TEXT[], p_authMethod "IdpProvider", p_expiresAt TIMESTAMPTZ)
LANGUAGE sql
AS $$
    INSERT INTO tbl_login_states (state_hash, kind, connection_id, nonce, code_verifier,
                                  return_to, candidate_user_ids, auth_method, expires_at)
    VALUES (p_stateHash, p_kind, p_connectionId, p_nonce, p_codeVerifier,
            p_returnTo, p_candidateUserIds, p_authMethod, p_expiresAt);
$$;
