/****** Object: Stored Procedure [stp_SetUserPassword] ******/
-- Sets a new password hash. Tenant-scoped so a leaked user id from another
-- organisation cannot be used to overwrite a password. An OAUTH_ONLY account
-- that receives a password becomes HYBRID, otherwise the password could
-- never be used; whether it MAY be used is still the login policy's
-- decision.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_SetUserPassword(p_userId TEXT, p_clientId TEXT, p_passwordHash TEXT)
LANGUAGE sql
AS $$
    UPDATE tbl_users
    SET    password_hash = p_passwordHash,
           account_type  = CASE WHEN account_type = 'OAUTH_ONLY' THEN 'HYBRID'::"AccountType"
                                ELSE account_type END,
           updated_at    = now()
    WHERE  id        = p_userId
      AND  client_id = p_clientId;
$$;
