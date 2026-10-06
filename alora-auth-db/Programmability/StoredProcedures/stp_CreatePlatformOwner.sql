/****** Object: Stored Procedure [stp_CreatePlatformOwner] ******/
-- Makes a platform-company user an Owner. Runs with the CALLER's rights, and
-- the application role holds no write on tbl_platform_owners, so only
-- provisioning connected as the schema owner can call it successfully.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_CreatePlatformOwner(p_userId TEXT, p_clientId TEXT)
LANGUAGE sql
AS $$
    INSERT INTO tbl_platform_owners (user_id, client_id)
    VALUES (p_userId, p_clientId)
    ON CONFLICT (user_id) DO NOTHING;
$$;
