/****** Object: Stored Procedure [stp_SetCodeIssuedFamily] ******/
-- Records the product login a code produced, so a later replay of the code
-- can revoke it (RFC 6749 4.1.2).
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_SetCodeIssuedFamily(p_codeId TEXT, p_familyId TEXT)
LANGUAGE sql
AS $$
    UPDATE tbl_authorization_codes
    SET    issued_family_id = p_familyId
    WHERE  id = p_codeId;
$$;
