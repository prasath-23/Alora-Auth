/****** Object: Table-valued Function [udf_GetLinkedIdentityByConnection] ******/
-- The live account an SSO subject is linked to at one connection. Matching
-- on the provider's stable subject, never the email, is what stops an
-- address change at the provider from moving someone into another account.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetLinkedIdentityByConnection(p_connectionId TEXT, p_subject TEXT)
RETURNS SETOF vw_LinkedIdentityOwner
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_LinkedIdentityOwner v
    WHERE  v.provider      = 'OIDC'
      AND  v.connection_id = p_connectionId
      AND  v.provider_id   = p_subject;
$$;
