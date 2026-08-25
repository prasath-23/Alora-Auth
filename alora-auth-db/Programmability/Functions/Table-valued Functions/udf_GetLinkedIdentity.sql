/****** Object: Table-valued Function [udf_GetLinkedIdentity] ******/
-- Resolves an external identity to its local user. Matching on the
-- provider's stable subject id rather than the email means a user who
-- changes their provider address keeps their account, and whoever later
-- acquires that address does not inherit it.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetLinkedIdentity(p_provider "IdpProvider", p_providerId TEXT)
RETURNS SETOF vw_LinkedIdentityOwner
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_LinkedIdentityOwner v
    WHERE  v.provider    = p_provider
      AND  v.provider_id = p_providerId;
$$;
