/****** Object: Table-valued Function [udf_ListGoogleLinks] ******/
-- Every live account a Google subject is linked to, one per tenant at most.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListGoogleLinks(p_subject TEXT)
RETURNS SETOF vw_LinkedIdentityOwner
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_LinkedIdentityOwner v
    WHERE  v.provider    = 'GOOGLE'
      AND  v.provider_id = p_subject;
$$;
