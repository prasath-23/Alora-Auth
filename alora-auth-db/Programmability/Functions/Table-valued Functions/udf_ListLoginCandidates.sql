/****** Object: Table-valued Function [udf_ListLoginCandidates] ******/
-- Every live password account that holds this address, across tenants: one
-- person may belong to several organisations. Capped and deterministically
-- ordered, so the work a login does is bounded and repeatable.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListLoginCandidates(p_email TEXT)
RETURNS SETOF vw_UserCredential
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserCredential v
    WHERE  lower(v.email) = lower(p_email)
    ORDER  BY v.created_at, v.id
    LIMIT  10;
$$;
