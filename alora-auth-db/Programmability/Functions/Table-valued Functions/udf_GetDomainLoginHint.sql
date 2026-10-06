/****** Object: Table-valued Function [udf_GetDomainLoginHint] ******/
-- The sign-in methods to OFFER for an email domain. A hint for the login
-- page only: every login path enforces the user's own policy regardless.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetDomainLoginHint(p_domain TEXT)
RETURNS SETOF vw_DomainLoginHint
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_DomainLoginHint v WHERE v.domain = lower(p_domain) LIMIT 1;
$$;
